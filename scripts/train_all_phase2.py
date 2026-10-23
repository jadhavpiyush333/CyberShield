from pathlib import Path
import json
import re
import sys
import traceback

import joblib
import numpy as np
import pandas as pd
import requests

from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.impute import SimpleImputer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "phase2"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"

for folder in [RAW, MODELS, REPORTS]:
    folder.mkdir(parents=True, exist_ok=True)

SEED = 42


def save_dataset(dataset, path):
    """Persist downloaded dataset files inside the CyberShield project."""
    frame = dataset.to_pandas()
    path.parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(path, index=False)
    print(f"Saved dataset: {path} ({len(frame):,} rows)")
    return frame


def train_text_model(name, frame, text_col, label_col, label_map):
    """Train a text classifier using a labelled dataset."""
    df = frame[[text_col, label_col]].copy()
    df.columns = ["text", "label"]
    df["text"] = df["text"].fillna("").astype(str).str.strip()
    df["label"] = df["label"].astype(str).str.strip().str.lower()
    df["target"] = df["label"].map(label_map)
    df = df.dropna(subset=["target"])
    df = df[df["text"].str.len() >= 3]
    df = df.drop_duplicates(subset=["text"])
    df["target"] = df["target"].astype(int)

    if df["target"].nunique() != 2:
        raise ValueError(
            f"{name}: could not find both classes. "
            f"Observed labels: {df['label'].value_counts().to_dict()}"
        )
    if df["target"].value_counts().min() < 2:
        raise ValueError(f"{name}: insufficient examples for one class.")

    X_train, X_test, y_train, y_test = train_test_split(
        df["text"], df["target"], test_size=0.20,
        random_state=SEED, stratify=df["target"]
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True, strip_accents="unicode",
            ngram_range=(1, 2), min_df=2,
            max_features=150000, sublinear_tf=True
        )),
        ("classifier", LogisticRegression(
            max_iter=1000, class_weight="balanced",
            random_state=SEED
        ))
    ])

    print(f"\nTraining {name}: {len(X_train):,} training rows")
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    write_results(name, model, y_test, pred, len(df), len(X_train), len(X_test))


def write_results(name, model, y_test, pred, total, n_train, n_test):
    tn, fp, fn, tp = confusion_matrix(
        y_test, pred, labels=[0, 1]
    ).ravel()

    results = {
        "model": name,
        "dataset_rows": int(total),
        "train_rows": int(n_train),
        "test_rows": int(n_test),
        "accuracy": float(accuracy_score(y_test, pred)),
        "precision": float(precision_score(y_test, pred, zero_division=0)),
        "recall": float(recall_score(y_test, pred, zero_division=0)),
        "f1": float(f1_score(y_test, pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if tn + fp else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "confusion_matrix_tn_fp_fn_tp": [int(tn), int(fp), int(fn), int(tp)],
        "classification_report": classification_report(
            y_test, pred, zero_division=0, output_dict=True
        )
    }

    model_path = MODELS / f"{name}.joblib"
    report_path = REPORTS / f"{name}_metrics.json"
    joblib.dump(model, model_path)
    report_path.write_text(json.dumps(results, indent=2))

    print(f"Model saved: {model_path}")
    print(f"Metrics saved: {report_path}")
    print(json.dumps({
        k: results[k] for k in (
            "dataset_rows", "accuracy", "precision", "recall",
            "f1", "false_positive_rate", "false_negative_rate"
        )
    }, indent=2))


def train_email():
    print("\n========== EMAIL PHISHING ==========")
    ds = load_dataset("ansulev/phishing-email-dataset")
    frame = pd.concat(
        [ds[split].to_pandas() for split in ds.keys()],
        ignore_index=True
    )
    frame.to_csv(RAW / "email_phishing.csv", index=False)
    print("Email columns:", list(frame.columns))

    lower = {str(c).strip().lower(): c for c in frame.columns}
    text_col = next(
        (lower[c] for c in ("email text", "email_text", "text", "body", "message")
         if c in lower), None
    )
    label_col = next(
        (lower[c] for c in ("email type", "email_type", "label", "class", "category")
         if c in lower), None
    )
    if not text_col or not label_col:
        raise ValueError(f"Email dataset schema unexpected: {list(frame.columns)}")

    label_map = {
        "safe email": 0, "safe": 0, "legitimate": 0, "ham": 0, "0": 0,
        "phishing email": 1, "phishing": 1, "malicious": 1, "spam": 1, "1": 1
    }
    train_text_model("email_phishing_text", frame, text_col, label_col, label_map)


def train_social():
    print("\n========== SOCIAL / MESSAGE SCAMS ==========")
    url = (
        "https://raw.githubusercontent.com/"
        "shaghayegh-hp/Smishing_Dataset/main/"
        "Combined-Labeled-Dataset.csv"
    )
    destination = RAW / "social_smishing.csv"

    if not destination.exists():
        response = requests.get(url, timeout=120)
        response.raise_for_status()
        destination.write_bytes(response.content)

    frame = pd.read_csv(destination)
    print("Social columns:", list(frame.columns))

    if "message" not in frame.columns or "smishing label" not in frame.columns:
        raise ValueError(f"Social dataset schema unexpected: {list(frame.columns)}")

    # This dataset uses 0 = non-smishing and 1 = smishing.
    frame["smishing label"] = pd.to_numeric(
        frame["smishing label"], errors="coerce"
    )
    frame = frame[frame["smishing label"].isin([0, 1])].copy()

    train_text_model(
        "social_scam_text", frame, "message", "smishing label",
        {"0": 0, "0.0": 0, "1": 1, "1.0": 1}
    )


def find_label_column(frame):
    candidates = [
        "label", "labels", "class", "class_label", "malware",
        "is_malware", "target", "category", "classification",
        "verdict", "malicious", "is_malicious"
    ]
    by_lower = {str(c).strip().lower(): c for c in frame.columns}
    for candidate in candidates:
        if candidate in by_lower:
            col = by_lower[candidate]
            if frame[col].nunique(dropna=True) == 2:
                return col

    # Use a binary column only if its name suggests a label.
    for col in frame.columns:
        key = str(col).lower()
        if any(word in key for word in ("label", "class", "malware", "malicious")):
            if frame[col].nunique(dropna=True) == 2:
                return col
    return None


def convert_apk_labels(series):
    """Map common benign/malware labels to 0/1."""
    output = []
    for value in series:
        if pd.isna(value):
            output.append(np.nan)
            continue
        if isinstance(value, (int, float, np.integer, np.floating)):
            if value in (0, 1):
                output.append(int(value))
            else:
                output.append(np.nan)
            continue

        label = str(value).strip().lower()
        if label in {"benign", "goodware", "good", "safe", "clean", "legitimate"}:
            output.append(0)
        elif label in {"malware", "malicious", "badware", "bad", "infected"}:
            output.append(1)
        elif label in {"0", "0.0"}:
            output.append(0)
        elif label in {"1", "1.0"}:
            output.append(1)
        else:
            output.append(np.nan)
    return pd.Series(output, index=series.index)


def train_apk():
    print("\n========== APK / ANDROID MALWARE ==========")
    # Public Android feature dataset. Hugging Face handles dataset files.
    ds = load_dataset("hendriow/mh100k")
    frame = pd.concat(
        [ds[split].to_pandas() for split in ds.keys()],
        ignore_index=True
    )
    frame.to_csv(RAW / "android_malware_features.csv", index=False)
    print("APK feature columns:", list(frame.columns))

    label_col = find_label_column(frame)
    if label_col is None:
        raise ValueError(
            "Could not identify a binary malware label column. "
            "Inspect data/raw/phase2/android_malware_features.csv"
        )

    y = convert_apk_labels(frame[label_col])
    valid = y.isin([0, 1])
    frame = frame.loc[valid].copy()
    y = y.loc[valid].astype(int)

    if y.nunique() != 2 or y.value_counts().min() < 2:
        raise ValueError(
            f"APK labels are not a valid binary target. "
            f"Column={label_col}, values={frame[label_col].value_counts().to_dict()}"
        )

    # Exclude identifiers and label fields to avoid training on hashes/names.
    exclude_words = (
        "sha", "hash", "filename", "file_name", "package_name",
        "package", "label", "class", "malware", "malicious",
        "target", "category", "verdict"
    )
    features = [
        c for c in frame.columns
        if c != label_col
        and not any(word in str(c).lower() for word in exclude_words)
    ]
    X = frame[features].copy()

    # Remove columns that contain no usable data.
    X = X.dropna(axis=1, how="all")
    if X.shape[1] == 0:
        raise ValueError("APK dataset has no usable feature columns.")

    numeric = X.select_dtypes(include=["number", "bool"]).columns.tolist()
    categorical = [c for c in X.columns if c not in numeric]
    transformers = []

    if numeric:
        transformers.append((
            "numeric",
            Pipeline([
                ("imputer", SimpleImputer(strategy="median")),
                ("scaler", StandardScaler())
            ]),
            numeric
        ))
    if categorical:
        transformers.append((
            "categorical",
            Pipeline([
                ("imputer", SimpleImputer(strategy="most_frequent")),
                ("encoder", OneHotEncoder(handle_unknown="ignore"))
            ]),
            categorical
        ))

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=SEED, stratify=y
    )

    model = Pipeline([
        ("features", ColumnTransformer(transformers, remainder="drop")),
        ("classifier", RandomForestClassifier(
            n_estimators=250, class_weight="balanced",
            random_state=SEED, n_jobs=-1,
            min_samples_leaf=2
        ))
    ])

    print(
        f"Training APK model on {len(X_train):,} rows, "
        f"using {X.shape[1]} feature columns; label column={label_col}"
    )
    model.fit(X_train, y_train)
    pred = model.predict(X_test)
    write_results(
        "apk_malware_classifier", model, y_test, pred,
        len(X), len(X_train), len(X_test)
    )


def show_qr_status():
    print("\n========== QR CODE SECURITY ==========")
    existing = MODELS / "phishing_url.joblib"
    if existing.exists():
        print("QR module uses the existing phishing URL model:")
        print(existing)
        print("QR is a decoding step; the decoded destination must be scanned.")
    else:
        print("WARNING: models/phishing_url.joblib not found.")
        print("Train the existing phishing URL model before using QR scans.")


def main():
    tasks = {
        "email": train_email,
        "social": train_social,
        "apk": train_apk,
    }
    requested = sys.argv[1:] or ["all"]
    selected = list(tasks) if "all" in requested else requested

    failures = []
    for name in selected:
        if name not in tasks:
            print(f"Unknown task: {name}. Choose email, social, apk, or all.")
            failures.append((name, "unknown task"))
            continue
        try:
            tasks[name]()
        except Exception as exc:
            failures.append((name, str(exc)))
            print(f"\nFAILED [{name}]: {exc}", file=sys.stderr)
            traceback.print_exc()

    if "all" in requested or "email" in selected or "social" in selected or "apk" in selected:
        show_qr_status()

    print("\n========== TRAINING SUMMARY ==========")
    for name in tasks:
        model_file = MODELS / {
            "email": "email_phishing_text.joblib",
            "social": "social_scam_text.joblib",
            "apk": "apk_malware_classifier.joblib"
        }[name]
        print(f"{name}: {'TRAINED' if model_file.exists() else 'NOT TRAINED'}")

    if failures:
        print("\nSome tasks failed; inspect the error above.")
        print("No successful training is claimed for failed tasks.")
        raise SystemExit(1)

    print("\nCompleted. Check reports/*_metrics.json for real evaluation results.")
    print("Note: models must still be integrated into phase2.py to affect API scans.")


if __name__ == "__main__":
    main()
