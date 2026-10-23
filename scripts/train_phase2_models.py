from pathlib import Path
import json
import re
import sys
import requests
import pandas as pd
import joblib

from datasets import load_dataset
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, classification_report
)

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw" / "phase2"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"

for folder in (RAW, MODELS, REPORTS):
    folder.mkdir(parents=True, exist_ok=True)

RANDOM_STATE = 42


def normalize_text(value):
    if pd.isna(value):
        return ""
    return re.sub(r"\s+", " ", str(value)).strip()


def train_text_model(name, frame, text_col, label_col, positive_values):
    """Train and evaluate a separate text classifier."""
    data = frame[[text_col, label_col]].copy()
    data[text_col] = data[text_col].map(normalize_text)
    data = data.dropna(subset=[label_col])
    data = data[data[text_col].str.len() >= 3]
    data = data.drop_duplicates(subset=[text_col])

    def convert_label(value):
        value = str(value).strip().lower()
        return int(value in positive_values)

    data["target"] = data[label_col].map(convert_label)
    data = data[data[text_col] != ""]

    if data["target"].nunique() != 2:
        raise ValueError(
            f"{name}: expected both legitimate and malicious labels; "
            f"found {data['target'].value_counts().to_dict()}"
        )

    if data["target"].value_counts().min() < 2:
        raise ValueError(f"{name}: too few examples in one class.")

    X_train, X_test, y_train, y_test = train_test_split(
        data[text_col],
        data["target"],
        test_size=0.20,
        random_state=RANDOM_STATE,
        stratify=data["target"]
    )

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            strip_accents="unicode",
            lowercase=True,
            ngram_range=(1, 2),
            min_df=2,
            max_features=200000,
            sublinear_tf=True
        )),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            random_state=RANDOM_STATE
        ))
    ])

    print(f"\n[{name}] Training on {len(X_train):,} rows...")
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    metrics = {
        "module": name,
        "dataset_rows_after_cleaning": int(len(data)),
        "train_rows": int(len(X_train)),
        "test_rows": int(len(X_test)),
        "class_counts_0_legitimate_1_malicious": {
            str(k): int(v) for k, v in data["target"].value_counts().items()
        },
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision": float(precision_score(y_test, predictions, zero_division=0)),
        "recall": float(recall_score(y_test, predictions, zero_division=0)),
        "f1": float(f1_score(y_test, predictions, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "confusion_matrix_tn_fp_fn_tp": [int(tn), int(fp), int(fn), int(tp)],
        "classification_report": classification_report(
            y_test, predictions, zero_division=0, output_dict=True
        )
    }

    model_path = MODELS / f"{name}.joblib"
    report_path = REPORTS / f"{name}_training_metrics.json"

    joblib.dump(model, model_path)
    report_path.write_text(json.dumps(metrics, indent=2))

    print(f"[{name}] Model saved: {model_path}")
    print(f"[{name}] Metrics saved: {report_path}")
    print(json.dumps({
        k: metrics[k] for k in (
            "dataset_rows_after_cleaning", "accuracy", "precision",
            "recall", "f1", "false_positive_rate", "false_negative_rate"
        )
    }, indent=2))


def download_social_dataset():
    """Download the public labelled smishing CSV from GitHub."""
    url = (
        "https://raw.githubusercontent.com/"
        "shaghayegh-hp/Smishing_Dataset/main/"
        "Combined-Labeled-Dataset.csv"
    )
    destination = RAW / "social_smishing.csv"

    if not destination.exists():
        print(f"Downloading social dataset from:\n{url}")
        response = requests.get(url, timeout=90)
        response.raise_for_status()
        destination.write_bytes(response.content)

    frame = pd.read_csv(destination)
    print("[social] Dataset columns:", list(frame.columns))

    # The repository documents these exact column names.
    text_col = "message"
    label_col = "smishing label"

    if text_col not in frame.columns or label_col not in frame.columns:
        raise ValueError(
            "Social dataset columns did not match expected schema. "
            f"Found: {list(frame.columns)}"
        )

    frame[label_col] = pd.to_numeric(frame[label_col], errors="coerce")
    frame = frame[frame[label_col].isin([0, 1])].copy()
    frame[label_col] = frame[label_col].astype(int)

    train_text_model(
        "social_scam_text",
        frame,
        text_col,
        label_col,
        positive_values={"1", "1.0"}
    )


def download_email_dataset():
    """Use Hugging Face Datasets to download the public email corpus."""
    dataset_name = "ansulev/phishing-email-dataset"
    print(f"Downloading email dataset: {dataset_name}")
    dataset = load_dataset(dataset_name)

    # Merge available splits if the repository provides more than one.
    frames = [dataset[split].to_pandas() for split in dataset.keys()]
    frame = pd.concat(frames, ignore_index=True)
    print("[email] Dataset columns:", list(frame.columns))

    lower_to_original = {
        str(col).strip().lower(): col for col in frame.columns
    }

    text_col = next(
        (lower_to_original[c] for c in
         ("email text", "email_text", "text", "body", "message")
         if c in lower_to_original),
        None
    )
    label_col = next(
        (lower_to_original[c] for c in
         ("email type", "email_type", "label", "class", "category")
         if c in lower_to_original),
        None
    )

    if text_col is None or label_col is None:
        raise ValueError(
            "Could not identify email text/label columns. "
            f"Dataset columns: {list(frame.columns)}"
        )

    # Dataset labels documented as "Safe Email" and "Phishing Email".
    labels = frame[label_col].astype(str).str.strip().str.lower()
    frame = frame[labels.isin({"safe email", "phishing email"})].copy()
    frame[label_col] = (
        frame[label_col].astype(str).str.strip().str.lower()
        .map({"safe email": "0", "phishing email": "1"})
    )

    train_text_model(
        "email_phishing_text",
        frame,
        text_col,
        label_col,
        positive_values={"1", "1.0", "phishing email", "phishing", "malicious"}
    )


def main():
    tasks = {
        "email": download_email_dataset,
        "social": download_social_dataset,
        "all": None,
    }

    choice = sys.argv[1].lower() if len(sys.argv) > 1 else "all"
    if choice not in tasks:
        raise SystemExit("Usage: python scripts/train_phase2_models.py [email|social|all]")

    selected = (
        [download_email_dataset, download_social_dataset]
        if choice == "all" else [tasks[choice]]
    )

    failures = []
    for task in selected:
        try:
            task()
        except Exception as exc:
            failures.append((task.__name__, str(exc)))
            print(f"\nERROR in {task.__name__}: {exc}", file=sys.stderr)

    print("\nTraining run finished.")
    if failures:
        print("Some tasks failed; no success is claimed for them:")
        for name, error in failures:
            print(f" - {name}: {error}")
        raise SystemExit(1)

    print("Review the metrics in reports/ before using these models in the app.")


if __name__ == "__main__":
    main()
