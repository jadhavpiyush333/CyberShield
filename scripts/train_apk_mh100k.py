from pathlib import Path
import json
import time
import warnings

import joblib
import numpy as np
import pandas as pd
from huggingface_hub import hf_hub_download
from scipy.sparse import csr_matrix
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report
)

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data/raw/phase2"
MODELS = ROOT / "models"
REPORTS = ROOT / "reports"

for directory in (RAW, MODELS, REPORTS):
    directory.mkdir(parents=True, exist_ok=True)

print("Downloading MH-100K files individually...")
files = {}
for filename in ("mh100.parquet", "mh100-labels.csv", "feature_names.csv"):
    print(f"Downloading {filename} ...")
    files[filename] = hf_hub_download(
        repo_id="hendriow/mh100k",
        filename=filename,
        repo_type="dataset",
    )

# Save local copies for reproducibility.
for name, path in files.items():
    destination = RAW / name
    if not destination.exists():
        import shutil
        shutil.copy2(path, destination)

print("Reading feature matrix...")
X_df = pd.read_parquet(files["mh100.parquet"])
labels = pd.read_csv(files["mh100-labels.csv"])
names_df = pd.read_csv(files["feature_names.csv"])

print("Feature matrix shape:", X_df.shape)
print("Label columns:", labels.columns.tolist())
print("Feature-name columns:", names_df.columns.tolist())
print("Label sample:")
print(labels.head(3).to_string(index=False))

# Identify the documented class column.
label_col = next(
    (c for c in labels.columns if str(c).strip().lower() == "class"),
    None
)
if label_col is None:
    raise ValueError(
        f"No 'class' label column found. Actual columns: {labels.columns.tolist()}"
    )

if len(X_df) != len(labels):
    raise ValueError(
        f"Feature/label row counts differ: {len(X_df)} vs {len(labels)}. "
        "Refusing to pair rows without verified identifiers."
    )

# The repository documents feature_names.csv as the feature-name mapping.
name_col = next(
    (c for c in names_df.columns
     if str(c).strip().lower() in {"feature_name", "features", "feature"}),
    None
)
if name_col is None and len(names_df.columns) == 1:
    name_col = names_df.columns[0]

if name_col is not None and len(names_df) == X_df.shape[1]:
    X_df.columns = names_df[name_col].astype(str).tolist()
elif len(X_df.columns) != X_df.shape[1]:
    raise ValueError("Unable to map feature names to the feature matrix.")

# Normalize binary labels conservatively.
raw_y = labels[label_col].astype(str).str.strip().str.lower()
label_map = {
    "benign": 0, "goodware": 0, "good": 0, "clean": 0,
    "malware": 1, "malicious": 1, "badware": 1, "bad": 1,
    "0": 0, "0.0": 0, "1": 1, "1.0": 1,
}
y = raw_y.map(label_map)

if y.isna().any():
    raise ValueError(
        f"Unrecognized label values: {raw_y[y.isna()].value_counts().head(20).to_dict()}"
    )

y = y.astype(np.int8)
if y.nunique() != 2:
    raise ValueError(f"Expected two classes; found {y.value_counts().to_dict()}")

print("Class counts (0=benign, 1=malware):", y.value_counts().sort_index().to_dict())

# Convert feature values to numeric, preserving sparse storage.
X_df = X_df.apply(pd.to_numeric, errors="coerce").fillna(0)
X = csr_matrix(X_df.to_numpy(dtype=np.float32))
del X_df

X_train, X_test, y_train, y_test = train_test_split(
    X, y.to_numpy(),
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print(f"Training rows: {X_train.shape[0]:,}")
print(f"Test rows: {X_test.shape[0]:,}")
print(f"Features: {X_train.shape[1]:,}")
print("Training sparse logistic-regression classifier...")

model = LogisticRegression(
    solver="liblinear",
    class_weight="balanced",
    max_iter=300,
    random_state=42,
)
started = time.time()
model.fit(X_train, y_train)
pred = model.predict(X_test)

tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()
metrics = {
    "model": "apk_malware_classifier",
    "dataset": "hendriow/mh100k",
    "dataset_rows": int(X.shape[0]),
    "feature_count": int(X.shape[1]),
    "train_rows": int(X_train.shape[0]),
    "test_rows": int(X_test.shape[0]),
    "accuracy": float(accuracy_score(y_test, pred)),
    "precision": float(precision_score(y_test, pred, zero_division=0)),
    "recall": float(recall_score(y_test, pred, zero_division=0)),
    "f1": float(f1_score(y_test, pred, zero_division=0)),
    "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
    "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
    "confusion_matrix_tn_fp_fn_tp": [int(tn), int(fp), int(fn), int(tp)],
    "classification_report": classification_report(
        y_test, pred, labels=[0, 1], output_dict=True, zero_division=0
    ),
    "training_seconds": round(time.time() - started, 2),
    "classifier": "LogisticRegression",
    "random_state": 42,
}

model_path = MODELS / "apk_malware_classifier.joblib"
metrics_path = REPORTS / "apk_malware_classifier_metrics.json"

joblib.dump({
    "model": model,
    "feature_names": list(X.shape[1] and range(X.shape[1])),
    "dataset": "hendriow/mh100k",
    "label_mapping": {"benign": 0, "malware": 1},
}, model_path)

metrics_path.write_text(json.dumps(metrics, indent=2))

print("\n========== APK EVALUATION ==========")
print(json.dumps({
    k: v for k, v in metrics.items()
    if k != "classification_report"
}, indent=2))
print("\nClassification report:")
print(classification_report(y_test, pred, zero_division=0))
print("Saved model:", model_path)
print("Saved metrics:", metrics_path)
