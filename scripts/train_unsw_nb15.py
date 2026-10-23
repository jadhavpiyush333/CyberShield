import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, classification_report, confusion_matrix,
    precision_score, recall_score, f1_score
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier

train_path = Path("data/processed/unsw_nb15_train.csv")
test_path = Path("data/processed/unsw_nb15_test.csv")
model_path = Path("models/network_intrusion.joblib")
report_path = Path("reports/network_intrusion_evaluation.json")

for path in (train_path, test_path):
    if not path.exists():
        raise FileNotFoundError(f"Missing dataset: {path}")

train = pd.read_csv(train_path)
test = pd.read_csv(test_path)

target = "label"
excluded = {"id", "attack_cat", target}
features = [c for c in train.columns if c not in excluded]

if target not in test.columns or set(features) - set(test.columns):
    raise ValueError("Training and test columns do not match.")

# Convert the binary target explicitly and verify its values.
y_train = pd.to_numeric(train[target], errors="raise").astype(int)
y_test = pd.to_numeric(test[target], errors="raise").astype(int)

if not set(y_train.unique()).issubset({0, 1}) or not set(y_test.unique()).issubset({0, 1}):
    raise ValueError("Expected binary labels 0=normal, 1=attack.")

X_train = train[features].copy()
X_test = test[features].copy()

# Treat known categorical columns as categories; coerce the rest to numeric.
categorical = [
    c for c in ("proto", "service", "state")
    if c in features
]
numeric = [c for c in features if c not in categorical]

for c in categorical:
    X_train[c] = X_train[c].replace("", pd.NA).fillna("unknown").astype(str)
    X_test[c] = X_test[c].replace("", pd.NA).fillna("unknown").astype(str)

for c in numeric:
    X_train[c] = pd.to_numeric(X_train[c], errors="coerce")
    X_test[c] = pd.to_numeric(X_test[c], errors="coerce")

numeric_pipe = Pipeline([
    ("imputer", SimpleImputer(strategy="median")),
])

categorical_pipe = Pipeline([
    ("imputer", SimpleImputer(strategy="most_frequent")),
    ("onehot", OneHotEncoder(handle_unknown="ignore")),
])

preprocessor = ColumnTransformer([
    ("numeric", numeric_pipe, numeric),
    ("categorical", categorical_pipe, categorical),
])

pipeline = Pipeline([
    ("preprocessor", preprocessor),
    ("classifier", RandomForestClassifier(
        n_estimators=150,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced_subsample",
    )),
])

print(f"Training rows: {len(X_train):,}")
print(f"Test rows: {len(X_test):,}")
print(f"Features: {len(features)}")
print("Training Random Forest...")
pipeline.fit(X_train, y_train)

pred = pipeline.predict(X_test)
tn, fp, fn, tp = confusion_matrix(y_test, pred, labels=[0, 1]).ravel()

metrics = {
    "dataset": "UNSW-NB15",
    "task": "binary normal-versus-attack classification",
    "train_rows": int(len(y_train)),
    "test_rows": int(len(y_test)),
    "features": features,
    "excluded_columns": sorted(excluded),
    "label_mapping": {"0": "normal", "1": "attack"},
    "accuracy": float(accuracy_score(y_test, pred)),
    "precision_attack": float(precision_score(y_test, pred, zero_division=0)),
    "recall_attack": float(recall_score(y_test, pred, zero_division=0)),
    "f1_attack": float(f1_score(y_test, pred, zero_division=0)),
    "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
    "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
    "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    "classification_report": classification_report(
        y_test, pred, labels=[0, 1],
        target_names=["normal", "attack"],
        output_dict=True, zero_division=0,
    ),
}

model_path.parent.mkdir(parents=True, exist_ok=True)
report_path.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(pipeline, model_path)
report_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

print("\nEvaluation on the supplied test set:")
print(classification_report(
    y_test, pred, labels=[0, 1],
    target_names=["normal", "attack"], zero_division=0
))
print("Confusion matrix [[TN, FP], [FN, TP]]:")
print([[tn, fp], [fn, tp]])
print(f"\nAccuracy: {metrics['accuracy']:.4f}")
print(f"Attack F1: {metrics['f1_attack']:.4f}")
print(f"False-positive rate: {metrics['false_positive_rate']:.4f}")
print(f"False-negative rate: {metrics['false_negative_rate']:.4f}")
print(f"\nModel saved to: {model_path}")
print(f"Metrics saved to: {report_path}")
