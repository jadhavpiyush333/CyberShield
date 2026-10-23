import json
from pathlib import Path

import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder
from sklearn.ensemble import RandomForestClassifier

train_path = Path("data/processed/unsw_nb15_train.csv")
test_path = Path("data/processed/unsw_nb15_test.csv")
model_path = Path("models/network_intrusion_tuned.joblib")
report_path = Path("reports/network_random_forest_threshold_tuning.json")

train = pd.read_csv(train_path)
test = pd.read_csv(test_path)

target = "label"
excluded = {"id", "attack_cat", target}
features = [c for c in train.columns if c not in excluded]

if set(features) - set(test.columns):
    raise ValueError("Test data is missing training features.")

y = pd.to_numeric(train[target], errors="raise").astype(int)
y_test = pd.to_numeric(test[target], errors="raise").astype(int)

if set(y.unique()) != {0, 1} or set(y_test.unique()) != {0, 1}:
    raise ValueError("Expected labels 0=normal and 1=attack.")

X = train[features].copy()
X_test = test[features].copy()

categorical = [c for c in ("proto", "service", "state") if c in features]
numeric = [c for c in features if c not in categorical]

for frame in (X, X_test):
    for c in categorical:
        frame[c] = frame[c].replace("", pd.NA).fillna("unknown").astype(str)
    for c in numeric:
        frame[c] = pd.to_numeric(frame[c], errors="coerce")

X_fit, X_val, y_fit, y_val = train_test_split(
    X, y, test_size=0.20, random_state=42, stratify=y
)

def build_model():
    preprocessor = ColumnTransformer([
        ("numeric", Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
        ]), numeric),
        ("categorical", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]), categorical),
    ])

    return Pipeline([
        ("preprocessor", preprocessor),
        ("classifier", RandomForestClassifier(
            n_estimators=150,
            random_state=42,
            n_jobs=-1,
            class_weight="balanced_subsample",
        )),
    ])

print(f"Training rows available: {len(X):,}")
print(f"Internal fit rows: {len(X_fit):,}")
print(f"Validation rows: {len(X_val):,}")
print(f"Held-out test rows: {len(X_test):,}")

# Select threshold using validation data only.
validation_model = build_model()
print("\nTraining validation model...")
validation_model.fit(X_fit, y_fit)

classifier = validation_model.named_steps["classifier"]
positive_index = list(classifier.classes_).index(1)
val_prob = validation_model.predict_proba(X_val)[:, positive_index]

candidates = []
for threshold in [i / 100 for i in range(5, 96)]:
    pred = (val_prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_val, pred, labels=[0, 1]
    ).ravel()

    recall = tp / (tp + fn) if tp + fn else 0.0
    fpr = fp / (fp + tn) if fp + tn else 0.0

    if recall >= 0.90:
        candidates.append({
            "threshold": threshold,
            "recall_attack": recall,
            "false_positive_rate": fpr,
            "precision_attack": precision_score(
                y_val, pred, zero_division=0
            ),
            "f1_attack": f1_score(y_val, pred, zero_division=0),
        })

if not candidates:
    raise RuntimeError(
        "No threshold achieved validation attack recall >= 0.90."
    )

best = min(
    candidates,
    key=lambda m: (
        m["false_positive_rate"],
        -m["precision_attack"],
        -m["threshold"],
    ),
)
threshold = best["threshold"]

print("\nThreshold selected on validation data:")
print(json.dumps(best, indent=2))

# Refit on all official training rows; evaluate test exactly once.
final_model = build_model()
print("\nRetraining on all training rows...")
final_model.fit(X, y)

test_classifier = final_model.named_steps["classifier"]
test_positive_index = list(test_classifier.classes_).index(1)
test_prob = final_model.predict_proba(X_test)[:, test_positive_index]
test_pred = (test_prob >= threshold).astype(int)

tn, fp, fn, tp = confusion_matrix(
    y_test, test_pred, labels=[0, 1]
).ravel()

metrics = {
    "dataset": "UNSW-NB15",
    "model": "RandomForestClassifier",
    "training_rows": int(len(X)),
    "validation_rows": int(len(X_val)),
    "test_rows": int(len(X_test)),
    "features": features,
    "label_mapping": {"0": "normal", "1": "attack"},
    "threshold": threshold,
    "threshold_selection": (
        "Lowest validation false-positive rate among thresholds "
        "with attack recall >= 0.90"
    ),
    "validation_selection_metrics": best,
    "test_metrics": {
        "accuracy": float(accuracy_score(y_test, test_pred)),
        "precision_attack": float(precision_score(
            y_test, test_pred, zero_division=0
        )),
        "recall_attack": float(recall_score(
            y_test, test_pred, zero_division=0
        )),
        "f1_attack": float(f1_score(
            y_test, test_pred, zero_division=0
        )),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else None,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else None,
        "roc_auc": float(roc_auc_score(y_test, test_prob)),
        "confusion_matrix": {
            "tn": int(tn), "fp": int(fp),
            "fn": int(fn), "tp": int(tp),
        },
    },
}

model_path.parent.mkdir(parents=True, exist_ok=True)
report_path.parent.mkdir(parents=True, exist_ok=True)
joblib.dump(final_model, model_path)
report_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

print("\nHeld-out test metrics:")
print(json.dumps(metrics["test_metrics"], indent=2))
print(f"\nTuned model saved to: {model_path}")
print(f"Report saved to: {report_path}")
print("\nExisting model files and registry were not changed.")
