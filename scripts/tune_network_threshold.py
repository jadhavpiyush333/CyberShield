from pathlib import Path
import joblib
import numpy as np
import pandas as pd

from sklearn.base import clone
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score

base = Path("data/processed/unsw-nb15")
train_df = pd.read_csv(base / "UNSW_NB15_testing-set.csv")
model = joblib.load("models/network_intrusion.joblib")
columns = list(model.feature_names_in_)

def prepare(df):
    df = df.rename(columns={"res_bdy_len": "response_body_len"})
    missing = [c for c in columns if c not in df.columns]
    if missing:
        raise ValueError(f"Missing features: {missing}")
    X = df[columns].copy()
    y = pd.to_numeric(df["label"]).astype(int)
    return X, y

X, y = prepare(train_df)
X_fit, X_val, y_fit, y_val = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

validation_model = clone(model)
validation_model.fit(X_fit, y_fit)

classes = list(validation_model.classes_)
attack_index = classes.index(1)
prob = validation_model.predict_proba(X_val)[:, attack_index]

print("Validation rows:", len(y_val))
print("Threshold | Precision | Recall | F1 | FPR | FNR")

rows = []
for threshold in np.arange(0.10, 0.951, 0.05):
    pred = (prob >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(
        y_val, pred, labels=[0, 1]
    ).ravel()
    fpr = fp / (fp + tn) if fp + tn else 0
    fnr = fn / (fn + tp) if fn + tp else 0
    row = {
        "threshold": round(float(threshold), 2),
        "precision": precision_score(y_val, pred, zero_division=0),
        "recall": recall_score(y_val, pred, zero_division=0),
        "f1": f1_score(y_val, pred, zero_division=0),
        "fpr": fpr,
        "fnr": fnr,
    }
    rows.append(row)
    print(
        f"{row['threshold']:.2f} | {row['precision']:.4f} | "
        f"{row['recall']:.4f} | {row['f1']:.4f} | "
        f"{row['fpr']:.4f} | {row['fnr']:.4f}"
    )

Path("reports/network_validation").mkdir(parents=True, exist_ok=True)
pd.DataFrame(rows).to_csv(
    "reports/network_validation/threshold_validation.csv", index=False
)
print("\nSaved reports/network_validation/threshold_validation.csv")
print("Choose the operating threshold based on the validation trade-off.")
print("Do not select the final threshold using the held-out test results.")
