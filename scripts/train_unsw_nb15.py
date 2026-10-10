from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data" / "external" / "unsw-nb15" / "corrected"
MODEL_PATH = ROOT / "models" / "network_ids.joblib"
REPORT_PATH = ROOT / "reports" / "network_official_test_evaluation.json"

COLUMNS = [
    "id", "dur", "proto", "service", "state",
    "spkts", "dpkts", "sbytes", "dbytes", "rate",
    "sttl", "dttl", "sload", "dload", "sloss", "dloss",
    "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb",
    "dtcpb", "dwin", "tcprtt", "synack", "ackdat",
    "smean", "dmean", "trans_depth", "res_bdy_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
    "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
    "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
    "attack_cat", "label",
]

CATEGORICAL = ["proto", "service", "state"]
DROP_FROM_FEATURES = ["id", "attack_cat", "label"]


def load_dataset(filename):
    path = DATA / filename
    if not path.exists():
        raise FileNotFoundError(
            f"Missing {path}\n"
            "Run the filename-correction step first."
        )

    df = pd.read_csv(path, sep="\t", header=None, names=COLUMNS)

    if len(df.columns) != 45:
        raise ValueError(f"Expected 45 columns, got {len(df.columns)}")
    if df["label"].isna().any():
        raise ValueError(f"Missing labels found in {filename}")

    labels = pd.to_numeric(df["label"], errors="raise").astype(int)
    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError("Expected binary labels 0 and 1.")

    for col in CATEGORICAL:
        df[col] = df[col].fillna("unknown").astype(str).str.strip()

    features = df.drop(columns=DROP_FROM_FEATURES).copy()
    numeric_cols = [c for c in features.columns if c not in CATEGORICAL]

    for col in numeric_cols:
        features[col] = pd.to_numeric(features[col], errors="coerce")

    features[numeric_cols] = features[numeric_cols].replace(
        [np.inf, -np.inf], np.nan
    )

    return features, labels


def main():
    print("CyberShield — UNSW-NB15 network intrusion training")
    print("scikit-learn:", sklearn.__version__)

    X_train, y_train = load_dataset("UNSW_NB15_training-set.csv")
    X_test, y_test = load_dataset("UNSW_NB15_testing-set.csv")

    # Fail fast if the files are accidentally reversed.
    if len(X_train) != 175341 or len(X_test) != 82332:
        raise ValueError(
            "Unexpected split sizes. Expected 175341 training rows and "
            f"82332 test rows; got {len(X_train)} and {len(X_test)}."
        )

    print(f"Training rows: {len(X_train):,}")
    print(f"Testing rows:  {len(X_test):,}")
    print("Training label counts:", y_train.value_counts().sort_index().to_dict())
    print("Testing label counts:", y_test.value_counts().sort_index().to_dict())

    numeric_cols = [c for c in X_train.columns if c not in CATEGORICAL]

    numeric_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("scaler", StandardScaler()),
    ])

    categorical_pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("onehot", OneHotEncoder(handle_unknown="ignore")),
    ])

    preprocess = ColumnTransformer([
        ("numeric", numeric_pipeline, numeric_cols),
        ("categorical", categorical_pipeline, CATEGORICAL),
    ])

    model = Pipeline([
        ("preprocess", preprocess),
        ("classifier", LogisticRegression(
            max_iter=1000,
            class_weight="balanced",
            solver="lbfgs",
            random_state=42,
        )),
    ])

    print("\nTraining model... This may take several minutes.")
    start = time.time()
    model.fit(X_train, y_train)
    training_seconds = time.time() - start

    print("Evaluating on the separate test set...")
    predictions = model.predict(X_test)

    tn, fp, fn, tp = confusion_matrix(
        y_test, predictions, labels=[0, 1]
    ).ravel()

    metrics = {
        "dataset": "UNSW-NB15",
        "training_file": "UNSW_NB15_training-set.csv",
        "test_file": "UNSW_NB15_testing-set.csv",
        "training_samples": int(len(X_train)),
        "test_samples": int(len(X_test)),
        "features_used": list(X_train.columns),
        "excluded_columns": DROP_FROM_FEATURES,
        "categorical_columns": CATEGORICAL,
        "model": "StandardScaler + OneHotEncoder + LogisticRegression",
        "class_weight": "balanced",
        "random_state": 42,
        "training_seconds": round(training_seconds, 2),
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_attack": float(precision_score(
            y_test, predictions, zero_division=0
        )),
        "recall_attack": float(recall_score(
            y_test, predictions, zero_division=0
        )),
        "f1_attack": float(f1_score(
            y_test, predictions, zero_division=0
        )),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "confusion_matrix": {
            "true_negative": int(tn),
            "false_positive": int(fp),
            "false_negative": int(fn),
            "true_positive": int(tp),
        },
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["normal", "attack"],
            output_dict=True,
            zero_division=0,
        ),
        "sklearn_version": sklearn.__version__,
        "note": (
            "Metrics are from the supplied held-out test file. "
            "This is a binary normal-versus-attack baseline, not "
            "a multi-class attack-family classifier."
        ),
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, MODEL_PATH)
    REPORT_PATH.write_text(json.dumps(metrics, indent=2))

    print("\n=== HELD-OUT TEST RESULTS ===")
    for key in [
        "accuracy", "precision_attack", "recall_attack",
        "f1_attack", "false_positive_rate", "false_negative_rate"
    ]:
        print(f"{key}: {metrics[key]:.4f}")

    print("\nConfusion matrix:")
    print(f"TN={tn:,}  FP={fp:,}")
    print(f"FN={fn:,}  TP={tp:,}")

    print("\nSaved model:", MODEL_PATH)
    print("Saved evaluation report:", REPORT_PATH)
    print("\nTraining and evaluation completed.")


if __name__ == "__main__":
    main()
