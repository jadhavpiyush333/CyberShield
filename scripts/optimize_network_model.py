from pathlib import Path
import json
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.base import clone
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/external/unsw-nb15/corrected"
OUT = ROOT / "reports/experiments"
OUT.mkdir(parents=True, exist_ok=True)

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
CAT = ["proto", "service", "state"]
DROP = ["id", "attack_cat", "label"]


def load_file(name):
    path = DATA / name
    if not path.exists():
        raise FileNotFoundError(f"Missing dataset: {path}")
    df = pd.read_csv(path, sep="\t", header=None, names=COLUMNS)
    y = pd.to_numeric(df["label"], errors="raise").astype(int)
    if not set(y.unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 and 1.")
    X = df.drop(columns=DROP).copy()
    for c in CAT:
        X[c] = X[c].fillna("unknown").astype(str).str.strip()
    nums = [c for c in X.columns if c not in CAT]
    for c in nums:
        X[c] = pd.to_numeric(X[c], errors="coerce")
    X[nums] = X[nums].replace([np.inf, -np.inf], np.nan)
    return X, y


def make_pipeline(class_weight):
    numeric = [c for c in COLUMNS if c not in DROP + CAT]
    prep = ColumnTransformer([
        ("num", Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scale", StandardScaler()),
        ]), numeric),
        ("cat", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", OneHotEncoder(handle_unknown="ignore")),
        ]), CAT),
    ])
    return Pipeline([
        ("prep", prep),
        ("clf", LogisticRegression(
            max_iter=1000,
            class_weight=class_weight,
            solver="lbfgs",
            random_state=42,
        )),
    ])


def metrics(y, pred, scores):
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {
        "accuracy": float(accuracy_score(y, pred)),
        "precision_attack": float(precision_score(y, pred, zero_division=0)),
        "recall_attack": float(recall_score(y, pred, zero_division=0)),
        "f1_attack": float(f1_score(y, pred, zero_division=0)),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "roc_auc": float(roc_auc_score(y, scores)),
        "confusion_matrix": {
            "true_negative": int(tn), "false_positive": int(fp),
            "false_negative": int(fn), "true_positive": int(tp),
        },
    }


def main():
    print("CyberShield network model optimization")
    print("scikit-learn:", sklearn.__version__)

    X, y = load_file("UNSW_NB15_training-set.csv")
    X_test, y_test = load_file("UNSW_NB15_testing-set.csv")

    if len(X) != 175341 or len(X_test) != 82332:
        raise ValueError(
            f"Unexpected split sizes: train={len(X)}, test={len(X_test)}"
        )

    # The official test set is not used for model selection or threshold tuning.
    X_fit, X_val, y_fit, y_val = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    results = {}
    fitted = {}

    for name, weight in [
        ("weighted", "balanced"),
        ("unweighted", None),
    ]:
        print(f"\nFitting {name} model...")
        model = make_pipeline(weight)
        start = time.time()
        model.fit(X_fit, y_fit)
        print(f"Fit time: {time.time() - start:.1f}s")

        scores = model.predict_proba(X_val)[:, 1]
        pred = (scores >= 0.5).astype(int)
        results[name] = {
            "class_weight": weight,
            "validation_at_0_5": metrics(y_val, pred, scores),
        }
        fitted[name] = model

        print(f"{name} validation @ 0.5:")
        print(json.dumps(results[name]["validation_at_0_5"], indent=2))

    # Select a threshold using validation predictions only.
    # Prefer the lowest validation FPR among thresholds with >=90% recall.
    weighted_scores = fitted["weighted"].predict_proba(X_val)[:, 1]
    threshold_rows = []

    for threshold in np.arange(0.20, 0.951, 0.01):
        pred = (weighted_scores >= threshold).astype(int)
        m = metrics(y_val, pred, weighted_scores)
        threshold_rows.append({"threshold": round(float(threshold), 2), **m})

    eligible = [r for r in threshold_rows if r["recall_attack"] >= 0.90]
    if eligible:
        chosen = max(
            eligible,
            key=lambda r: (
                -r["false_positive_rate"],
                r["f1_attack"],
                r["threshold"],
            ),
        )
        selection_rule = "Lowest validation FPR among thresholds with recall >= 0.90"
    else:
        chosen = max(threshold_rows, key=lambda r: r["f1_attack"])
        selection_rule = "No threshold reached 90% recall; selected highest validation F1"

    results["threshold_selection"] = {
        "model": "weighted",
        "threshold": chosen["threshold"],
        "selection_rule": selection_rule,
        "validation_metrics": chosen,
        "validation_threshold_sweep": threshold_rows,
    }

    # Save experiment results without changing the existing model/report.
    (OUT / "network_optimization_validation.json").write_text(
        json.dumps(results, indent=2)
    )
    print("\nSelected threshold:", chosen["threshold"])
    print("Selection rule:", selection_rule)
    print("Validation metrics:")
    print(json.dumps(chosen, indent=2))

    # Final evaluation of selected validation strategy on official test set.
    # Fit a fresh weighted model on the complete official training file.
    print("\nFitting final weighted model on all official training rows...")
    final_model = make_pipeline("balanced")
    final_model.fit(X, y)
    test_scores = final_model.predict_proba(X_test)[:, 1]
    test_pred = (test_scores >= chosen["threshold"]).astype(int)
    test_metrics = metrics(y_test, test_pred, test_scores)

    final_report = {
        "dataset": "UNSW-NB15",
        "training_samples": int(len(X)),
        "validation_samples": int(len(X_val)),
        "test_samples": int(len(X_test)),
        "threshold_selected_on_validation": chosen["threshold"],
        "selection_rule": selection_rule,
        "model": "StandardScaler + OneHotEncoder + LogisticRegression",
        "class_weight": "balanced",
        "test_metrics": test_metrics,
        "classification_report": classification_report(
            y_test, test_pred, labels=[0, 1],
            target_names=["normal", "attack"],
            output_dict=True, zero_division=0,
        ),
        "note": (
            "Threshold was selected using a validation split from the official "
            "training file. Official test set was used only for final evaluation."
        ),
    }

    joblib.dump(final_model, OUT / "network_ids_optimized.joblib")
    (OUT / "network_optimization_final_test.json").write_text(
        json.dumps(final_report, indent=2)
    )

    print("\n=== FINAL OFFICIAL TEST RESULTS ===")
    print(json.dumps(test_metrics, indent=2))
    print("\nSaved experiment model:", OUT / "network_ids_optimized.joblib")
    print("Saved validation experiment:", OUT / "network_optimization_validation.json")
    print("Saved final test report:", OUT / "network_optimization_final_test.json")
    print("\nExisting models/network_ids.joblib was not changed.")


if __name__ == "__main__":
    main()
