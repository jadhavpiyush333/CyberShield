
import json
from pathlib import Path

import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
)

from cybershield.engine import CyberShieldEngine


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

CATEGORICAL = {"proto", "service", "state", "attack_cat"}
EXCLUDED = {"id", "attack_cat", "label"}

DATA_PATH = Path(
    "data/external/unsw-nb15/corrected/UNSW_NB15_testing-set.csv"
)
REPORT_PATH = Path(
    "reports/network_integration_evaluation.json"
)


def main():
    if not DATA_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATA_PATH}")

    df = pd.read_csv(
        DATA_PATH,
        sep="\t",
        header=None,
        names=COLUMNS,
        low_memory=False,
    )

    if len(df.columns) != 45:
        raise ValueError(f"Expected 45 columns; got {len(df.columns)}")

    for col in COLUMNS:
        if col not in CATEGORICAL and col not in EXCLUDED:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Missing numeric values may be handled by the model's fitted
    # imputer. Missing categorical values are represented as None.
    df = df.where(pd.notna(df), None)

    engine = CyberShieldEngine()
    y_true = df["label"].astype(int).tolist()
    y_pred = []
    attack_scores = []
    fallback_count = 0

    total = len(df)

    for i, (_, row) in enumerate(df.iterrows(), start=1):
        event = {
            col: row[col]
            for col in COLUMNS
            if col not in EXCLUDED
        }

        # Convert pandas/numpy scalars into Python-native values.
        event = {
            key: value.item() if hasattr(value, "item") else value
            for key, value in event.items()
        }

        model_result = engine.models.network(event)

        if not isinstance(model_result, dict) or "prediction" not in model_result:
            fallback_count += 1
            raise RuntimeError(
                f"ML prediction unavailable for row {i}; "
                "stopping so heuristic results cannot contaminate metrics."
            )

        prediction = int(model_result["prediction"])
        probability = float(model_result["attack_probability"])

        y_pred.append(prediction)
        attack_scores.append(probability)

        if i % 10000 == 0 or i == total:
            print(f"Processed {i}/{total} rows")

    tn, fp, fn, tp = confusion_matrix(
        y_true, y_pred, labels=[0, 1]
    ).ravel()

    metrics = {
        "dataset": str(DATA_PATH),
        "evaluation_type": "integrated_model_registry_inference",
        "model_version": "unsw-nb15-logreg-optimized-1.0",
        "classification_threshold": 0.61,
        "samples": total,
        "heuristic_fallbacks": fallback_count,
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision_attack": float(
            precision_score(y_true, y_pred, zero_division=0)
        ),
        "recall_attack": float(
            recall_score(y_true, y_pred, zero_division=0)
        ),
        "f1_attack": float(
            f1_score(y_true, y_pred, zero_division=0)
        ),
        "false_positive_rate": float(fp / (fp + tn)) if fp + tn else 0.0,
        "false_negative_rate": float(fn / (fn + tp)) if fn + tp else 0.0,
        "confusion_matrix": {
            "tn": int(tn),
            "fp": int(fp),
            "fn": int(fn),
            "tp": int(tp),
        },
        "roc_auc": float(roc_auc_score(y_true, attack_scores)),
    }

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(metrics, indent=2))

    print("\n=== Integrated Network Model Evaluation ===")
    print(json.dumps(metrics, indent=2))
    print(f"\nReport saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
