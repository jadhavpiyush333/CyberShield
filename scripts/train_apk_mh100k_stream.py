import json
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from scipy.sparse import csr_matrix
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

BASE = Path("data/raw/phase2")
PARQUET = BASE / "mh100.parquet"
LABELS = BASE / "mh100-labels.csv"
MODEL_OUT = Path("models/apk_malware_classifier.joblib")
METRICS_OUT = Path("reports/apk_malware_classifier_metrics.json")

BATCH_SIZE = 256
EPOCHS = 3
SEED = 42

def main():
    started = time.time()

    for path in (PARQUET, LABELS):
        if not path.exists():
            raise FileNotFoundError(f"Required dataset file missing: {path}")

    print("Reading labels...", flush=True)
    y = pd.read_csv(LABELS, usecols=["class"])["class"].to_numpy(
        dtype=np.int8
    )

    if not np.isin(y, [0, 1]).all():
        raise ValueError("Expected binary labels 0 and 1.")

    # Dataset counts match the published MH-100K class totals.
    # Assumption: class 0 = benign, class 1 = malware.
    counts = np.bincount(y, minlength=2)
    if counts.tolist() != [92134, 9800]:
        raise ValueError(
            f"Unexpected class counts {counts.tolist()}; "
            "recheck label mapping before training."
        )

    parquet = pq.ParquetFile(PARQUET)
    n_rows = parquet.metadata.num_rows
    n_features = parquet.metadata.num_columns

    if n_rows != len(y):
        raise ValueError(f"Rows mismatch: parquet={n_rows}, labels={len(y)}")

    print(f"Rows: {n_rows:,}; features: {n_features:,}", flush=True)
    print(f"Class counts: benign={counts[0]:,}, malware={counts[1]:,}")
    print("Creating stratified 80/20 split...", flush=True)

    indices = np.arange(n_rows)
    train_idx, test_idx = train_test_split(
        indices,
        test_size=0.20,
        random_state=SEED,
        stratify=y,
    )

    train_mask = np.zeros(n_rows, dtype=bool)
    test_mask = np.zeros(n_rows, dtype=bool)
    train_mask[train_idx] = True
    test_mask[test_idx] = True

    # The malware class is the minority class; weight it more heavily.
    weights = {0: 1.0, 1: float(counts[0] / counts[1])}
    model = SGDClassifier(
        loss="log_loss",
        penalty="l2",
        alpha=0.0001,
        class_weight=weights,
        random_state=SEED,
        max_iter=1,
        tol=None,
        average=True,
    )

    rng = np.random.default_rng(SEED)
    first_batch = True

    for epoch in range(EPOCHS):
        print(f"\nTraining epoch {epoch + 1}/{EPOCHS}", flush=True)
        row_start = 0
        rows_seen = 0

        for batch in parquet.iter_batches(batch_size=BATCH_SIZE):
            row_end = row_start + batch.num_rows

            batch_y = y[row_start:row_end]
            local_train = train_mask[row_start:row_end]

            if local_train.any():
                # Only materialize one small batch as a NumPy array.
                dense = batch.to_pandas().to_numpy(
                    dtype=np.int8, copy=False
                )
                X_batch = csr_matrix(dense[local_train])
                y_batch = batch_y[local_train]

                # Shuffle within the batch to reduce ordering effects.
                order = rng.permutation(len(y_batch))
                X_batch = X_batch[order]
                y_batch = y_batch[order]

                if first_batch:
                    model.partial_fit(X_batch, y_batch, classes=np.array([0, 1]))
                    first_batch = False
                else:
                    model.partial_fit(X_batch, y_batch)

                rows_seen += len(y_batch)

            row_start = row_end

        print(f"Training rows processed: {rows_seen:,}", flush=True)

    print("\nEvaluating held-out test set...", flush=True)
    predictions = np.empty(len(test_idx), dtype=np.int8)
    probabilities = np.empty(len(test_idx), dtype=np.float32)

    # Map original dataset row indices to their position in test_idx.
    test_position = np.full(n_rows, -1, dtype=np.int32)
    test_position[test_idx] = np.arange(len(test_idx))

    row_start = 0
    for batch in parquet.iter_batches(batch_size=BATCH_SIZE):
        row_end = row_start + batch.num_rows
        local_test = test_mask[row_start:row_end]

        if local_test.any():
            dense = batch.to_pandas().to_numpy(
                dtype=np.int8, copy=False
            )
            X_batch = csr_matrix(dense[local_test])
            original_rows = np.arange(row_start, row_end)[local_test]
            positions = test_position[original_rows]

            predictions[positions] = model.predict(X_batch).astype(np.int8)
            probabilities[positions] = model.predict_proba(X_batch)[:, 1]

        row_start = row_end

    y_test = y[test_idx]
    cm = confusion_matrix(y_test, predictions, labels=[0, 1])

    metrics = {
        "dataset": "MH-100K",
        "label_mapping": {"0": "benign", "1": "malware"},
        "label_mapping_note": (
            "Inferred from the published class totals; verify against "
            "the original dataset label definition."
        ),
        "rows": int(n_rows),
        "features": int(n_features),
        "class_counts": {
            "benign": int(counts[0]),
            "malware": int(counts[1]),
        },
        "train_rows": int(len(train_idx)),
        "test_rows": int(len(test_idx)),
        "epochs": EPOCHS,
        "batch_size": BATCH_SIZE,
        "accuracy": float(accuracy_score(y_test, predictions)),
        "precision_malware": float(
            precision_score(y_test, predictions, pos_label=1, zero_division=0)
        ),
        "recall_malware": float(
            recall_score(y_test, predictions, pos_label=1, zero_division=0)
        ),
        "f1_malware": float(
            f1_score(y_test, predictions, pos_label=1, zero_division=0)
        ),
        "confusion_matrix_labels_order": ["benign_0", "malware_1"],
        "confusion_matrix": cm.tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            labels=[0, 1],
            target_names=["benign", "malware"],
            output_dict=True,
            zero_division=0,
        ),
        "elapsed_seconds": round(time.time() - started, 2),
        "model": str(MODEL_OUT),
    }

    MODEL_OUT.parent.mkdir(parents=True, exist_ok=True)
    METRICS_OUT.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_OUT, compress=3)
    METRICS_OUT.write_text(json.dumps(metrics, indent=2))

    print("\n===== HELD-OUT RESULTS =====")
    print(json.dumps({
        k: metrics[k] for k in [
            "accuracy", "precision_malware", "recall_malware",
            "f1_malware", "confusion_matrix", "elapsed_seconds"
        ]
    }, indent=2))
    print(f"\nSaved model: {MODEL_OUT}")
    print(f"Saved metrics: {METRICS_OUT}")

if __name__ == "__main__":
    main()
