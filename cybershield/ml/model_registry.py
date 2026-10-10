from pathlib import Path

import joblib
import pandas as pd

from .features import text_features, url_features


class ModelRegistry:
    def __init__(self, root="models"):
        self.root = Path(root)
        self.models = {}
        self.network_threshold = 0.61

    def load(self):
        for name in ("phishing_url", "scam_text"):
            path = self.root / f"{name}.joblib"
            if path.exists():
                try:
                    self.models[name] = joblib.load(path)
                except Exception as exc:
                    print(f"Warning: could not load {path}: {exc}")

        optimized = Path("reports/experiments/network_ids_optimized.joblib")
        original = self.root / "network_ids.joblib"

        # Prefer the optimized model, falling back to the original trained model.
        network_path = optimized if optimized.exists() else original
        if network_path.exists():
            try:
                self.models["network_ids"] = joblib.load(network_path)
                print(f"Loaded network model: {network_path}")
            except Exception as exc:
                print(f"Warning: could not load {network_path}: {exc}")

        return self

    def _predict(self, name, X):
        model = self.models.get(name)
        if model is None:
            return None
        prediction = int(model.predict(X)[0])
        confidence = (
            float(max(model.predict_proba(X)[0]))
            if hasattr(model, "predict_proba")
            else 0.5
        )
        return prediction, confidence

    def phishing(self, url):
        return self._predict("phishing_url", url_features([url]))

    def scam(self, text):
        return self._predict("scam_text", [text])

    def network(self, event):
        model = self.models.get("network_ids")
        if model is None:
            return None

        # The trained UNSW-NB15 model requires all of its original input columns.
        columns = [
            "dur", "proto", "service", "state", "spkts", "dpkts",
            "sbytes", "dbytes", "rate", "sttl", "dttl", "sload",
            "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit",
            "djit", "swin", "stcpb", "dtcpb", "dwin", "tcprtt",
            "synack", "ackdat", "smean", "dmean", "trans_depth",
            "res_bdy_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
            "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm",
            "is_ftp_login", "ct_ftp_cmd", "ct_flw_http_mthd",
            "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
        ]
        categorical = {"proto", "service", "state"}

        # Event summaries alone are not UNSW-NB15 flow records.
        # Reject incomplete records rather than inventing feature values.
        missing = [col for col in columns if col not in event]
        if missing:
            return {
                "error": "incomplete_flow_record",
                "message": (
                    "This model requires a complete UNSW-NB15-style flow "
                    "record. Event summaries cannot be evaluated reliably."
                ),
                "missing_fields": missing,
            }

       
        row = {}
        for col in columns:
            value = event[col]

            if col in categorical:
                row[col] = (
                    "unknown"
                    if pd.isna(value)
                    else str(value).strip()
                )
            else:
                try:
                    row[col] = (
                        float(value)
                        if pd.notna(value)
                        else float("nan")
                    )
                except (TypeError, ValueError):
                    return {
                        "error": "invalid_flow_feature",
                        "message": f"Feature {col} must be numeric.",
                    }

        frame = pd.DataFrame([row], columns=columns)
        probability = float(model.predict_proba(frame)[0][1])
        prediction = int(probability >= self.network_threshold)

        frame = pd.DataFrame([row], columns=columns)
        probability = float(model.predict_proba(frame)[0][1])
        prediction = int(probability >= self.network_threshold)

        return {
            "prediction": prediction,
            "attack_probability": probability,
            "threshold": self.network_threshold,
            "model_version": "unsw-nb15-logreg-optimized-1.0",
        }
