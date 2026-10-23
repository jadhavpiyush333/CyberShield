"""CyberShield registry for trained local ML models."""

from pathlib import Path

import joblib
import pandas as pd

from .features import url_features


class ModelRegistry:
    """Load and run the saved phishing, SMS, and network models."""

    NETWORK_MODEL_CANDIDATES = (
        "network_intrusion_tuned.joblib",
        "network_intrusion.joblib",
        "network_ids.joblib",
    )

    def __init__(self, root="models"):
        self.root = Path(root)
        self.models = {}
        self.network_threshold = 0.85
        self.load_errors = {}

    def load(self):
        """Load available models without hiding loading errors."""
        self.models.clear()
        self.load_errors.clear()

        for name in ("phishing_url", "scam_text"):
            path = self.root / f"{name}.joblib"
            self._load_one(name, path)

        # Prefer the candidate model, then the other saved models.
        for filename in self.NETWORK_MODEL_CANDIDATES:
            path = self.root / filename
            if path.exists():
                self._load_one("network_ids", path)
                if "network_ids" in self.models:
                    break

        return self

    def _load_one(self, name, path):
        if not path.exists():
            self.load_errors[name] = f"Model file not found: {path}"
            return

        try:
            self.models[name] = joblib.load(path)
            print(f"[CyberShield] Loaded {name}: {path}")
        except Exception as exc:
            self.load_errors[name] = str(exc)
            print(f"[CyberShield] Could not load {path}: {exc}")

    @staticmethod
    def _positive_probability(model, frame):
        """Return the probability for class 1, when supported."""
        if not hasattr(model, "predict_proba"):
            return None

        probabilities = model.predict_proba(frame)[0]
        classes = list(model.classes_)
        if 1 not in classes:
            return 0.0

        return float(probabilities[classes.index(1)])

    def _predict(self, name, frame):
        model = self.models.get(name)
        if model is None:
            return None

        prediction = int(model.predict(frame)[0])
        probability = self._positive_probability(model, frame)

        # Keep both fields explicit: confidence is the predicted class's
        # probability; positive_probability is the probability of class 1.
        confidence = None
        if probability is not None:
            confidence = (
                probability if prediction == 1 else 1.0 - probability
            )

        return {
            "available": True,
            "prediction": prediction,
            "label": prediction,
            "confidence": confidence,
            "positive_probability": probability,
            "model_version": name + "-1.0",
        }

    def phishing(self, url):
        """Predict whether a URL belongs to the phishing class."""
        try:
            return self._predict(
                "phishing_url",
                url_features([url]),
            )
        except Exception as exc:
            return {
                "available": False,
                "error": "phishing_prediction_failed",
                "message": str(exc),
            }

    def scam(self, message):
        """Predict whether an SMS belongs to the positive class."""
        try:
            # The saved SMS pipeline accepts raw message strings.
            return self._predict("scam_text", [message])
        except Exception as exc:
            return {
                "available": False,
                "error": "sms_prediction_failed",
                "message": str(exc),
            }

    def network(self, event):
        """Predict a complete flow using the selected saved IDS model."""
        model = self.models.get("network_ids")
        if model is None:
            return {
                "available": False,
                "error": "network_model_unavailable",
                "message": self.load_errors.get(
                    "network", "No network model was loaded."
                ),
            }

        columns = list(getattr(model, "feature_names_in_", []))
        if not columns:
            return {
                "available": False,
                "error": "network_feature_schema_unavailable",
                "message": (
                    "The model does not expose its expected feature names."
                ),
            }

        if not isinstance(event, dict):
            return {
                "available": False,
                "error": "invalid_flow_record",
                "message": "Provide a network flow as a dictionary.",
            }

        # Never invent missing traffic features.
        missing = [column for column in columns if column not in event]
        if missing:
            return {
                "available": False,
                "error": "incomplete_flow_record",
                "message": (
                    "A complete flow record is required. "
                    f"Missing {len(missing)} model features."
                ),
                "missing_fields": missing,
            }

        categorical = {"proto", "service", "state"}
        row = {}

        try:
            for column in columns:
                value = event[column]

                if column in categorical:
                    if pd.isna(value):
                        raise ValueError(
                            f"Categorical feature {column} is missing."
                        )
                    row[column] = str(value).strip()
                else:
                    number = pd.to_numeric(value, errors="raise")
                    if pd.isna(number):
                        raise ValueError(
                            f"Numeric feature {column} is missing."
                        )
                    row[column] = float(number)

            frame = pd.DataFrame([row], columns=columns)
            prediction = int(model.predict(frame)[0])
            probability = self._positive_probability(model, frame)

            if probability is None:
                return {
                    "available": False,
                    "error": "network_probability_unavailable",
                    "message": (
                        "The network model does not support probability "
                        "estimation; the configured threshold cannot be used."
                    ),
                }

            return {
                "available": True,
                "prediction": int(probability >= self.network_threshold),
                "model_prediction": prediction,
                "attack_probability": probability,
                "confidence": (
                    probability if prediction == 1 else 1.0 - probability
                ),
                "threshold": self.network_threshold,
                "model_version": "network-ids-1.0",
            }

        except (TypeError, ValueError, KeyError) as exc:
            return {
                "available": False,
                "error": "invalid_flow_feature",
                "message": str(exc),
            }
        except Exception as exc:
            return {
                "available": False,
                "error": "network_prediction_failed",
                "message": str(exc),
            }
