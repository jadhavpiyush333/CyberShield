"""Main engine for CyberShield threat detection."""

from cybershield.detectors.phishing import detect as url_rule
from cybershield.detectors.scam import detect as msg_rule
from cybershield.detectors.network import detect as net_rule
from cybershield.detectors.malware import detect as mal

from cybershield.storage import Storage
from cybershield.advisor.local_advisor import advise
from cybershield.ml.model_registry import ModelRegistry


class CyberShieldEngine:
    """Coordinate rule-based and machine-learning threat detection."""

    def __init__(self):
        self.storage = Storage()
        self.models = ModelRegistry().load()

    def _s(self, result):
        """Save a DetectionResult and return its dictionary."""
        data = result.to_dict()
        self.storage.save(data)
        return data

    @staticmethod
    def _is_positive_prediction(label, positive_labels):
        """Recognize known positive class labels."""
        if isinstance(label, bool):
            return label

        if isinstance(label, (int, float)):
            return label == 1

        return str(label).strip().lower() in positive_labels

    @staticmethod
    def _update_severity(result):
        """Keep severity consistent with the risk score."""
        score = float(result.risk_score)

        if score >= 80:
            result.severity = "critical"
        elif score >= 60:
            result.severity = "high"
        elif score >= 35:
            result.severity = "medium"
        else:
            result.severity = "low"

    def _apply_text_model(
        self, result, prediction, model_name, positive_labels
    ):
        """Apply ML output while preserving heuristic evidence."""

        if not isinstance(prediction, dict):
            return result

        if not prediction.get("available", False):
            error = prediction.get("error")
            if error:
                result.evidence.append(
                    f"{model_name} model unavailable: {error}"
                )
            return result

        if "prediction" not in prediction:
            result.evidence.append(
                f"{model_name} model returned no prediction."
            )
            return result

        label = prediction["prediction"]
        positive = self._is_positive_prediction(
            label, positive_labels
        )

        result.evidence.append(
            f"{model_name} model predicted class: {label!s}."
        )

        confidence = prediction.get("confidence")
        if confidence is not None:
            try:
                confidence = float(confidence)
                if 0.0 <= confidence <= 1.0:
                    result.confidence = confidence
            except (TypeError, ValueError):
                pass

        result.model_version = prediction.get(
            "model_version", f"{model_name}-ml-1.0"
        )

        # Only a positive prediction can raise the heuristic risk score.
        if positive:
            probability = prediction.get("positive_probability")

            try:
                if probability is None:
                    probability = confidence

                probability = float(probability)
                if 0.0 <= probability <= 1.0:
                    result.risk_score = max(
                        float(result.risk_score),
                        probability * 100.0,
                    )
            except (TypeError, ValueError):
                pass

            if float(result.risk_score) >= 35:
                result.recommended_actions = [
                    "Do not open the link or follow its instructions.",
                    "Verify the sender and destination using an official channel.",
                    "Do not share passwords, payment information, or OTPs.",
                ]

        self._update_severity(result)
        return result

    def scan_url(self, url):
        """Scan a URL with heuristic and trained-model detection."""
        result = url_rule(url)
        prediction = self.models.phishing(url)

        result = self._apply_text_model(
            result,
            prediction,
            "phishing-url",
            {"1", "phishing", "malicious", "phish", "true"},
        )
        return self._s(result)

    def scan_message(self, message):
        """Scan an SMS with heuristic and trained-model detection."""
        result = msg_rule(message)
        prediction = self.models.scam(message)

        result = self._apply_text_model(
            result,
            prediction,
            "scam-sms",
            {"1", "spam", "scam", "fraud", "malicious", "true"},
        )
        return self._s(result)

    def scan_network(self, event):
        """Scan a network flow with ML and rule-based fallback."""
        model_result = self.models.network(event)

        if (
            not isinstance(model_result, dict)
            or not model_result.get("available", False)
        ):
            result = net_rule(event)

            if isinstance(model_result, dict):
                error = model_result.get(
                    "error", "Network model unavailable."
                )
                result.evidence.append(
                    f"Network ML fallback: {error}"
                )

            return self._s(result)

        result = net_rule(event, model_result)
        return self._s(result)

    def scan_behavior(self, behavior):
        """Scan process or malware-behaviour indicators."""
        result = mal(behavior)
        return self._s(result)

    def advice(self, context):
        """Request advice from the configured local advisor."""
        return advise(context)

    def history(self, limit=50):
        """Return recent saved detection results."""
        return self.storage.recent(limit)
