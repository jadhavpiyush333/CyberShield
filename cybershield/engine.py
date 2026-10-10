
from cybershield.detectors.phishing import detect as url_rule
from cybershield.detectors.scam import detect as msg_rule
from cybershield.detectors.network import detect as net_rule
from cybershield.detectors.malware import detect as mal

from cybershield.storage import Storage
from cybershield.advisor.local_advisor import advise
from cybershield.ml.model_registry import ModelRegistry


class CyberShieldEngine:
    """Main engine for CyberShield threat detection."""

    def __init__(self):
        self.storage = Storage()
        self.models = ModelRegistry().load()

    def _s(self, result):
        """Save a DetectionResult and return its dictionary."""
        data = result.to_dict()
        self.storage.save(data)
        return data

    def scan_url(self, url):
        """Scan a URL using rules and the trained phishing model."""
        result = url_rule(url)
        prediction = self.models.phishing(url)

        if prediction:
            label, confidence = prediction
            result.model_version = "phishing-url-ml-1.0"
            result.confidence = confidence

            if label:
                result.risk_score = max(
                    result.risk_score,
                    confidence * 100,
                )

        return self._s(result)

    def scan_message(self, message):
        """Scan an SMS using rules and the trained scam model."""
        result = msg_rule(message)
        prediction = self.models.scam(message)

        if prediction:
            label, confidence = prediction
            result.model_version = "scam-sms-ml-1.0"
            result.confidence = confidence

            if label:
                result.risk_score = max(
                    result.risk_score,
                    confidence * 100,
                )

        return self._s(result)

    def scan_network(self, event):
        """
        Scan a network flow using the trained IDS model when
        sufficient flow features are available.

        Incomplete events fall back to the existing heuristic
        detector. Missing model features are never fabricated.
        """
        model_result = self.models.network(event)

        # The ML model requires a complete network-flow record.
        if (
            isinstance(model_result, dict)
            and "error" in model_result
        ):
            result = net_rule(event)

            result.evidence.append(
                model_result.get(
                    "message",
                    "The network ML model could not process this event.",
                )
            )
            result.evidence.append(
                "The trained network model was not used because "
                "required flow features were missing."
            )

            return self._s(result)

        # Use the ML result if available; otherwise the detector
        # retains its heuristic fallback behaviour.
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
