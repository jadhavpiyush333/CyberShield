
"""CyberShield phishing URL detector."""

import math
import re
from collections import Counter
from urllib.parse import urlparse

from cybershield.schemas import DetectionResult
from cybershield.ml.features import url_features


WORDS = {
    "login", "verify", "verification", "secure", "account",
    "update", "wallet", "bank", "password", "credential",
    "bonus", "free", "claim", "urgent", "signin", "confirm",
    "authenticate", "payment", "recovery",
}


def entropy(value):
    """Calculate Shannon entropy for a string."""
    if not value:
        return 0.0

    counts = Counter(value)
    length = len(value)

    return -sum(
        (count / length) * math.log2(count / length)
        for count in counts.values()
    )


def detect(url):
    """Run heuristic phishing checks and return DetectionResult."""
    if not isinstance(url, str) or not url.strip():
        return DetectionResult(
            "phishing_url",
            "low",
            0,
            0.0,
            ["No URL was provided."],
            ["Enter a valid URL to scan."],
        )

    url = url.strip()

    # Reject control characters and unsupported URL schemes.
    if any(ord(char) < 32 for char in url):
        return DetectionResult(
            "phishing_url", "low", 0, 0.0,
            ["URL contains control characters."],
            ["Check the URL before scanning."],
        )

    normalized = url if "://" in url else "https://" + url

    try:
        parsed = urlparse(normalized)
        hostname = parsed.hostname or ""
        _ = parsed.port
    except ValueError:
        return DetectionResult(
            "phishing_url", "low", 0, 0.0,
            ["URL is malformed."],
            ["Check the URL and try again."],
        )

    if parsed.scheme.lower() not in {"http", "https"} or not hostname:
        return DetectionResult(
            "phishing_url", "low", 0, 0.0,
            ["URL scheme or hostname is invalid."],
            ["Use a complete HTTP or HTTPS URL."],
        )

    text = normalized.lower()
    score = 0
    evidence = []

    checks = [
        (
            parsed.scheme.lower() != "https",
            15,
            "URL does not use HTTPS.",
        ),
        (
            bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", hostname)),
            25,
            "Host appears to be an IPv4 address.",
        ),
        (
            "@" in parsed.netloc,
            30,
            "URL contains an @ delimiter in its authority section.",
        ),
        (
            hostname.count(".") >= 3,
            15,
            "Hostname contains multiple subdomains.",
        ),
        (
            any(word in text for word in WORDS),
            15,
            "URL contains suspicious account or security wording.",
        ),
        (
            len(normalized) > 120,
            10,
            "URL is unusually long.",
        ),
        (
            entropy(hostname + parsed.path) > 4,
            10,
            "Hostname and path have high character entropy.",
        ),
    ]

    for triggered, weight, message in checks:
        if triggered:
            score += weight
            evidence.append(message)

    score = min(100, score)

    severity = (
        "critical" if score >= 80 else
        "high" if score >= 60 else
        "medium" if score >= 35 else
        "low"
    )

    confidence = min(0.99, 0.5 + score / 200)

    actions = (
        [
            "Do not enter passwords, payment details, or OTPs.",
            "Open the official website manually instead of following the link.",
            "Block or report the URL if it is confirmed malicious.",
        ]
        if score >= 35
        else [
            "Verify the domain before entering sensitive information.",
            "Treat unexpected links cautiously.",
        ]
    )

    return DetectionResult(
        "phishing_url",
        severity,
        score,
        confidence,
        evidence,
        actions,
    )


def scan_url(url, model_result=None):
    """Compatibility wrapper for callers expecting scan_url().

    The existing detector returns DetectionResult. The optional model_result
    argument is accepted for compatibility, but is not yet fused into the
    verdict because the model's positive-class mapping must be verified.
    """
    return detect(url)


def scan(url, model_result=None):
    """Compatibility alias."""
    return detect(url)


def detect_phishing(url, model_result=None):
    """Compatibility alias."""
    return detect(url)
