"""CyberShield Phase 2 static and communication analysis.

All processing is local. Uploaded APKs are inspected as ZIP archives;
they are never installed or executed.
"""

import hashlib
import io
import re
import zipfile
from email import policy
from email.parser import BytesParser
from html.parser import HTMLParser
from pathlib import PurePosixPath
from xml.etree import ElementTree

from cybershield.schemas import DetectionResult


MAX_EMAIL_BYTES = 1_000_000
MAX_APK_BYTES = 50 * 1024 * 1024
MAX_QR_BYTES = 10 * 1024 * 1024
MAX_APK_ENTRIES = 10_000
MAX_ARCHIVE_EXPANSION = 200 * 1024 * 1024

URL_RE = re.compile(
    r"""(?i)\b(?:https?://|www\.)[^\s<>"']+"""
)

SUSPICIOUS_PERMISSIONS = {
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.SEND_SMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_CONTACTS",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.SYSTEM_ALERT_WINDOW",
}


def _urls(text):
    """Extract URL-like strings without visiting them."""
    return list(dict.fromkeys(
        match.rstrip(".,;:!?)]}") for match in URL_RE.findall(text or "")
    ))[:30]


def _result(engine, kind, evidence, risk, actions, confidence=0.5, model_version="phase2-static-1.0"):
    """Persist a standard DetectionResult through the existing engine."""
    risk = max(0.0, min(100.0, float(risk)))
    severity = (
        "critical" if risk >= 80 else
        "high" if risk >= 60 else
        "medium" if risk >= 35 else
        "low"
    )
    result = DetectionResult(
        threat_type=kind,
        severity=severity,
        risk_score=risk,
        confidence=max(0.0, min(1.0, float(confidence))),
        evidence=list(dict.fromkeys(evidence)),
        recommended_actions=list(dict.fromkeys(actions)),
        model_version=model_version,
    )
    return engine._s(result)


def scan_email(engine, raw):
    """Analyze raw RFC822 email bytes; never fetch external content."""
    if not isinstance(raw, bytes) or not raw:
        raise ValueError("Provide a non-empty email file.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Email file exceeds the 1 MB size limit.")

    message = BytesParser(policy=policy.default).parsebytes(raw)
    evidence = []
    body_parts = []

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))
    subject = str(message.get("Subject", ""))
    if not sender:
        evidence.append("Email has no From header.")
    if reply_to and sender and reply_to.lower() != sender.lower():
        evidence.append("Reply-To differs from From; verify the sender.")
    if message.defects:
        evidence.append("Email contains parsing or format defects.")

    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        if part.get_content_type() not in {"text/plain", "text/html"}:
            continue
        try:
            content = part.get_content()
            if isinstance(content, str):
                body_parts.append(content[:100_000])
        except (LookupError, UnicodeError, ValueError):
            evidence.append("A message body part could not be decoded.")

    body = "\n".join(body_parts)
    combined = f"Subject: {subject}\n{body}"
    urls = _urls(combined)

    # Reuse the configured scam and phishing detectors.
    text_result = engine.scan_message(combined)
    risk = float(text_result.get("risk_score", 0))
    evidence.extend(text_result.get("evidence", []))

    for url in urls[:10]:
        scanned = engine.scan_url(url)
        url_risk = float(scanned.get("risk_score", 0))
        risk = max(risk, url_risk)
        if url_risk >= 35:
            evidence.append(f"Suspicious link indicator: {url}")

    if urls:
        evidence.append(f"Extracted {len(urls)} unique URL(s); links were not opened.")
    if not evidence:
        evidence.append("No strong suspicious indicators were identified by configured checks.")

    return _result(
        engine, "email_security", evidence, risk,
        [
            "Do not open unexpected links or attachments.",
            "Verify the sender using a trusted contact method.",
            "Never disclose passwords, payment details, or OTPs.",
        ],
        confidence=text_result.get("confidence", 0.5),
    )


def scan_social(engine, text):
    """Analyze copied social posts, DMs, job offers, or marketplace messages."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Provide the social media post or message text.")
    if len(text) > 10_000:
        raise ValueError("Text exceeds the 10,000-character limit.")

    message_result = engine.scan_message(text)
    evidence = list(message_result.get("evidence", []))
    risk = float(message_result.get("risk_score", 0))

    urls = _urls(text)
    for url in urls[:10]:
        scanned = engine.scan_url(url)
        url_risk = float(scanned.get("risk_score", 0))
        risk = max(risk, url_risk)
        if url_risk >= 35:
            evidence.append(f"Suspicious link indicator: {url}")

    if not evidence:
        evidence.append("No strong suspicious indicators were identified by configured checks.")
    if urls:
        evidence.append(f"Extracted {len(urls)} unique URL(s); links were not opened.")

    return _result(
        engine, "social_media_scam", evidence, risk,
        [
            "Verify job offers, prizes, and payment requests independently.",
            "Do not send money or disclose OTPs, PINs, or passwords.",
            "Avoid opening suspicious links.",
        ],
        confidence=message_result.get("confidence", 0.5),
    )


def scan_qr(engine, image_bytes):
    """Decode a QR image locally, then scan extracted text or URL."""
    if not isinstance(image_bytes, bytes) or not image_bytes:
        raise ValueError("Provide a QR image.")
    if len(image_bytes) > MAX_QR_BYTES:
        raise ValueError("QR image exceeds the 10 MB size limit.")

    try:
        from PIL import Image
        from pyzbar.pyzbar import decode
    except ImportError as exc:
        raise RuntimeError(
            "QR scanning dependencies are missing. Install Pillow and "
            "pyzbar, plus the system zbar library."
        ) from exc

    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
            image.verify()
        with Image.open(io.BytesIO(image_bytes)) as image:
            image.load()
            if image.width * image.height > 20_000_000:
                raise ValueError("Image dimensions exceed the safety limit.")
            decoded = decode(image)
    except ValueError:
        raise
    except Exception as exc:
        raise ValueError("Could not decode the uploaded image.") from exc

    if not decoded:
        return _result(
            engine, "qr_scan", ["No QR code could be decoded from this image."],
            0, ["Try a clearer image with the entire QR code visible."], 0.0
        )

    contents = []
    for item in decoded[:10]:
        contents.append(item.data.decode("utf-8", errors="replace")[:4096])

    evidence = [f"Decoded {len(contents)} QR code(s)."]
    risk = 0.0

    for content in contents:
        if re.match(r"(?i)^https?://", content.strip()):
            result = engine.scan_url(content.strip())
            risk = max(risk, float(result.get("risk_score", 0)))
            evidence.append("QR contains a URL that was passed to the phishing detector.")
        elif re.match(r"(?i)^www\.", content.strip()):
            result = engine.scan_url(content.strip())
            risk = max(risk, float(result.get("risk_score", 0)))
            evidence.append("QR contains a web address that was passed to the phishing detector.")
        else:
            evidence.append("QR contains non-URL text; it was not opened or executed.")

    return _result(
        engine, "qr_scan", evidence, risk,
        [
            "Preview the decoded destination before visiting it.",
            "Do not enter credentials or payment details on an unverified page.",
        ],
        0.7 if risk else 0.5,
    )


def scan_apk(engine, apk_bytes):
    """Inspect APK archive structure and readable XML manifest only."""
    if not isinstance(apk_bytes, bytes) or not apk_bytes:
        raise ValueError("Provide an APK file.")
    if len(apk_bytes) > MAX_APK_BYTES:
        raise ValueError("APK exceeds the 50 MB size limit.")

    digest = hashlib.sha256(apk_bytes).hexdigest()
    evidence = [f"SHA-256: {digest}"]

    try:
        archive = zipfile.ZipFile(io.BytesIO(apk_bytes))
    except (zipfile.BadZipFile, OSError):
        return _result(
            engine, "apk_static_analysis",
            evidence + ["File is not a valid readable ZIP/APK archive."],
            0, ["Obtain the APK from a trusted source."], 0.0
        )

    with archive:
        entries = archive.infolist()
        if len(entries) > MAX_APK_ENTRIES:
            raise ValueError("APK contains too many archive entries.")

        total_uncompressed = sum(item.file_size for item in entries)
        if total_uncompressed > MAX_ARCHIVE_EXPANSION:
            raise ValueError("APK archive expansion exceeds the 200 MB safety limit.")

        names = {item.filename for item in entries}
        if "AndroidManifest.xml" not in names:
            evidence.append("AndroidManifest.xml is missing.")
        else:
            manifest_info = archive.getinfo("AndroidManifest.xml")
            if manifest_info.file_size > 2_000_000:
                raise ValueError("Manifest exceeds the 2 MB safety limit.")
            manifest = archive.read(manifest_info)

            try:
                root = ElementTree.fromstring(manifest)
                permissions = [
                    element.attrib.get(
                        "{http://schemas.android.com/apk/res/android}name", ""
                    )
                    for element in root.iter()
                    if element.tag.endswith("uses-permission")
                ]
                for permission in sorted(set(permissions) & SUSPICIOUS_PERMISSIONS):
                    evidence.append(f"Sensitive permission declared: {permission}")
            except ElementTree.ParseError:
                evidence.append(
                    "Manifest is binary or not plain XML; permissions could not be fully parsed."
                )

        if "classes.dex" in names or any(
            name.startswith("classes") and name.endswith(".dex") for name in names
        ):
            evidence.append("Dalvik bytecode file(s) found; code was not executed.")
        else:
            evidence.append("No standard DEX bytecode file was identified.")

        urls = []
        for item in entries:
            path = PurePosixPath(item.filename)
            if path.is_absolute() or ".." in path.parts:
                evidence.append("Archive contains a suspicious path entry.")
            if item.file_size > 5_000_000 or item.is_dir():
                continue
            if item.filename.endswith((".xml", ".json", ".txt", ".html", ".js")):
                try:
                    data = archive.read(item)
                    text = data.decode("utf-8", errors="ignore")
                    urls.extend(_urls(text))
                except (OSError, RuntimeError, zipfile.BadZipFile):
                    evidence.append("An archive entry could not be read.")

        urls = list(dict.fromkeys(urls))[:10]
        risk = min(60, sum(
            10 for item in evidence if item.startswith("Sensitive permission declared:")
        ))
        for url in urls:
            evidence.append(f"Embedded URL found: {url}")
            scanned = engine.scan_url(url)
            risk = max(risk, float(scanned.get("risk_score", 0)))

        evidence.append(
            "Static inspection only: signature validity and runtime behaviour were not verified."
        )

    model_version = "phase2-static-1.0"
    confidence = 0.5

    try:
        from cybershield.apk_ml import predict_apk

        prediction = predict_apk(apk_bytes)
        probability = prediction["malware_probability"]
        ml_risk = probability * 100.0

        risk = max(risk, ml_risk)
        confidence = max(probability, 1.0 - probability)
        model_version = "mh100k-sgd-1.0"

        verdict = "malware" if probability >= 0.5 else "benign"
        evidence.append(
            f"MH-100K ML screening prediction: {verdict} "
            f"(raw malware probability: {probability:.4f})."
        )
        evidence.append(
            f"ML feature coverage: {prediction['features_matched']} of "
            f"{prediction['features_total']} known features matched."
        )
    except Exception as exc:
        evidence.append(
            "MH-100K ML analysis unavailable; static findings only "
            f"({type(exc).__name__})."
        )

    return _result(
        engine, "apk_static_analysis", evidence, risk,
        [
            "Do not install an APK from an untrusted source.",
            "Verify the publisher and signing certificate using a trusted tool.",
            "Treat this static scan as a screening result, not proof that the APK is safe.",
        ],
        confidence,
        model_version=model_version,
    )
