from flask import Flask, jsonify, render_template, request

from cybershield.engine import CyberShieldEngine
from cybershield.security import safe_text
from cybershield.phase2 import (
    scan_email,
    scan_social,
    scan_qr,
    scan_apk,
)


def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )

    engine = CyberShieldEngine()

    # General
    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify({
            "service": "CyberShield AI",
            "status": "ok",
            "offline": True,
        })

    @app.get("/api/history")
    def history():
        return jsonify(engine.history())

    # Learning and feedback
    @app.get("/api/learning/stats")
    def learning_stats():
        return jsonify(engine.learning_stats())

    @app.get("/api/learning/pending")
    def learning_pending():
        return jsonify(engine.learning_pending())

    @app.post("/api/advice")
    def advice():
        data = request.get_json(silent=True) or {}
        question = safe_text(
            data.get("question") or data.get("text") or ""
        )
        return jsonify(engine.advice(question))

    @app.post("/api/feedback")
    def feedback():
        data = request.get_json(silent=True) or {}
        return jsonify(engine.submit_feedback(data))

    @app.post("/api/feedback/<int:fid>/review")
    def review_feedback(fid):
        data = request.get_json(silent=True) or {}
        verdict = data.get("verdict", "")
        return jsonify(engine.review_feedback(fid, verdict))

    @app.post("/api/learning/export")
    def learning_export():
        return jsonify(engine.export_learning_data())

    # Existing scanners
    @app.post("/api/scan/behavior")
    def scan_behavior_route():
        data = request.get_json(silent=True) or {}
        return jsonify(engine.scan_behavior(data))

    @app.post("/api/scan/message")
    def scan_message_route():
        data = request.get_json(silent=True) or {}
        message = safe_text(
            data.get("text") or data.get("message") or ""
        )

        if not message.strip():
            return jsonify({
                "error": (
                    "Missing message text. "
                    "Provide 'text' or 'message'."
                )
            }), 400

        return jsonify(engine.scan_message(message))

    @app.post("/api/scan/network")
    def scan_network_route():
        data = request.get_json(silent=True) or {}
        return jsonify(engine.scan_network(data))

    @app.post("/api/scan/url")
    def scan_url_route():
        data = request.get_json(silent=True) or {}
        url = safe_text(data.get("url") or "")

        if not url.strip():
            return jsonify({"error": "Missing URL"}), 400

        return jsonify(engine.scan_url(url))

    # Phase 2: Email phishing analysis
    @app.post("/api/scan/email")
    def scan_email_route():
        uploaded = request.files.get("file")

        if uploaded is None:
            return jsonify({
                "error": "Upload an .eml email file."
            }), 400

        if not (uploaded.filename or "").lower().endswith(".eml"):
            return jsonify({
                "error": "Only .eml files are accepted."
            }), 400

        try:
            raw = uploaded.stream.read(1_000_001)

            if len(raw) > 1_000_000:
                return jsonify({
                    "error": "Email file exceeds the 1 MB limit."
                }), 413

            return jsonify(scan_email(engine, raw))

        except (ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400

    # Phase 2: Social media posts and direct messages
    @app.post("/api/scan/social")
    def scan_social_route():
        data = request.get_json(silent=True) or {}
        text = safe_text(
            data.get("text") or data.get("message") or ""
        )

        if not text.strip():
            return jsonify({
                "error": "Provide a social media post or message."
            }), 400

        try:
            return jsonify(scan_social(engine, text))
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    # Phase 2: QR-code image scanning
    @app.post("/api/scan/qr")
    def scan_qr_route():
        uploaded = request.files.get("file")

        if uploaded is None:
            return jsonify({
                "error": "Upload a QR-code image."
            }), 400

        allowed = (".png", ".jpg", ".jpeg", ".webp", ".bmp")
        filename = (uploaded.filename or "").lower()

        if not filename.endswith(allowed):
            return jsonify({
                "error": "Unsupported image extension."
            }), 400

        try:
            raw = uploaded.stream.read(10_485_761)

            if len(raw) > 10_485_760:
                return jsonify({
                    "error": "Image exceeds the 10 MB limit."
                }), 413

            return jsonify(scan_qr(engine, raw))

        except RuntimeError as exc:
            return jsonify({"error": str(exc)}), 503
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

    # Phase 2: Static APK analysis; never installs or executes the APK
    @app.post("/api/scan/apk")
    def scan_apk_route():
        uploaded = request.files.get("file")

        if uploaded is None:
            return jsonify({
                "error": "Upload an APK file."
            }), 400

        if not (uploaded.filename or "").lower().endswith(".apk"):
            return jsonify({
                "error": "Only .apk files are accepted."
            }), 400

        try:
            raw = uploaded.stream.read(52_428_801)

            if len(raw) > 52_428_800:
                return jsonify({
                    "error": "APK exceeds the 50 MB limit."
                }), 413

            return jsonify(scan_apk(engine, raw))

        except (ValueError, RuntimeError) as exc:
            return jsonify({"error": str(exc)}), 400

    return app
