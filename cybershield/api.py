from cybershield.learning.manager import LearningManager
from flask import Flask, jsonify, request, render_template

from cybershield.engine import CyberShieldEngine
from cybershield.security import safe_text, safe_url, obj


def create_app():
    app = Flask(
        __name__,
        template_folder="../templates",
        static_folder="../static",
    )
    e = CyberShieldEngine()
    learning = LearningManager()
    @app.get("/")
    def home():
        return render_template("index.html")

    @app.get("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "service": "CyberShield AI",
            "offline": True,
        })

    @app.get("/api/history")
    def history():
        return jsonify(e.history(request.args.get("limit", 50)))

    @app.post("/api/scan/url")
    def su():
        try:
            data = obj(request.get_json(silent=True))
            return jsonify(e.scan_url(safe_url(data.get("url"))))
        except Exception as x:
            return jsonify({"error": str(x)}), 400

    @app.post("/api/scan/message")
    def sm():
        try:
            data = obj(request.get_json(silent=True))
            return jsonify(e.scan_message(safe_text(data.get("text"))))
        except Exception as x:
            return jsonify({"error": str(x)}), 400

    @app.post("/api/scan/network")
    def sn():
        try:
            return jsonify(e.scan_network(
                obj(request.get_json(silent=True))
            ))
        except Exception as x:
            return jsonify({"error": str(x)}), 400

    @app.post("/api/scan/behavior")
    def sb():
        try:
            return jsonify(e.scan_behavior(
                obj(request.get_json(silent=True))
            ))
        except Exception as x:
            return jsonify({"error": str(x)}), 400

    @app.post("/api/advice")
    def advice_api():
        try:
            return jsonify(e.advice(
                obj(request.get_json(silent=True))
            ))
        except Exception as x:
            return jsonify({"error": str(x)}), 400
    
    @app.post("/api/feedback")
    def feedback():
        data = obj(request.get_json(silent=True))
        fid = learning.feedback(
            data.get("kind", "unknown"),
            data.get("input", {}),
            data.get("result", {}),
        )
        return jsonify({
            "feedback_id": fid,
            "status": "queued_for_verification",
        })

    @app.post("/api/feedback/<int:fid>/review")
    def review_feedback(fid):
        data = obj(request.get_json(silent=True))
        learning.confirm(fid, data.get("verdict", "rejected"))
        return jsonify({
            "status": "updated",
            "stats": learning.stats(),
        })

    @app.get("/api/learning/stats")
    def learning_stats():
        return jsonify(learning.stats())

    @app.post("/api/learning/export")
    def learning_export():
        return jsonify({
            "path": learning.export(),
            "status": "exported_verified_samples",
        })
    @app.get("/api/learning/pending")
    def learning_pending():
        try:
            items = learning.list_pending()
            return jsonify({
                "items": items,
                "count": len(items),
            })
        except Exception:
            app.logger.exception("Failed to retrieve pending feedback")
            return jsonify({
                "error": "Failed to retrieve pending feedback",
            }), 500

    return app
