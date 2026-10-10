from .feedback import LearningStore


class LearningManager:
    def __init__(self):
        self.store = LearningStore()

    def feedback(self, kind, payload, result):
        return self.store.add(
            kind,
            payload,
            result.get("threat_type", "unknown"),
            result.get("confidence", 0.0),
        )

    def confirm(self, fid, verdict):
        return self.store.review(int(fid), verdict)

    def list_pending(self, limit=100):
        return self.store.list_pending(limit)

    def stats(self):
        return self.store.stats()

    def export(self):
        return self.store.export_verified()
