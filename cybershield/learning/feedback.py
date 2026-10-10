import csv, json, sqlite3
from pathlib import Path

class LearningStore:
    def __init__(self, db_path='data/cybershield.db'):
        self.db_path=Path(db_path); self.db_path.parent.mkdir(parents=True,exist_ok=True); self._init()
    def _db(self): return sqlite3.connect(self.db_path)
    def _init(self):
        with self._db() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS feedback (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, payload TEXT, prediction TEXT, confidence REAL, verdict TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
            c.execute('''CREATE TABLE IF NOT EXISTS learning_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, feedback_id INTEGER, status TEXT DEFAULT 'pending', reviewed_at DATETIME)''')
    def add(self, kind,payload,prediction,confidence,verdict='unreviewed'):
        with self._db() as c:
            cur=c.execute('INSERT INTO feedback(kind,payload,prediction,confidence,verdict) VALUES(?,?,?,?,?)',(kind,json.dumps(payload),prediction,float(confidence),verdict))
            fid=cur.lastrowid; c.execute('INSERT INTO learning_queue(feedback_id) VALUES(?)',(fid,)); return fid
    def review(self, feedback_id, verdict):
        if verdict not in ('confirmed','false_positive','rejected'): raise ValueError('invalid verdict')
        with self._db() as c:
            c.execute('UPDATE feedback SET verdict=? WHERE id=?',(verdict,feedback_id)); c.execute('UPDATE learning_queue SET status=? , reviewed_at=CURRENT_TIMESTAMP WHERE feedback_id=?',(verdict,feedback_id))
    def stats(self):
        with self._db() as c:
            rows=c.execute('SELECT verdict,COUNT(*) FROM feedback GROUP BY verdict').fetchall(); pending=c.execute("SELECT COUNT(*) FROM learning_queue WHERE status='pending'").fetchone()[0]
        d={k:v for k,v in rows}; d['pending']=pending; return d
    def list_pending(self, limit=100):
        with self._db() as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("""
                SELECT f.id, f.kind, f.payload, f.prediction,
                       f.confidence, f.created_at
                FROM feedback f
                JOIN learning_queue q ON q.feedback_id = f.id
                WHERE q.status = 'pending'
                ORDER BY f.id DESC
                LIMIT ?
            """, (max(1, min(int(limit), 500)),)).fetchall()

        items = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item["payload"])
            items.append(item)

        return items

    def export_verified(self, out='data/verified/verified_feedback.jsonl'):
        Path(out).parent.mkdir(parents=True,exist_ok=True)
        with self._db() as c, open(out,'w',encoding='utf8') as f:
            for r in c.execute("SELECT kind,payload,prediction,confidence,verdict,created_at FROM feedback WHERE verdict IN ('confirmed','false_positive')"):
                f.write(json.dumps({'kind':r[0],'payload':json.loads(r[1]),'prediction':r[2],'confidence':r[3],'verdict':r[4],'created_at':r[5]})+'\n')
        return out
