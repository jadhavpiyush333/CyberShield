import sqlite3,json
from datetime import datetime,timezone
from config import DB_PATH
class Storage:
 def __init__(self,path=DB_PATH): self.path=str(path); self.init_db()
 def connect(self): c=sqlite3.connect(self.path); c.row_factory=sqlite3.Row; return c
 def init_db(self):
  with self.connect() as c: c.execute('CREATE TABLE IF NOT EXISTS detections(id INTEGER PRIMARY KEY,created_at TEXT,threat_type TEXT,severity TEXT,risk_score REAL,confidence REAL,evidence TEXT,actions TEXT,model_version TEXT)')
 def save(self,r):
  with self.connect() as c: c.execute('INSERT INTO detections(created_at,threat_type,severity,risk_score,confidence,evidence,actions,model_version) VALUES(?,?,?,?,?,?,?,?)',(datetime.now(timezone.utc).isoformat(),r['threat_type'],r['severity'],r['risk_score'],r['confidence'],json.dumps(r['evidence']),json.dumps(r['recommended_actions']),r['model_version']))
 def recent(self,n=50):
  with self.connect() as c: return [dict(x) for x in c.execute('SELECT * FROM detections ORDER BY id DESC LIMIT ?',(max(1,min(int(n),200)),)).fetchall()]
