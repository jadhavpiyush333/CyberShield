"""Feature extraction used by the reproducible Phase 1 baselines."""
import math, re
from collections import Counter
from urllib.parse import urlparse
import numpy as np
import pandas as pd

URL_SUSPICIOUS = {
    'login','verify','verification','secure','account','update','wallet','bank','password',
    'credential','bonus','free','claim','urgent','signin','confirm','reset','payment','invoice'
}

def _entropy(s: str) -> float:
    if not s: return 0.0
    c = Counter(s); n = len(s)
    return -sum((v/n) * math.log2(v/n) for v in c.values())

def url_features(series):
    rows=[]
    for raw in pd.Series(series).fillna('').astype(str):
        u = raw.strip(); p=urlparse(u if '://' in u else 'http://' + u); host=p.hostname or ''; low=u.lower()
        rows.append({
            'length':len(u),'host_length':len(host),'path_length':len(p.path),
            'dots':host.count('.'),'subdomains':max(0,host.count('.')),
            'digits':sum(ch.isdigit() for ch in u),'special':sum(not ch.isalnum() for ch in u),
            'hyphens':u.count('-'),'at':u.count('@'),'query_params':u.count('&') + (1 if '?' in u else 0),
            'https':int(p.scheme.lower()=='https'),'ip_host':int(bool(re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}',host))),
            'suspicious_words':sum(w in low for w in URL_SUSPICIOUS),'entropy':_entropy(host+p.path),
        })
    return pd.DataFrame(rows)

def text_features(series):
    s=pd.Series(series).fillna('').astype(str)
    return pd.DataFrame({
        'length':s.str.len(), 'words':s.str.split().str.len(), 'digits':s.str.count(r'\d'),
        'urls':s.str.count(r'https?://|www\.'), 'money':s.str.count(r'[₹$€£]'),
        'upper':s.apply(lambda x:sum(c.isupper() for c in x)),
        'exclamations':s.str.count('!'), 'questions':s.str.count(r'\?'),
        'otp':s.str.lower().str.count(r'\botp\b'),
        'urgency':s.str.lower().str.count(r'urgent|immediately|act now|last warning|suspended'),
    })

def network_features(df):
    """Normalize common UNSW-NB15/CICIDS-style numeric flow columns."""
    d=df.copy(); d.columns=[str(c).strip() for c in d.columns]
    numeric=d.select_dtypes(include=[np.number]).copy()
    if numeric.empty:
        raise ValueError('Network dataset needs numeric flow features.')
    numeric=numeric.replace([np.inf,-np.inf],np.nan).fillna(0)
    return numeric

def labels(series):
    s=pd.Series(series).astype(str).str.strip().str.lower()
    benign={'0','ham','benign','normal','safe','legitimate','non-malicious','non malicious'}
    return s.map(lambda x:0 if x in benign else 1).astype(int)
