from urllib.parse import urlparse
MAX_TEXT=10000

def safe_text(v): return str(v or '')[:MAX_TEXT]
def safe_url(v):
    x=safe_text(v).strip(); p=urlparse(x)
    if p.scheme not in {'http','https'} or not p.netloc: raise ValueError('Valid http/https URL required')
    return x
def obj(v):
    if not isinstance(v,dict): raise ValueError('JSON object expected')
    return v
