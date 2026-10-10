import re,math
from collections import Counter
from urllib.parse import urlparse
from cybershield.schemas import DetectionResult
WORDS={'login','verify','verification','secure','account','update','wallet','bank','password','credential','bonus','free','claim','urgent','signin','confirm'}
def entropy(s):
 c=Counter(s); n=max(1,len(s)); return -sum((v/n)*math.log2(v/n) for v in c.values())
def detect(url):
 p=urlparse(url); h=p.hostname or ''; t=url.lower(); score=0; ev=[]
 checks=[(p.scheme!='https',15,'URL is not HTTPS'),(bool(re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}',h)),25,'Host is an IP address'),('@' in url,30,'URL contains @ delimiter'),(h.count('.')>=3,15,'Multiple subdomains'),(sum(w in t for w in WORDS)>0,15,'Suspicious account/security wording'),(len(url)>120,10,'Unusually long URL'),(entropy(h+p.path)>4,10,'High URL entropy')]
 for hit,w,msg in checks:
  if hit: score+=w; ev.append(msg)
 score=min(100,score); sev='critical' if score>=80 else 'high' if score>=60 else 'medium' if score>=35 else 'low'
 return DetectionResult('phishing_url',sev,score,min(.99,.5+score/200),ev,['Do not enter credentials.','Open the official site manually.','Block/report the URL.'] if score>=35 else ['Verify the domain before sensitive actions.'])
