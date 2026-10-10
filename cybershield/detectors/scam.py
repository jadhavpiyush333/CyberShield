import re
from cybershield.schemas import DetectionResult
URG={'urgent','immediately','act now','account blocked','account suspended','verify now','last warning'}
SCAM={'prize','winner','lottery','refund','cashback','investment','guaranteed','loan','kyc','otp','verification code','gift'}
def detect(text):
 t=text.lower(); score=0; ev=[]
 u=sum(x in t for x in URG); s=sum(x in t for x in SCAM); links=len(re.findall(r'https?://|www\.',t)); money=len(re.findall(r'(?:₹|rs\.?|inr|\$)\s?\d+',t))
 if u: score+=min(25,u*8); ev.append('Urgency/pressure language')
 if s: score+=min(25,s*5); ev.append('Scam/financial language')
 if 'otp' in t or 'one time password' in t: score+=20; ev.append('OTP request')
 if links: score+=15; ev.append('Link present')
 if money: score+=10; ev.append('Money amount detected')
 score=min(100,score); sev='critical' if score>=80 else 'high' if score>=60 else 'medium' if score>=35 else 'low'
 return DetectionResult('scam_message',sev,score,min(.99,.5+score/200),ev,['Do not share OTP/PIN/password.','Do not send money.','Verify through an official channel.'] if score>=35 else ['Treat unexpected requests cautiously.'])
