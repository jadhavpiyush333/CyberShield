from cybershield.detectors.scam import detect as s
from cybershield.detectors.network import detect as n
from cybershield.detectors.malware import detect as m
def test_scam(): assert s('URGENT verify OTP payment now').risk_score>0
def test_network(): assert n({'event_type':'ddos'}).risk_score>=80
def test_malware(): assert m({'x':'powershell encoded_command persistence'}).risk_score>0
