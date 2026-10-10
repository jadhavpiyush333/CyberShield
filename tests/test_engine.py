from cybershield.engine import CyberShieldEngine
def test_engine():
 e=CyberShieldEngine(); r=e.scan_url('http://192.168.1.5/verify'); assert r['threat_type']=='phishing_url'
