from cybershield.api import create_app
def test_health(): assert create_app().test_client().get('/api/health').status_code==200
def test_url(): assert create_app().test_client().post('/api/scan/url',json={'url':'http://192.168.1.5/verify'}).status_code==200
