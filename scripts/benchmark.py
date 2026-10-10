import time
from cybershield.engine import CyberShieldEngine
e=CyberShieldEngine(); cases=[('url',lambda:e.scan_url('http://192.168.1.5/verify/login')),('message',lambda:e.scan_message('URGENT verify OTP payment now')),('network',lambda:e.scan_network({'event_type':'port_scan'})),('behavior',lambda:e.scan_behavior({'process':'powershell encoded_command'}))]
for n,f in cases:
 t=time.perf_counter()
 for _ in range(100): f()
 print(n, round((time.perf_counter()-t)*10,3),'ms/request')
