#!/usr/bin/env python3
import argparse
from cybershield.ml.train import train_text_csv, train_url_csv, train_network_csv
p=argparse.ArgumentParser(description='Train CyberShield Phase 1 baseline models')
p.add_argument('kind',choices=['sms','phishing','network'])
p.add_argument('--csv',required=True); p.add_argument('--label-column',default='label'); p.add_argument('--text-column',default='text'); p.add_argument('--url-column',default='url'); p.add_argument('--output')
a=p.parse_args(); out=a.output or {'sms':'models/scam_text.joblib','phishing':'models/phishing_url.joblib','network':'models/network.joblib'}[a.kind]
if a.kind=='sms': train_text_csv(a.csv,a.text_column,a.label_column,out)
elif a.kind=='phishing': train_url_csv(a.csv,a.url_column,a.label_column,out)
else: train_network_csv(a.csv,a.label_column,out)
print('Saved:',out)
