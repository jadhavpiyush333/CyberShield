#!/usr/bin/env python3
import argparse,json
from cybershield.ml.evaluate import evaluate
p=argparse.ArgumentParser(description='Evaluate CyberShield model')
p.add_argument('kind',choices=['sms','phishing','network']); p.add_argument('--model',required=True); p.add_argument('--csv',required=True); p.add_argument('--label-column',default='label'); p.add_argument('--text-column',default='text'); p.add_argument('--url-column',default='url'); p.add_argument('--output',default='reports/model_metrics.json')
a=p.parse_args(); r=evaluate(a.model,a.csv,a.kind,a.label_column,a.text_column,a.url_column,a.output); print(json.dumps({k:r[k] for k in ('accuracy','precision','recall','f1','false_positive_rate','false_negative_rate','samples')},indent=2))
