from pathlib import Path
import json, joblib, pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, precision_score, recall_score, f1_score
from .features import text_features, url_features, network_features, labels

def _metrics(y,p):
    cm=confusion_matrix(y,p,labels=[0,1]); tn,fp,fn,tp=cm.ravel()
    return {'accuracy':accuracy_score(y,p),'precision':precision_score(y,p,zero_division=0),'recall':recall_score(y,p,zero_division=0),'f1':f1_score(y,p,zero_division=0),'false_positive_rate':fp/max(1,fp+tn),'false_negative_rate':fn/max(1,fn+tp),'confusion_matrix':cm.tolist(),'classification_report':classification_report(y,p,output_dict=True,zero_division=0),'samples':len(y)}

def evaluate(model,csv,kind,label_col,text_col=None,url_col=None,out='reports/model_metrics.json'):
    m=joblib.load(model); d=pd.read_csv(csv); y=labels(d[label_col])
    if kind=='sms': X=d[text_col].fillna('').astype(str)
    elif kind=='phishing': X=url_features(d[url_col])
    elif kind=='network': X=network_features(d.drop(columns=[label_col]))
    else: raise ValueError(kind)
    r=_metrics(y,m.predict(X)); Path(out).parent.mkdir(parents=True,exist_ok=True); Path(out).write_text(json.dumps(r,indent=2)); return r
