from pathlib import Path
import joblib, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import classification_report
from .features import text_features, url_features, network_features, labels

def _save(model,out):
    Path(out).parent.mkdir(parents=True,exist_ok=True); joblib.dump(model,out); return out

def train_text_csv(path,text_col,label_col,out):
    d=pd.read_csv(path); X=d[text_col].fillna('').astype(str); y=labels(d[label_col])
    a,b=train_test_split(range(len(d)),test_size=.2,random_state=42,stratify=y)
    model=Pipeline([('tfidf',TfidfVectorizer(ngram_range=(1,2),min_df=1,max_features=50000,sublinear_tf=True)),('clf',LogisticRegression(max_iter=1500,class_weight='balanced'))])
    model.fit(X.iloc[a],y.iloc[a]); print(classification_report(y.iloc[b],model.predict(X.iloc[b]),zero_division=0)); return _save(model,out)

def train_url_csv(path,url_col,label_col,out):
    d=pd.read_csv(path); X=url_features(d[url_col]); y=labels(d[label_col])
    a,b=train_test_split(range(len(d)),test_size=.2,random_state=42,stratify=y)
    model=Pipeline([('scale',StandardScaler()),('clf',LogisticRegression(max_iter=1500,class_weight='balanced'))])
    model.fit(X.iloc[a],y.iloc[a]); print(classification_report(y.iloc[b],model.predict(X.iloc[b]),zero_division=0)); return _save(model,out)

def train_network_csv(path,label_col,out):
    d=pd.read_csv(path); X=network_features(d.drop(columns=[label_col])); y=labels(d[label_col])
    a,b=train_test_split(range(len(d)),test_size=.2,random_state=42,stratify=y)
    model=Pipeline([('scale',StandardScaler()),('clf',LogisticRegression(max_iter=2000,class_weight='balanced'))])
    model.fit(X.iloc[a],y.iloc[a]); print(classification_report(y.iloc[b],model.predict(X.iloc[b]),zero_division=0));
    model.feature_names_in_ = X.columns.to_numpy() if hasattr(model,'feature_names_in_') else None
    return _save(model,out)
