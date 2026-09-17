"""
CyberSentinel Pro - ML Model Trainer
Trains and saves models for: SMS spam, Email body spam, URL phishing

Datasets are loaded from CSV files in: backend/data/
  - sms_dataset.csv
  - email_dataset.csv
  - url_dataset.csv

Run this once: python models/train_models.py
"""
import os
import joblib
import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.svm import LinearSVC
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

MODELS_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(os.path.dirname(MODELS_DIR), 'data')


def load_csv(filename: str) -> pd.DataFrame:
    path = os.path.join(DATA_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"Dataset not found: {path}")
    return pd.read_csv(path, encoding='utf-8')


# ─────────────────────────────────────────────
# URL FEATURE EXTRACTION
# ─────────────────────────────────────────────
def extract_url_features(url: str) -> list:
    """Extract numerical features from URL for ML classification."""
    import re
    import tldextract
    from urllib.parse import urlparse

    features = []
    parsed = urlparse(url if url.startswith('http') else 'http://' + url)
    ext = tldextract.extract(url)

    features.append(len(url))                                          # 1: length
    features.append(url.count('.'))                                    # 2: dot count
    features.append(1 if parsed.scheme == 'https' else 0)             # 3: HTTPS
    ip_pat = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    features.append(1 if ip_pat.search(url) else 0)                   # 4: IP address
    special = sum(url.count(c) for c in ['@', '!', '#', '$', '%', '^', '&', '*'])
    features.append(special)                                           # 5: special chars
    sub_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
    features.append(sub_count)                                         # 6: subdomain count
    features.append(1 if '@' in url else 0)                           # 7: @ symbol
    features.append(1 if '//' in parsed.path else 0)                  # 8: double slash
    phish_words = ['login', 'signin', 'account', 'secure', 'verify', 'update',
                   'confirm', 'bank', 'paypal', 'ebay', 'amazon', 'apple',
                   'microsoft', 'google', 'facebook', 'urgent', 'suspended']
    features.append(sum(1 for w in phish_words if w in url.lower()))  # 9: phish keywords
    features.append(len(ext.domain))                                   # 10: domain length
    features.append(len(parsed.path))                                  # 11: path length
    features.append(ext.domain.count('-') if ext.domain else 0)       # 12: dashes
    features.append(1 if ext.domain and any(c.isdigit() for c in ext.domain) else 0)  # 13: digits
    features.append(len(parsed.query))                                 # 14: query length
    sus_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.link',
                '.online', '.site', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf']
    features.append(1 if any(url.lower().endswith(t) for t in sus_tlds) else 0)  # 15: sus TLD

    return features


# ─────────────────────────────────────────────
# TRAINING FUNCTIONS
# ─────────────────────────────────────────────
def train_sms_model():
    print("Training SMS spam detector...")
    df = load_csv('sms_dataset.csv')
    texts, labels = df['text'].tolist(), df['label'].tolist()

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=10000,
                                  sublinear_tf=True, stop_words='english')),
        ('clf', MultinomialNB(alpha=0.1))
    ])
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42)
    pipeline.fit(X_train, y_train)
    acc = accuracy_score(y_test, pipeline.predict(X_test))
    print(f"  SMS Model Accuracy: {acc:.2%}  ({len(df)} samples)")

    path = os.path.join(MODELS_DIR, 'sms_model.pkl')
    joblib.dump(pipeline, path)
    print(f"  Saved -> {path}")
    return pipeline


def train_email_body_model():
    print("Training email body spam detector...")
    df = load_csv('email_dataset.csv')
    texts, labels = df['text'].tolist(), df['label'].tolist()

    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(ngram_range=(1, 2), max_features=15000,
                                  sublinear_tf=True, stop_words='english')),
        ('clf', LinearSVC(C=1.0, max_iter=2000))
    ])
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.2, random_state=42)
    pipeline.fit(X_train, y_train)
    acc = accuracy_score(y_test, pipeline.predict(X_test))
    print(f"  Email Model Accuracy: {acc:.2%}  ({len(df)} samples)")

    path = os.path.join(MODELS_DIR, 'email_body_model.pkl')
    joblib.dump(pipeline, path)
    print(f"  Saved -> {path}")
    return pipeline


def train_url_model():
    print("Training URL phishing detector...")
    df = load_csv('url_dataset.csv')

    features, labels = [], []
    for _, row in df.iterrows():
        try:
            features.append(extract_url_features(row['url']))
            labels.append(row['label'])
        except Exception as e:
            print(f"  Skipping URL {row['url']}: {e}")

    X = np.array(features)
    y = np.array(labels)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42)

    clf = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, random_state=42)
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    print(f"  URL Model Accuracy: {acc:.2%}  ({len(df)} samples)")

    path = os.path.join(MODELS_DIR, 'url_model.pkl')
    joblib.dump(clf, path)
    print(f"  Saved -> {path}")
    return clf


if __name__ == '__main__':
    print("=" * 55)
    print("CyberSentinel Pro - Training ML Models")
    print(f"Data directory : {DATA_DIR}")
    print("=" * 55)

    try:
        import tldextract
    except ImportError:
        print("Installing tldextract...")
        import subprocess
        subprocess.check_call(['pip', 'install', 'tldextract'])

    train_sms_model()
    train_email_body_model()
    train_url_model()

    print("\n" + "=" * 55)
    print("All models trained and saved successfully!")
    print("=" * 55)
