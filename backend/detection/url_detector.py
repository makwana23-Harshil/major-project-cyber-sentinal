"""URL Phishing Detector — ML + Deep Inspection + LLM Analysis"""
import re
import os
import joblib
import numpy as np
import tldextract
from urllib.parse import urlparse
from detection.link_inspector import inspect_link

MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'url_model.pkl')
_model = None

def _get_model():
    global _model
    if _model is None:
        if os.path.exists(MODEL_PATH):
            _model = joblib.load(MODEL_PATH)
        else:
            raise FileNotFoundError("URL model not found. Run: python models/train_models.py")
    return _model

def extract_url_features(url: str) -> list:
    """15 numerical features from URL"""
    features = []
    if not url.startswith('http'):
        url = 'http://' + url
    parsed = urlparse(url)
    ext = tldextract.extract(url)

    features.append(len(url))
    features.append(url.count('.'))
    features.append(1 if parsed.scheme == 'https' else 0)
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    features.append(1 if ip_pattern.search(url) else 0)
    special_chars = sum(url.count(c) for c in ['@', '!', '#', '$', '%', '^', '&', '*'])
    features.append(special_chars)
    subdomain_count = len(ext.subdomain.split('.')) if ext.subdomain else 0
    features.append(subdomain_count)
    features.append(1 if '@' in url else 0)
    features.append(1 if '//' in parsed.path else 0)
    phish_words = ['login', 'signin', 'account', 'secure', 'verify', 'update',
                   'confirm', 'bank', 'paypal', 'ebay', 'amazon', 'apple',
                   'microsoft', 'google', 'facebook', 'urgent', 'suspended']
    features.append(sum(1 for w in phish_words if w in url.lower()))
    features.append(len(ext.domain) if ext.domain else 0)
    features.append(len(parsed.path))
    features.append(ext.domain.count('-') if ext.domain else 0)
    has_num = 1 if ext.domain and any(c.isdigit() for c in ext.domain) else 0
    features.append(has_num)
    features.append(len(parsed.query))
    sus_tlds = ['.xyz', '.top', '.club', '.work', '.click', '.link', '.online',
                '.site', '.ru', '.cn', '.tk', '.ml', '.ga', '.cf']
    features.append(1 if any(url.lower().endswith(t) for t in sus_tlds) else 0)
    return features

def analyze_url(url: str, do_inspect: bool = True) -> dict:
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url_for_model = 'http://' + url
    else:
        url_for_model = url

    # ML prediction on lexical features
    model = _get_model()
    features = np.array(extract_url_features(url_for_model)).reshape(1, -1)
    ml_prediction = model.predict(features)[0]  # 1=legitimate, 0=phishing
    try:
        ml_proba = model.predict_proba(features)[0]
        phish_prob = float(ml_proba[0])
        legit_prob = float(ml_proba[1])
    except Exception:
        phish_prob = 0.85 if ml_prediction == 0 else 0.15
        legit_prob = 1 - phish_prob

    ml_risk = int(phish_prob * 60)

    # Deep link inspection (DNS, HTTP status, Typosquatting, Content, SSL, LLM)
    inspection = {}
    if do_inspect:
        inspection = inspect_link(url_for_model)

    inspection_risk = inspection.get('risk_score', 0) if inspection else 0
    inspection_verdict = inspection.get('verdict', 'UNKNOWN') if inspection else 'UNKNOWN'

    # Determine final composite verdict
    # Real-world verification must take priority over purely lexical ML
    if inspection_verdict in ('FAKE', 'NON-EXISTENT'):
        verdict = inspection_verdict
        composite_risk = max(75, inspection_risk)
        phish_prob = 0.90
        legit_prob = 0.10
    elif inspection_verdict == 'PHISHING':
        verdict = 'PHISHING'
        composite_risk = max(85, inspection_risk)
        phish_prob = 0.95
        legit_prob = 0.05
    elif inspection_verdict == 'DANGEROUS':
        verdict = 'DANGEROUS'
        composite_risk = max(75, inspection_risk)
        phish_prob = 0.90
        legit_prob = 0.10
    elif inspection_verdict == 'SAFE':
        # If the site exists, has valid SSL and clean content
        verdict = 'SAFE'
        composite_risk = min(inspection_risk, 15)
        legit_prob = 0.98
        phish_prob = 0.02
    else:
        composite_risk = min(int(ml_risk * 0.4 + inspection_risk * 0.6), 100)
        if composite_risk >= 65:
            verdict = 'PHISHING'
        elif composite_risk >= 35:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'SAFE'

    # Synchronize ML prediction label with unified verdict to eliminate contradictions
    if verdict in ('FAKE', 'NON-EXISTENT'):
        ml_pred_label = verdict
        phish_prob = max(phish_prob, 0.95)
        legit_prob = 1.0 - phish_prob
    elif verdict in ('PHISHING', 'DANGEROUS'):
        ml_pred_label = 'PHISHING'
        phish_prob = max(phish_prob, 0.95)
        legit_prob = 1.0 - phish_prob
    elif verdict == 'SAFE':
        ml_pred_label = 'SAFE'
        legit_prob = max(legit_prob, 0.98)
        phish_prob = 1.0 - legit_prob
    else:
        ml_pred_label = 'SUSPICIOUS'

    feature_notes = _build_url_notes(url_for_model, features[0])

    return {
        'verdict': verdict,
        'confidence': round(phish_prob if verdict in ('PHISHING', 'FAKE', 'DANGEROUS', 'NON-EXISTENT') else legit_prob, 4),
        'risk_score': composite_risk,
        'ml_prediction': ml_pred_label,
        'phishing_probability': round(phish_prob, 4),
        'legitimate_probability': round(legit_prob, 4),
        'url_features': feature_notes,
        'deep_inspection': inspection if inspection else None
    }

def _build_url_notes(url: str, features: np.ndarray) -> list:
    notes = []
    if features[2] == 0:
        notes.append('⚠️ No HTTPS protocol')
    if features[3] == 1:
        notes.append('🔴 URL contains raw IP address')
    if features[6] == 1:
        notes.append('🔴 @ symbol in URL — potential misdirection')
    if features[8] > 2:
        notes.append(f'⚠️ {int(features[8])} phishing-related keywords in URL')
    if features[1] > 5:
        notes.append(f'⚠️ Many dots ({int(features[1])}) in URL — possible subdomain abuse')
    if features[14] == 1:
        notes.append('⚠️ Suspicious top-level domain (TLD)')
    if features[11] > 0:
        notes.append(f'ℹ️ {int(features[11])} dashes in domain name')
    if not notes:
        notes.append('✅ Lexical URL structure is standard')
    return notes
