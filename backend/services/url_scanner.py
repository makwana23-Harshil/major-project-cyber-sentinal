"""
Cyber Sentinel - URL Deep Scanner Service
Extracts 30+ features, runs Random Forest ML inference, evaluates structural & domain heuristics,
and generates Explainable AI feature diagnostics.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, List
from backend.config import URL_MODEL_PATH, FEATURE_NAMES_PATH
from ml.feature_extraction.url_features import extract_url_features, FEATURE_COLUMN_NAMES
from backend.services.rule_engine import calculate_cyber_risk_score

# Cache trained model
_URL_MODEL = None
_FEATURE_NAMES = None


def get_url_model():
    global _URL_MODEL, _FEATURE_NAMES
    if _URL_MODEL is None and os.path.exists(URL_MODEL_PATH):
        _URL_MODEL = joblib.load(URL_MODEL_PATH)
    if _FEATURE_NAMES is None and os.path.exists(FEATURE_NAMES_PATH):
        _FEATURE_NAMES = joblib.load(FEATURE_NAMES_PATH)
    return _URL_MODEL, _FEATURE_NAMES


def scan_url(url: str, deep_analysis: bool = True) -> Dict[str, Any]:
    """
    Perform deep security scan and threat detection on a given URL.
    """
    url_clean = url.strip()
    extracted = extract_url_features(url_clean)
    features = extracted['features']
    metadata = extracted['metadata']
    
    # Feature vector for ML
    feature_vector = np.array([features[col] for col in FEATURE_COLUMN_NAMES], dtype=np.float32).reshape(1, -1)
    
    # Model inference
    model, _ = get_url_model()
    if model is not None:
        probs = model.predict_proba(feature_vector)[0]
        real_prob = float(round(probs[0] * 100, 1))
        phish_prob = float(round(probs[1] * 100, 1))
    else:
        # Fallback heuristic calculation if model not yet loaded
        phish_prob = 85.0 if (features['has_ip'] or features['brand_impersonation']) else 15.0
        real_prob = 100.0 - phish_prob

    # Structural Anomaly & Heuristic Indicators
    anomaly_score = 0.0
    indicators: List[str] = []
    reasons: List[str] = []
    has_critical = False

    if features['has_ip'] == 1:
        anomaly_score += 35.0
        has_critical = True
        indicators.append(f"Direct IP Address in Hostname: Host '{metadata['hostname']}' uses numeric IP instead of standard DNS domain.")
        reasons.append("Uses an IP address instead of a normal domain (often used in phishing kits and direct server attacks).")

    if features['brand_impersonation'] == 1:
        anomaly_score += 30.0
        has_critical = True
        brands_str = ", ".join(metadata['impersonated_brands'])
        indicators.append(f"Brand Impersonation: Targets brand '{brands_str}' while registered domain is '{metadata['domain']}.{metadata['tld']}'.")
        reasons.append(f"Deceptive brand targeting ({brands_str}) detected on an unauthorized domain.")

    if features['is_suspicious_tld'] == 1:
        anomaly_score += 20.0
        indicators.append(f"High-Risk TLD: Uses '.{metadata['tld']}' (frequently associated with spam and malicious disposable hosting).")
        reasons.append(f"Uses a high-risk suspicious top-level domain (.{metadata['tld']}).")

    if features['is_shortened'] == 1:
        anomaly_score += 15.0
        indicators.append(f"URL Shortener Detected: Host '{metadata['hostname']}' hides actual landing destination.")
        reasons.append("Uses a URL shortening service which obscures the final destination.")

    if features['keyword_count'] > 0:
        anomaly_score += min(30.0, features['keyword_count'] * 10.0)
        kw_str = ", ".join(f"'{k}'" for k in metadata['found_keywords'][:4])
        indicators.append(f"Phishing Keywords in URL: Found security/credential keywords: {kw_str}.")
        reasons.append(f"Contains suspicious authentication & account keywords: {kw_str}.")

    if features['subdomain_count'] >= 3:
        anomaly_score += 15.0
        indicators.append(f"Excessive Subdomains: Found {features['subdomain_count']} subdomain levels creating deceptive visual hierarchy.")
        reasons.append(f"Excessive subdomains ({features['subdomain_count']} levels) used to disguise true host.")

    if features['num_at_symbols'] > 0:
        anomaly_score += 25.0
        indicators.append("URL Authority Bypass ('@' symbol): Browser will ignore host prefix and route to authority after '@'.")
        reasons.append("Contains '@' symbol indicating possible URL credential/destination spoofing.")

    if features['has_double_slash_path'] == 1:
        anomaly_score += 15.0
        indicators.append("Double Slash '//' in URL Path: Often used in open redirect vulnerabilities.")

    if features['is_https'] == 0:
        anomaly_score += 10.0
        indicators.append("Insecure Protocol: URL uses unencrypted HTTP rather than HTTPS.")
        reasons.append("Uses unencrypted HTTP connection (credentials can be intercepted).")
    else:
        reasons.append("Uses HTTPS encryption protocol.")

    if features['url_length'] > 85:
        anomaly_score += 10.0
        indicators.append(f"Abnormally Long URL ({features['url_length']} chars): May contain padded query parameters to hide destination.")

    if not indicators:
        reasons.append("Domain and URL path structure are consistent with legitimate web services.")
        reasons.append("No brand impersonation, suspicious TLDs, or IP hostnames detected.")

    anomaly_score = min(100.0, anomaly_score)

    # Compute final fused Cyber Risk Score (0-100)
    risk_score, risk_level, prediction = calculate_cyber_risk_score(
        ml_probability=phish_prob,
        heuristic_score=anomaly_score,
        vector_anomaly_score=anomaly_score,
        has_critical_trigger=has_critical
    )

    # Calibrate display confidence
    confidence = phish_prob if prediction == "Fake / Malicious" else (real_prob if prediction == "Real / Safe" else max(phish_prob, real_prob))

    # Feature table for UI inspection
    inspected_features = [
        {"name": "URL Length", "value": f"{features['url_length']} characters", "risk": "High" if features['url_length'] > 90 else "Normal"},
        {"name": "Domain / Host", "value": metadata['hostname'] or "N/A", "risk": "Critical" if features['has_ip'] else "Normal"},
        {"name": "Registered Domain", "value": f"{metadata['domain']}.{metadata['tld']}" if metadata['domain'] else "N/A", "risk": "High" if features['is_suspicious_tld'] else "Normal"},
        {"name": "HTTPS Encryption", "value": "Enabled" if features['is_https'] else "Disabled (Insecure HTTP)", "risk": "Normal" if features['is_https'] else "Medium"},
        {"name": "IP Address as Host", "value": "Yes (Detected)" if features['has_ip'] else "No (Standard DNS)", "risk": "Critical" if features['has_ip'] else "Safe"},
        {"name": "Subdomain Depth", "value": f"{features['subdomain_count']} subdomains", "risk": "High" if features['subdomain_count'] >= 3 else "Normal"},
        {"name": "Suspicious TLD", "value": f".{metadata['tld']}" if metadata['tld'] else "None", "risk": "High" if features['is_suspicious_tld'] else "Normal"},
        {"name": "URL Shortener", "value": "Yes" if features['is_shortened'] else "No", "risk": "Medium" if features['is_shortened'] else "Normal"},
        {"name": "Suspicious Keywords", "value": ", ".join(metadata['found_keywords']) if metadata['found_keywords'] else "None", "risk": "High" if features['keyword_count'] > 0 else "Safe"},
        {"name": "Shannon Entropy", "value": f"{features['url_entropy']:.2f} bits/symbol", "risk": "High" if features['url_entropy'] > 4.5 else "Normal"},
        {"name": "Special Characters", "value": f"Dots: {features['num_dots']}, Hyphens: {features['num_hyphens']}, Slashes: {features['num_slashes']}", "risk": "Medium" if (features['num_dots'] > 3 or features['num_hyphens'] > 3) else "Normal"},
    ]

    return {
        "scan_type": "url",
        "input_preview": url_clean[:80] + ("..." if len(url_clean) > 80 else ""),
        "raw_input": url_clean,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "class_probabilities": {
            "real": real_prob,
            "fake": phish_prob
        },
        "indicators": indicators,
        "xai_data": {
            "reasons": reasons,
            "feature_table": inspected_features,
            "entropy": features['url_entropy'],
            "ml_probability": phish_prob
        },
        "metadata_info": metadata
    }
