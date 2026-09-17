"""
Cyber Sentinel - Text, Email, and SMS/Message Threat Scanner Service
Evaluates natural language, social engineering cues, embedded links, sender spoofing,
and generates Explainable AI diagnostics with highlighted markup.
"""

import os
import joblib
import numpy as np
from typing import Dict, Any, List, Optional
from backend.config import TEXT_MODEL_PATH, TFIDF_VECTORIZER_PATH
from backend.services.rule_engine import analyze_social_engineering, calculate_cyber_risk_score
from backend.services.explainability import generate_highlighted_markup, format_xai_summary
from backend.services.email_parser import extract_urls_from_text, analyze_sender_spoofing, audit_attachments
from backend.services.url_scanner import scan_url

_TEXT_MODEL = None
_TFIDF_VECTORIZER = None


def get_text_model():
    global _TEXT_MODEL, _TFIDF_VECTORIZER
    if _TEXT_MODEL is None and os.path.exists(TEXT_MODEL_PATH):
        _TEXT_MODEL = joblib.load(TEXT_MODEL_PATH)
    if _TFIDF_VECTORIZER is None and os.path.exists(TFIDF_VECTORIZER_PATH):
        _TFIDF_VECTORIZER = joblib.load(TFIDF_VECTORIZER_PATH)
    return _TEXT_MODEL, _TFIDF_VECTORIZER


def extract_top_influential_tokens(text: str, vectorizer, model, top_n: int = 10) -> List[Dict[str, Any]]:
    """Extract tokens present in text that carry the highest model weights."""
    if not text or vectorizer is None or model is None:
        return []
    
    feature_names = np.array(vectorizer.get_feature_names_out())
    coefs = model.coef_[0]
    
    # Transform text to find present features
    X_tfidf = vectorizer.transform([text])
    present_indices = X_tfidf.nonzero()[1]
    
    if len(present_indices) == 0:
        return []
        
    token_weights = []
    for idx in present_indices:
        token = feature_names[idx]
        weight = coefs[idx]
        tfidf_val = X_tfidf[0, idx]
        # Impact score = weight * tfidf_val
        impact = weight * tfidf_val
        token_weights.append({
            "token": token,
            "weight": round(float(weight), 3),
            "impact": round(float(impact), 3)
        })
        
    # Sort descending by impact
    token_weights.sort(key=lambda x: x["impact"], reverse=True)
    return token_weights[:top_n]


def scan_text_content(
    text: str,
    scan_type: str = "text",
    subject: str = "",
    sender: str = "",
    recipient: str = "",
    attachments: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Unified scanner for Raw Text, Email messages, and SMS/WhatsApp messages.
    """
    combined_text = f"{subject} {text}".strip()
    
    # 1. ML Model Inference
    model, vectorizer = get_text_model()
    if model is not None and vectorizer is not None:
        X_vec = vectorizer.transform([combined_text])
        probs = model.predict_proba(X_vec)[0]
        real_prob = float(round(probs[0] * 100, 1))
        phish_prob = float(round(probs[1] * 100, 1))
        top_tokens = extract_top_influential_tokens(combined_text, vectorizer, model)
    else:
        phish_prob = 50.0
        real_prob = 50.0
        top_tokens = []

    # 2. Social Engineering & Heuristic Analysis
    se_analysis = analyze_social_engineering(combined_text)
    heuristic_score = se_analysis["heuristic_score"]
    indicators = list(se_analysis["indicators"])
    matched_phrases = se_analysis["matched_phrases"]
    has_critical = False
    
    # 3. Email-specific checks (Spoofing & Attachments)
    email_metadata = {}
    if scan_type == "email":
        if sender:
            spoof_res = analyze_sender_spoofing(sender)
            email_metadata["sender_analysis"] = spoof_res
            if spoof_res.get("spoofing_detected"):
                heuristic_score += 35.0
                has_critical = True
                indicators.append(f"Sender Domain Mismatch: {spoof_res['reason']}")
                
        if attachments:
            att_audit = audit_attachments(attachments)
            email_metadata["attachment_audit"] = att_audit
            if att_audit["has_dangerous"]:
                heuristic_score += 40.0
                has_critical = True
                for d in att_audit["dangerous_files"]:
                    indicators.append(f"Malicious Attachment: {d}")
            for s in att_audit.get("suspicious_files", []):
                indicators.append(f"Suspicious Attachment: {s}")

    # 4. Embedded URL Extraction & Deep Nested Scanning
    embedded_urls = extract_urls_from_text(combined_text)
    nested_url_scans = []
    max_url_risk = 0.0
    
    for u in embedded_urls[:3]:  # Deep scan top 3 extracted links
        u_res = scan_url(u)
        nested_url_scans.append({
            "url": u,
            "prediction": u_res["prediction"],
            "risk_score": u_res["risk_score"],
            "risk_level": u_res["risk_level"],
            "indicators": u_res["indicators"]
        })
        if u_res["risk_score"] > max_url_risk:
            max_url_risk = u_res["risk_score"]
            
        if u_res["prediction"] == "Fake / Malicious":
            has_critical = True
            indicators.append(f"Malicious Embedded Link: Found link '{u}' ({u_res['risk_level']} Risk - {u_res['risk_score']}/100)")

    # 5. Risk Fusion Formula
    # Incorporate embedded URL risk if present
    vector_risk = max_url_risk if embedded_urls else 0.0
    risk_score, risk_level, prediction = calculate_cyber_risk_score(
        ml_probability=phish_prob,
        heuristic_score=heuristic_score,
        vector_anomaly_score=vector_risk,
        has_critical_trigger=has_critical
    )

    confidence = phish_prob if prediction == "Fake / Malicious" else (real_prob if prediction == "Real / Safe" else max(phish_prob, real_prob))

    # 6. Generate Highlighted Markup for UI
    highlighted_html = generate_highlighted_markup(
        raw_text=text,
        matched_phrases=matched_phrases,
        embedded_urls=embedded_urls,
        influential_tokens=top_tokens
    )

    # 7. Structure XAI payload
    xai_data = format_xai_summary(
        scan_type=scan_type,
        prediction=prediction,
        confidence=confidence,
        risk_score=risk_score,
        indicators=indicators,
        top_tokens=top_tokens
    )
    xai_data["highlighted_html"] = highlighted_html
    xai_data["embedded_urls_analysis"] = nested_url_scans
    xai_data["social_engineering"] = se_analysis["triggered_categories"]

    input_preview = (subject + " - " if subject else "") + text.strip()
    preview_clean = input_preview[:80] + ("..." if len(input_preview) > 80 else "")

    return {
        "scan_type": scan_type,
        "input_preview": preview_clean,
        "raw_input": text,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "class_probabilities": {
            "real": real_prob,
            "fake": phish_prob
        },
        "indicators": indicators,
        "xai_data": xai_data,
        "metadata_info": {
            "subject": subject,
            "sender": sender,
            "recipient": recipient,
            "email_metadata": email_metadata,
            "embedded_urls_count": len(embedded_urls)
        }
    }
