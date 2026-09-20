"""
Cyber Sentinel - Explainable AI (XAI) Service
Provides token-level attribution, visual word highlighting markup,
and transparent detection rationales.
"""

import re
import html
from typing import List, Dict, Any

CATEGORY_CSS_CLASSES = {
    "URGENCY_PRESSURE": "xai-highlight xai-urgent",
    "COERCIVE_THREATS": "xai-highlight xai-threat",
    "CREDENTIAL_HARVESTING": "xai-highlight xai-credential",
    "OTP_SECURITY_BAIT": "xai-highlight xai-otp",
    "FINANCIAL_EXTORTION": "xai-highlight xai-financial",
    "IMPERSONATION_AUTHORITY": "xai-highlight xai-impersonation",
    "URL_LINK": "xai-highlight xai-link",
    "SAFE_TOKEN": "xai-highlight xai-safe"
}


def generate_highlighted_markup(
    raw_text: str,
    matched_phrases: List[str] = None,
    embedded_urls: List[str] = None,
    influential_tokens: List[Dict[str, Any]] = None
) -> str:
    """
    Generate safe HTML markup where risky phrases, URLs, and influential tokens
    are wrapped in stylized span tags for XAI visualization.
    """
    if not raw_text:
        return ""
    
    escaped_text = html.escape(raw_text)
    
    # Highlight URLs first
    if embedded_urls:
        for u in embedded_urls:
            esc_u = html.escape(u)
            if esc_u in escaped_text:
                replacement = f'<span class="xai-highlight xai-link" title="Detected URL: {esc_u}">{esc_u}</span>'
                escaped_text = escaped_text.replace(esc_u, replacement)
                
    # Highlight social engineering matched phrases
    if matched_phrases:
        # Sort by length descending to match longer multi-word phrases first
        sorted_phrases = sorted(list(set(matched_phrases)), key=len, reverse=True)
        for phrase in sorted_phrases:
            if not phrase.strip():
                continue
            # Case-insensitive replacement
            pattern = re.compile(re.escape(phrase), re.IGNORECASE)
            
            def replace_match(m):
                matched_val = m.group(0)
                return f'<span class="xai-highlight xai-threat" title="Threat Indicator: {matched_val}">{matched_val}</span>'
                
            escaped_text = pattern.sub(replace_match, escaped_text)
            
    # Highlight influential ML tokens if present
    if influential_tokens:
        for item in influential_tokens[:8]:
            tok = item.get("token", "")
            if len(tok) > 3 and not tok.startswith("http"):
                pattern = re.compile(rf"\b({re.escape(tok)})\b", re.IGNORECASE)
                token_weight = item.get("weight", 0)
                def replace_token(m):
                    val = m.group(0)
                    # Don't double wrap if already highlighted
                    return f'<span class="xai-highlight xai-token" title="ML Phishing Feature Weight: +{token_weight}">{val}</span>'
                escaped_text = pattern.sub(replace_token, escaped_text)
                
    return escaped_text


def format_xai_summary(
    scan_type: str,
    prediction: str,
    confidence: float,
    risk_score: float,
    indicators: List[str],
    top_tokens: List[Dict[str, Any]],
    url_diagnostics: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Generate comprehensive Explainable AI metadata structure.
    """
    reasons = []
    
    if indicators:
        reasons.extend(indicators)
    elif prediction == "Real / Safe":
        reasons.append("No abnormal social engineering triggers or phishing signals detected.")
        reasons.append("Structure, syntax, and domain characteristics conform to verified legitimate patterns.")
        
    return {
        "scan_type": scan_type,
        "prediction": prediction,
        "confidence": confidence,
        "risk_score": risk_score,
        "reasons": reasons,
        "influential_features": top_tokens,
        "url_diagnostics": url_diagnostics or {}
    }
