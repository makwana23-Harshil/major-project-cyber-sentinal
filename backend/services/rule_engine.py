"""
Cyber Sentinel - Rule Engine & Multi-Signal Risk Assessment
Evaluates social engineering triggers, coercive pressure, brand impersonation,
domain mismatches, and fuses ML probabilities with heuristic indicators.
"""

import re
from typing import List, Dict, Any, Tuple
from backend.config import RISK_THRESHOLD_SAFE, RISK_THRESHOLD_SUSPICIOUS, RISK_THRESHOLD_HIGH

# Social Engineering Pattern Categories
PATTERNS = {
    "URGENCY_PRESSURE": {
        "label": "Urgent Time Pressure",
        "description": "Uses artificial time limit or panic inducing wording",
        "weight": 18,
        "keywords": [
            r"\burgent\b", r"\bimmediately\b", r"\bright now\b", r"\bwithin 24 hours\b",
            r"\bwithin 12 hours\b", r"\btoday only\b", r"\baction required\b",
            r"\bimmediate action\b", r"\btime-sensitive\b", r"\bdeadline\b",
            r"\bexpires soon\b", r"\blast warning\b", r"\bfinal notice\b"
        ]
    },
    "COERCIVE_THREATS": {
        "label": "Coercive Threats & Account Blocking",
        "description": "Threatens account suspension, deactivation, legal action, or fines",
        "weight": 22,
        "keywords": [
            r"\baccount suspended\b", r"\baccount blocked\b", r"\baccount locked\b",
            r"\brestricted access\b", r"\bpermanently closed\b", r"\bterminated\b",
            r"\bunauthorized access\b", r"\bsecurity breach\b", r"\bsuspicious activity\b",
            r"\bviolation\b", r"\bavoid penalty\b", r"\blegal action\b", r"\barrest\b"
        ]
    },
    "CREDENTIAL_HARVESTING": {
        "label": "Credential & Password Requests",
        "description": "Solicits login credentials, password resets, PINs, or secret keys",
        "weight": 25,
        "keywords": [
            r"\benter your password\b", r"\bverify your password\b", r"\bconfirm password\b",
            r"\blogin to verify\b", r"\bsign in here\b", r"\bsecurity pin\b",
            r"\bseed phrase\b", r"\bsecret key\b", r"\brecovery phrase\b",
            r"\bverify credentials\b", r"\bupdate credentials\b", r"\bidentity verification\b"
        ]
    },
    "OTP_SECURITY_BAIT": {
        "label": "OTP & Authentication Code Theft",
        "description": "Tricks user into disclosing or confirming one-time passwords",
        "weight": 25,
        "keywords": [
            r"\benter the otp\b", r"\bshare your otp\b", r"\botp sent to your phone\b",
            r"\bverification code is\b", r"\bconfirm otp\b", r"\bprovide otp\b",
            r"\bsim swap\b", r"\b2fa code\b", r"\bauthentication code\b"
        ]
    },
    "FINANCIAL_EXTORTION": {
        "label": "Financial Bait & Unauthorized Charges",
        "description": "Claims unpaid fees, lotteries, wire transfers, or tax refunds",
        "weight": 20,
        "keywords": [
            r"\bwire transfer\b", r"\bdirect deposit\b", r"\bunpaid customs fee\b",
            r"\btax refund\b", r"\blottery winner\b", r"\bclaim prize\b",
            r"\bunpaid toll\b", r"\bcredit card details\b", r"\bbank account number\b",
            r"\bgift card\b", r"\bcrypto giveaway\b", r"\bpayment failed\b", r"\brefund pending\b"
        ]
    },
    "IMPERSONATION_AUTHORITY": {
        "label": "Authority / Corporate Impersonation",
        "description": "Fakes authoritative identity (Bank, IRS, CEO, IT Helpdesk, HR)",
        "weight": 18,
        "keywords": [
            r"\bceo request\b", r"\bit helpdesk\b", r"\bhr department\b",
            r"\bfraud department\b", r"\birs refund\b", r"\boffice 365 support\b",
            r"\bpaypal resolution center\b", r"\bapple support\b", r"\bchase bank alert\b",
            r"\bwells fargo alert\b", r"\bbank of america\b", r"\bkyc verification\b"
        ]
    }
}


def analyze_social_engineering(text: str) -> Dict[str, Any]:
    """
    Analyze text for social engineering patterns and extract triggered indicators.
    """
    if not text:
        return {"heuristic_score": 0.0, "triggered_categories": [], "indicators": [], "matched_phrases": []}
    
    text_lower = text.lower()
    triggered = []
    indicators = []
    matched_phrases = []
    total_weight = 0
    
    for cat_key, cat_data in PATTERNS.items():
        cat_matches = []
        for kw_regex in cat_data["keywords"]:
            found = re.findall(kw_regex, text_lower)
            if found:
                cat_matches.extend(found)
        
        if cat_matches:
            total_weight += cat_data["weight"]
            unique_matches = list(set(cat_matches))
            triggered.append({
                "category": cat_key,
                "label": cat_data["label"],
                "description": cat_data["description"],
                "matches": unique_matches
            })
            indicators.append(f"{cat_data['label']}: Detected phrases {', '.join(f'\"{m}\"' for m in unique_matches[:3])}")
            matched_phrases.extend(unique_matches)
            
    # Normalize heuristic score to 0 - 100 range
    heuristic_score = min(100.0, float(total_weight))
    
    return {
        "heuristic_score": heuristic_score,
        "triggered_categories": triggered,
        "indicators": indicators,
        "matched_phrases": list(set(matched_phrases))
    }


def calculate_cyber_risk_score(
    ml_probability: float,
    heuristic_score: float,
    vector_anomaly_score: float = 0.0,
    has_critical_trigger: bool = False
) -> Tuple[float, str, str]:
    """
    Transparent multi-signal risk fusion formula:
    Cyber Risk Score (0-100) = (ML_Prob * 0.50) + (Heuristic_Score * 0.35) + (Vector_Anomaly * 0.15)
    
    Returns: (risk_score, risk_level, prediction_label)
    """
    # ml_probability is in range 0 - 100
    risk = (ml_probability * 0.50) + (heuristic_score * 0.35) + (vector_anomaly_score * 0.15)
    
    # If critical trigger present (e.g. IP host + credential harvesting), amplify minimum risk
    if has_critical_trigger:
        risk = max(risk, 75.0)
        
    risk_score = round(min(100.0, max(0.0, risk)), 1)
    
    # Determine Risk Level and Prediction Label
    if risk_score <= RISK_THRESHOLD_SAFE:
        risk_level = "LOW"
        prediction = "Real / Safe"
    elif risk_score <= RISK_THRESHOLD_SUSPICIOUS:
        risk_level = "MEDIUM"
        prediction = "Suspicious"
    elif risk_score <= RISK_THRESHOLD_HIGH:
        risk_level = "HIGH"
        prediction = "Fake / Malicious"
    else:
        risk_level = "CRITICAL"
        prediction = "Fake / Malicious"
        
    return risk_score, risk_level, prediction
