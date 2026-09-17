"""Email Address Validator and Predictor"""
import re
import dns.resolver
import whois
from datetime import datetime, timezone

DISPOSABLE_DOMAINS = {
    'mailinator.com', 'guerrillamail.com', 'tempmail.com', 'throwaway.email',
    'yopmail.com', 'sharklasers.com', 'guerrillamailblock.com', 'grr.la',
    'guerrillamail.info', 'spam4.me', 'trashmail.com', 'trashmail.at',
    'trashmail.io', 'fakeinbox.com', 'maildrop.cc', 'dispostable.com',
    '10minutemail.com', 'minutemail.com', 'discard.email', 'spamgourmet.com',
    'mailnull.com', 'spamgourmet.net', 'spamgourmet.org', 'spamex.com',
    'spamfree24.org', 'mailcatch.com', 'jetable.fr.nf', 'jetable.net',
    'spam.la', 'spamhole.com', 'mytempemail.com', 'emailondeck.com'
}

SUSPICIOUS_PATTERNS = [
    r'^\d+@',                    # Starts with numbers only
    r'@.*\d{4,}',                # Domain has 4+ consecutive digits
    r'[^a-zA-Z0-9._%+\-]',      # Non-standard characters
    r'\.{2,}',                   # Consecutive dots
]

def validate_email_syntax(email: str) -> tuple[bool, str]:
    pattern = re.compile(
        r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$'
    )
    if not pattern.match(email):
        return False, "Invalid email format"
    parts = email.split('@')
    if len(parts) != 2:
        return False, "Must have exactly one @ symbol"
    local, domain = parts
    if len(local) > 64:
        return False, "Local part too long (max 64 chars)"
    if len(domain) > 253:
        return False, "Domain too long"
    if domain.startswith('.') or domain.endswith('.'):
        return False, "Domain cannot start or end with a dot"
    return True, "Syntax valid"

def check_mx_records(domain: str) -> tuple[bool, list]:
    try:
        records = dns.resolver.resolve(domain, 'MX', lifetime=5)
        mx_list = [str(r.exchange).rstrip('.') for r in records]
        return True, mx_list
    except dns.resolver.NXDOMAIN:
        return False, []
    except dns.resolver.NoAnswer:
        return False, []
    except Exception:
        return None, []  # None = unknown

def check_domain_age(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            age_days = (datetime.now() - creation_date.replace(tzinfo=None)).days
            return {'available': True, 'age_days': age_days, 'creation_date': str(creation_date)}
    except Exception:
        pass
    return {'available': False, 'age_days': None, 'creation_date': None}

def analyze_email_address(email: str) -> dict:
    email = email.strip().lower()
    evidence = []
    risk_score = 0

    # Syntax check
    syntax_ok, syntax_msg = validate_email_syntax(email)
    if not syntax_ok:
        return {
            'verdict': 'INVALID',
            'confidence': 0.99,
            'risk_score': 95,
            'is_valid_syntax': False,
            'is_disposable': False,
            'has_mx_records': False,
            'domain_age': None,
            'risk_evidence': [f'🔴 Syntax Error: {syntax_msg}'],
            'mx_records': []
        }

    parts = email.split('@')
    local, domain = parts

    evidence.append(f'✅ Valid email syntax')

    # Suspicious patterns in local part
    for pattern in SUSPICIOUS_PATTERNS:
        if re.search(pattern, local):
            evidence.append(f'⚠️ Suspicious pattern in email username')
            risk_score += 10
            break

    # Typosquatting check on email domain
    from detection.link_inspector import check_typosquatting
    from detection.llm_inspector import analyze_email_with_llm

    is_typo, typo_msg = check_typosquatting(domain)
    if is_typo:
        evidence.append(f'🔴 {typo_msg}')
        risk_score += 80

    # Disposable domain check
    is_disposable = domain in DISPOSABLE_DOMAINS
    if is_disposable:
        evidence.append(f'🔴 Disposable/temporary email domain: {domain}')
        risk_score += 55

    # MX records (Real-world existence of mail server)
    has_mx, mx_records = check_mx_records(domain)
    if has_mx is False:
        evidence.append(f'🔴 Domain {domain} does not exist as a mail server in the real world (MX records missing)')
        risk_score += 65
    elif has_mx is None:
        evidence.append(f'⚠️ Could not verify mail server for {domain}')
        risk_score += 15
    else:
        evidence.append(f'✅ Real-world mail server verified: {mx_records[0] if mx_records else "found"}')

    # Domain age
    domain_age = check_domain_age(domain)
    if domain_age['available']:
        age = domain_age['age_days']
        if age is not None:
            if age < 30:
                evidence.append(f'🔴 Domain is very new ({age} days old) — high risk')
                risk_score += 35
            elif age < 180:
                evidence.append(f'⚠️ Domain is relatively new ({age} days old)')
                risk_score += 15
            else:
                evidence.append(f'✅ Domain has been active for {age} days')
    else:
        evidence.append('ℹ️ Could not retrieve domain registration information')

    # LLM Real-World Verification
    llm_data = analyze_email_with_llm(email, has_mx=(has_mx is True), is_disposable=is_disposable, domain=domain)
    if llm_data.get('enabled'):
        if not llm_data.get('real_world_exists', True):
            evidence.append(f'🤖 AI Verification: Address is non-existent or fake in the real world')
            risk_score = max(risk_score, 80)
        elif llm_data.get('verdict') in ('FAKE', 'SUSPICIOUS'):
            evidence.append(f'🤖 AI Alert: {llm_data.get("analysis", "")}')
            risk_score = max(risk_score, llm_data.get('risk_score', 65))
        elif llm_data.get('verdict') == 'LEGITIMATE' and (has_mx is True):
            evidence.append(f'🤖 AI Verified: {llm_data.get("analysis", "Genuine real-world email structure")}')

    # Verdict
    risk_score = min(risk_score, 100)
    if (has_mx is False) or is_typo or (risk_score >= 70):
        verdict = 'FAKE'
    elif is_disposable:
        verdict = 'DISPOSABLE'
    elif risk_score >= 35:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'LEGITIMATE'

    confidence = 1.0 - (risk_score / 200)

    return {
        'verdict': verdict,
        'confidence': round(confidence, 4),
        'risk_score': risk_score,
        'is_valid_syntax': syntax_ok,
        'is_disposable': is_disposable,
        'has_mx_records': has_mx,
        'domain': domain,
        'domain_age': domain_age,
        'mx_records': mx_records[:3] if mx_records else [],
        'risk_evidence': evidence
    }


def analyze_email_body(body: str, inspect_links: bool = True) -> dict:
    """Analyze email body text for spam/phishing"""
    import os
    import joblib
    import re as _re
    from detection.link_inspector import inspect_link

    MODEL_PATH = os.path.join(os.path.dirname(__file__), '..', 'models', 'email_body_model.pkl')

    try:
        model = joblib.load(MODEL_PATH)
        prediction = model.predict([body])[0]
        # Calculate decision function distance
        try:
            df = float(model.decision_function([body])[0])
            # Sigmoid conversion
            import math
            spam_prob = 1.0 / (1.0 + math.exp(-df))
        except Exception:
            spam_prob = 0.80 if prediction == 'spam' else 0.20
    except FileNotFoundError:
        raise FileNotFoundError("Email model not found. Run: python models/train_models.py")

    # Extract URLs from email body
    url_pattern = _re.compile(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', _re.IGNORECASE)
    urls = list(set(url_pattern.findall(body)))

    link_results = []
    if inspect_links and urls:
        for url in urls[:5]:  # Limit to 5 links
            li = inspect_link(url)
            link_results.append(li)

    # LLM Contextual Evaluation
    from detection.llm_inspector import analyze_email_body_with_llm
    llm_analysis = analyze_email_body_with_llm(body, urls)

    evidence = []
    body_lower = body.lower()

    if llm_analysis.get('enabled'):
        llm_v = llm_analysis.get('verdict')
        intent = llm_analysis.get('sender_intent', '')
        reason = llm_analysis.get('reasoning', '')
        if llm_v == 'LEGITIMATE':
            evidence.append(f'🤖 AI Verified Content: {intent}')
            evidence.append(f'ℹ️ {reason}')
            prediction = 'ham'
            spam_prob = min(spam_prob, 0.05)
        elif llm_v in ('PHISHING', 'SUSPICIOUS'):
            evidence.append(f'🤖 AI Threat Alert: {reason}')
            prediction = 'spam'
            spam_prob = max(spam_prob, 0.90)

    max_link_risk = max((l['risk_score'] for l in link_results), default=0)
    base_risk = int(spam_prob * 70)
    composite_risk = min(base_risk + int(max_link_risk * 0.3), 100)

    dangerous_links = [l for l in link_results if l.get('verdict') in ('DANGEROUS', 'PHISHING', 'FAKE', 'NON-EXISTENT')]
    has_nonexistent_or_phish_links = len(dangerous_links) > 0

    if has_nonexistent_or_phish_links:
        composite_risk = max(composite_risk, 80)
        prediction = 'spam'
        verdict = 'PHISHING'
    elif prediction == 'spam' and composite_risk >= 70:
        verdict = 'PHISHING'
    elif prediction == 'spam' and composite_risk >= 35:
        verdict = 'SPAM'
    elif composite_risk >= 35:
        verdict = 'SUSPICIOUS'
    else:
        verdict = 'LEGITIMATE'
        composite_risk = min(composite_risk, 10)
        prediction = 'ham'

    phish_words = ['verify your account', 'click here', 'urgent', 'suspended',
                   'update payment', 'confirm identity', 'login now', 'prize']
    found = [w for w in phish_words if w in body_lower]
    if found:
        evidence.append(f'⚠️ Phishing keywords: {", ".join(found[:3])}')
    if urls:
        evidence.append(f'🔗 {len(urls)} URL(s) found in email body')
    if dangerous_links:
        evidence.append(f'🔴 {len(dangerous_links)} dangerous link(s) detected in email')
    if not evidence:
        evidence.append('✅ Email body content appears clean')

    return {
        'verdict': verdict,
        'confidence': round(1.0 - spam_prob if verdict == 'LEGITIMATE' else spam_prob, 4),
        'risk_score': composite_risk,
        'ml_prediction': verdict,
        'spam_probability': round(spam_prob, 4),
        'extracted_urls': urls,
        'url_count': len(urls),
        'link_inspections': link_results,
        'risk_evidence': evidence
    }
