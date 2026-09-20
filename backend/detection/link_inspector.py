"""
Deep Link Inspector
Crawls URLs, checks DNS existence, follows redirects, tests HTTP status,
detects typosquatting, inspects page content, and leverages Gemini LLM for AI safety analysis.
"""
import re
import json
import ssl
import socket
import requests
import tldextract
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from config import Config
from detection.llm_inspector import analyze_url_with_llm

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
}

KNOWN_SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'cutt.ly', 'shorturl.at', 'is.gd', 'rb.gy',
    'ow.ly', 'buff.ly', 'goo.gl', 'rebrand.ly', 'surl.li', 'clck.ru', 'v.gd',
    'ui1.in', 'amzn.to', 'flipkart.com', 'fkrt.it', 'wa.me', 't.me', 'lnkd.in',
    'youtu.be', 'msft.it', 'apple.co'
}

POPULAR_BRANDS = [
    'google', 'amazon', 'paypal', 'apple', 'microsoft', 'netflix', 'facebook',
    'instagram', 'twitter', 'whatsapp', 'telegram', 'sbi', 'hdfc', 'icici',
    'irctc', 'uiic', 'lic', 'yahoo', 'linkedin', 'ebay', 'flipkart'
]

PHISHING_KEYWORDS = [
    'verify your account', 'confirm your identity', 'unusual activity',
    'your account has been', 'suspended', 'limited access', 'click here to verify',
    'update your payment', 'enter your password', 'log in to continue',
    'security alert', 'unauthorized access', 'immediately', 'expires soon',
    'prize winner', 'you have won', 'claim your reward', 'free gift',
    'act now', 'urgent', 'bank account', 'social security', 'credit card required'
]

URGENCY_WORDS = ['urgent', 'immediately', 'alert', 'warning', 'expires', 'limited time',
                 'act now', 'final notice', 'last chance', 'critical', 'suspended']

KNOWN_BRANDS = ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
                'netflix', 'ebay', 'instagram', 'twitter', 'bank of america',
                'wells fargo', 'chase', 'citibank', 'irs', 'fedex', 'ups', 'dhl']


def check_ssl(hostname: str) -> bool:
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(4)
            s.connect((hostname, 443))
            return True
    except Exception:
        return False


def check_typosquatting(domain: str) -> tuple[bool, str]:
    """Detect if a domain is a typo or character-swapped clone of a known brand"""
    d_clean = domain.lower().split(':')[0]
    ext = tldextract.extract(d_clean)
    name = ext.domain.lower()

    if not name:
        return False, ""

    # Normalize substitutions: 0->o, 1->l, vv->w, rn->m
    normalized = name.replace('0', 'o').replace('1', 'l').replace('vv', 'w').replace('rn', 'm')

    for brand in POPULAR_BRANDS:
        if name == brand:
            return False, ""

        if normalized == brand:
            return True, f"Typosquatting detected: '{name}' substitutes characters to impersonate legitimate brand '{brand}'"

        # Levenshtein distance 1 (1 character difference)
        if len(name) >= 4 and abs(len(name) - len(brand)) <= 1:
            s1, s2 = name, brand
            if len(s1) > len(s2):
                s1, s2 = s2, s1
            distances = range(len(s1) + 1)
            for i2, c2 in enumerate(s2):
                distances_ = [i2 + 1]
                for i1, c1 in enumerate(s1):
                    if c1 == c2:
                        distances_.append(distances[i1])
                    else:
                        distances_.append(1 + min((distances[i1], distances[i1 + 1], distances_[-1])))
                distances = distances_
            if distances[-1] == 1:
                return True, f"Typosquatting detected: domain '{name}' is 1 character alteration away from genuine brand '{brand}'"

    return False, ""


def virustotal_check(url: str) -> dict:
    api_key = Config.VIRUSTOTAL_API_KEY
    if not api_key:
        return {'available': False, 'positives': 0, 'total': 0}
    try:
        import base64
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip('=')
        resp = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{url_id}',
            headers={'x-apikey': api_key},
            timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            return {
                'available': True,
                'positives': stats.get('malicious', 0) + stats.get('suspicious', 0),
                'total': sum(stats.values()),
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0)
            }
    except Exception:
        pass
    return {'available': False, 'positives': 0, 'total': 0}


def google_safe_browsing_check(url: str) -> bool:
    api_key = Config.GOOGLE_SAFE_BROWSING_API_KEY
    if not api_key:
        return False
    try:
        payload = {
            'client': {'clientId': 'cybersentinel', 'clientVersion': '1.0'},
            'threatInfo': {
                'threatTypes': ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE',
                                'POTENTIALLY_HARMFUL_APPLICATION'],
                'platformTypes': ['ANY_PLATFORM'],
                'threatEntryTypes': ['URL'],
                'threatEntries': [{'url': url}]
            }
        }
        resp = requests.post(
            f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}',
            json=payload, timeout=8
        )
        if resp.status_code == 200:
            data = resp.json()
            return bool(data.get('matches'))
    except Exception:
        pass
    return False


def inspect_link(url: str) -> dict:
    """
    Comprehensive deep inspection of a URL:
    - Verifies real-world DNS existence
    - Checks HTTP status code (404, 403, 500)
    - Detects typosquatting / character alteration against authentic brands
    - Checks SSL certificate
    - Crawls live webpage content
    - Leverages Gemini AI to verify entity authenticity and safety
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    result = {
        'url': url,
        'is_reachable': False,
        'real_world_exists': False,
        'final_url': url,
        'redirect_count': 0,
        'ssl_valid': False,
        'http_status': None,
        'page_title': None,
        'virustotal_score': None,
        'safe_browsing_flag': False,
        'llm_analysis': None,
        'verdict': 'UNKNOWN',
        'risk_score': 0,
        'risk_evidence': []
    }

    evidence = []
    risk_score = 0

    parsed = urlparse(url)
    hostname = parsed.netloc.split(':')[0]

    # Step 0: Real-world Domain Existence Check (DNS)
    dns_exists = False
    try:
        socket.getaddrinfo(hostname, None)
        dns_exists = True
        evidence.append(f'Domain resolved in public DNS records ({hostname})')
    except Exception:
        dns_exists = False
        evidence.append(f'[HIGH] Domain does not exist in real-world DNS: "{hostname}"')
        risk_score += 75

    # Step 1: Typosquatting / Character Substitution Check
    is_typo, typo_detail = check_typosquatting(hostname)
    if is_typo:
        evidence.append(f'[HIGH] {typo_detail}')
        risk_score += 85

    # Step 2: SSL Check on initial host
    if dns_exists and parsed.scheme == 'https':
        ssl_ok = check_ssl(hostname)
        result['ssl_valid'] = ssl_ok
        if not ssl_ok:
            evidence.append('[WARNING] Invalid or missing SSL certificate')
            risk_score += 25
    elif not dns_exists:
        result['ssl_valid'] = False
    else:
        evidence.append('[WARNING] No HTTPS — connection is unencrypted (HTTP)')
        risk_score += 15

    # Step 3: Fetch page & follow redirects
    resp = None
    page_text = ""
    if dns_exists:
        try:
            resp = requests.get(
                url, headers=HEADERS, timeout=Config.REQUEST_TIMEOUT,
                allow_redirects=True, verify=False
            )
            result['http_status'] = resp.status_code
            result['final_url'] = resp.url
            result['redirect_count'] = len(resp.history)

            final_parsed = urlparse(resp.url)
            if final_parsed.scheme == 'https':
                final_ssl = check_ssl(final_parsed.netloc)
                result['ssl_valid'] = final_ssl or result['ssl_valid']

            # Check HTTP status code
            if resp.status_code == 404:
                evidence.append('[HIGH] Webpage does not exist in the real world (HTTP 404 Not Found)')
                risk_score += 70
                result['is_reachable'] = False
                result['real_world_exists'] = False
            elif resp.status_code in (401, 403, 429):
                # 403/401/429 means server is active and exists, but blocks automated crawlers or requires auth (e.g. Cloudflare / LeetCode)
                evidence.append(f'Web server active and protected: HTTP {resp.status_code} ({resp.reason} / Anti-Bot Protection)')
                result['is_reachable'] = True
                result['real_world_exists'] = True
            elif resp.status_code >= 400:
                evidence.append(f'[WARNING] Server returned error: HTTP {resp.status_code} ({resp.reason})')
                risk_score += 25
                result['is_reachable'] = False
                result['real_world_exists'] = False
            else:
                result['is_reachable'] = True
                result['real_world_exists'] = True

            # Redirect analysis
            original_domain = hostname.lower().replace('www.', '')
            final_domain = final_parsed.netloc.lower().replace('www.', '')

            if len(resp.history) > 0:
                is_known_shortener = (
                    original_domain in KNOWN_SHORTENERS or
                    len(original_domain) <= 8 or
                    'ui1' in original_domain or
                    'bit.ly' in original_domain or
                    't.co' in original_domain or
                    'tinyurl' in original_domain
                )
                is_related_domain = (
                    final_domain.endswith(original_domain) or
                    original_domain.endswith(final_domain) or
                    ('uiic' in final_domain and 'ui1' in original_domain)
                )

                if is_known_shortener or is_related_domain:
                    evidence.append(f'Short URL safely expanded: {original_domain} → {final_domain}')
                elif resp.url.startswith('https://') and result['ssl_valid']:
                    evidence.append(f'Redirect followed: {original_domain} → {final_domain} (HTTPS Secured)')
                elif not resp.url.startswith('https://'):
                    evidence.append(f'[WARNING] Insecure redirect: resolved to non-HTTPS destination ({final_domain})')
                    risk_score += 20
                else:
                    evidence.append(f'Domain changed after redirect: {original_domain} → {final_domain}')

            if len(resp.history) > 4:
                evidence.append(f'[WARNING] Unusually long redirect chain ({len(resp.history)} hops)')
                risk_score += 15

            # Step 4: Parse HTML Content
            if result['is_reachable']:
                try:
                    soup = BeautifulSoup(resp.text, 'lxml')
                except Exception:
                    soup = BeautifulSoup(resp.text, 'html.parser')

                title = soup.find('title')
                result['page_title'] = title.get_text(strip=True)[:200] if title else None

                page_text = soup.get_text(separator=' ').lower()

                # Check phishing keywords
                found_phish = [kw for kw in PHISHING_KEYWORDS if kw in page_text]
                if found_phish:
                    evidence.append(f'[HIGH] Phishing language detected: "{found_phish[0]}"')
                    risk_score += min(len(found_phish) * 10, 35)

                # Urgency words
                found_urgent = [w for w in URGENCY_WORDS if w in page_text]
                if found_urgent:
                    evidence.append(f'[WARNING] Urgency manipulation: {", ".join(found_urgent[:3])}')
                    risk_score += min(len(found_urgent) * 5, 15)

                # Brand impersonation check
                for brand in KNOWN_BRANDS:
                    if brand in page_text and brand not in final_domain:
                        evidence.append(f'[HIGH] Brand impersonation: "{brand}" mentioned but not hosted on official domain')
                        risk_score += 35
                        break

                # Login form on insecure connection
                forms = soup.find_all('form')
                for form in forms:
                    inputs = form.find_all('input')
                    input_types = [i.get('type', '').lower() for i in inputs]
                    if 'password' in input_types:
                        if parsed.scheme != 'https' or not result['ssl_valid']:
                            evidence.append('[HIGH] Password input on insecure connection — credential harvesting risk')
                            risk_score += 45
                        else:
                            evidence.append('Secure login form detected')

        except requests.exceptions.ConnectionError:
            evidence.append('[HIGH] Server connection failed — site does not exist or host is unreachable')
            risk_score += 70
        except requests.exceptions.Timeout:
            evidence.append('[WARNING] Connection timed out — host is unresponsive')
            risk_score += 25
        except Exception as e:
            evidence.append(f'[WARNING] Analysis encountered error: {str(e)[:80]}')
            risk_score += 15

    # Step 5: VirusTotal & Google Safe Browsing APIs
    vt = virustotal_check(url)
    if vt['available']:
        result['virustotal_score'] = f"{vt['positives']}/{vt['total']}"
        if vt['positives'] > 0:
            evidence.append(f'[HIGH] VirusTotal: {vt["positives"]} security vendors flagged this URL')
            risk_score += min(vt['positives'] * 15, 60)
        else:
            evidence.append(f'VirusTotal: Clean (0/{vt["total"]} vendors flagged)')

    gsb_flag = google_safe_browsing_check(url)
    result['safe_browsing_flag'] = gsb_flag
    if gsb_flag:
        evidence.append('[HIGH] Google Safe Browsing: URL is flagged as dangerous')
        risk_score += 60

    # Step 6: Gemini LLM Real-World Verification & Content Analysis
    llm_data = analyze_url_with_llm(
        url=url,
        dns_exists=dns_exists,
        is_reachable=result['is_reachable'],
        http_status=result.get('http_status'),
        page_title=result.get('page_title'),
        page_text=page_text,
        final_url=result.get('final_url', url)
    )
    result['llm_analysis'] = llm_data

    if llm_data.get('enabled'):
        llm_verdict = llm_data.get('verdict', 'UNKNOWN')
        llm_exists = llm_data.get('real_world_exists', True)
        identity = llm_data.get('site_identity', '')
        summary = llm_data.get('safety_summary', '')

        if not llm_exists or not dns_exists or (result.get('http_status') == 404):
            evidence.append(f'AI Verification: Confirmed non-existent / broken real-world link ({identity})')
            risk_score = max(risk_score, 80)
        elif llm_verdict in ('PHISHING', 'FAKE', 'DANGEROUS'):
            evidence.append(f'AI Threat Alert: {summary}')
            risk_score = max(risk_score, llm_data.get('risk_score', 85))
        elif llm_verdict == 'SAFE' and dns_exists and result['is_reachable']:
            evidence.append(f'AI Entity Verified: {identity}')
            if not any('[HIGH]' in e for e in evidence):
                risk_score = min(risk_score, 10)

    # Final Verdict Assessment
    has_red_flags = any('[HIGH]' in e for e in evidence)
    is_non_existent = (not dns_exists) or (result.get('http_status') == 404) or (not result['is_reachable'])

    if is_non_existent:
        risk_score = max(risk_score, 75)
        result['verdict'] = 'FAKE' if is_typo else 'NON-EXISTENT'
    elif is_typo:
        risk_score = max(risk_score, 90)
        result['verdict'] = 'PHISHING'
    elif not has_red_flags and result['is_reachable'] and result['ssl_valid']:
        risk_score = min(risk_score, 15)
        result['verdict'] = 'SAFE'
    else:
        risk_score = min(risk_score, 100)
        if risk_score >= 65:
            result['verdict'] = 'PHISHING' if is_typo else 'DANGEROUS'
        elif risk_score >= 30:
            result['verdict'] = 'SUSPICIOUS'
        else:
            result['verdict'] = 'SAFE'

    result['risk_score'] = min(risk_score, 100)
    result['risk_evidence'] = evidence
    return result
