"""
Cyber Sentinel - URL Feature Extractor
Extracts 30+ lexical, structural, statistical, and security features from URLs
for phishing classification and Explainable AI analysis.
"""

import re
import math
from urllib.parse import urlparse
import numpy as np

# Suspicious Top-Level Domains frequently associated with phishing/spam campaigns
SUSPICIOUS_TLDS = {
    'tk', 'xyz', 'top', 'ru', 'work', 'click', 'fit', 'gq', 'ga', 'cf',
    'ml', 'loan', 'racing', 'download', 'stream', 'accountant', 'date',
    'faith', 'review', 'party', 'trade', 'bid', 'surf', 'buzz', 'icu',
    'vip', 'monster', 'rest', 'live', 'cam', 'cn', 'tokyo', 'win'
}

# High-risk phishing intent keywords
SUSPICIOUS_KEYWORDS = [
    'login', 'signin', 'verify', 'verification', 'secure', 'account', 'update',
    'banking', 'bank', 'wallet', 'confirm', 'password', 'credential', 'auth',
    'authenticate', 'support', 'service', 'security', 'alert', 'suspended',
    'blocked', 'unusual', 'activity', 'free', 'gift', 'bonus', 'claim',
    'reward', 'paypal', 'apple', 'microsoft', 'netflix', 'amazon', 'chase',
    'wellsfargo', 'recovery', 'validate', 'portal', 'webscr', 'cmd', 'dispatch',
    'session', 'billing', 'invoice', 'payment', 'unlock', 'urgent', 'kyc'
]

# Common URL Shortener domains
SHORTENER_DOMAINS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'buff.ly', 'ow.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'bl.ink', 'tr.im'
}

# Recognized authoritative brand names often targeted for typosquatting / brand spoofing
TARGETED_BRANDS = [
    'google', 'paypal', 'apple', 'microsoft', 'netflix', 'amazon', 'chase',
    'wellsfargo', 'bankofamerica', 'citibank', 'facebook', 'instagram',
    'whatsapp', 'twitter', 'linkedin', 'binance', 'coinbase', 'metamask',
    'dropbox', 'adobe', 'ebay', 'spotify', 'roblox', 'steam'
]


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return float(entropy)


def is_ip_address(hostname: str) -> int:
    """Check if the hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return 0
    # Clean port if present in hostname
    host = hostname.split(':')[0]
    ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
    if re.match(ipv4_pattern, host):
        parts = host.split('.')
        if all(0 <= int(part) <= 255 for part in parts):
            return 1
    # Hex or Octal IP representation
    if re.match(r'^0x[0-9a-fA-F]+$', host) or re.match(r'^0[0-7]+$', host):
        return 1
    # Basic IPv6 check
    if ':' in host and all(c in '0123456789abcdefABCDEF:' for c in host):
        return 1
    return 0


def extract_url_features(url: str) -> dict:
    """
    Extract a dictionary of numerical and categorical features from a raw URL.
    Returns a dict with 30+ features and metadata.
    """
    if not url:
        url = ""
    
    # Ensure scheme for proper urlparse parsing
    raw_url = url.strip()
    if not re.match(r'^[a-zA-Z]+://', raw_url):
        parsed = urlparse('http://' + raw_url)
        has_explicit_scheme = False
    else:
        parsed = urlparse(raw_url)
        has_explicit_scheme = True

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    path = parsed.path
    query = parsed.query
    fragment = parsed.fragment
    
    # Extract domain and subdomain components
    host_only = netloc.split(':')[0]
    host_parts = [p for p in host_only.split('.') if p]
    
    tld = host_parts[-1] if len(host_parts) > 1 else ''
    domain = host_parts[-2] if len(host_parts) > 1 else (host_parts[0] if host_parts else '')
    subdomains = host_parts[:-2] if len(host_parts) > 2 else []
    
    # Feature 1: Length metrics
    url_length = len(raw_url)
    domain_length = len(host_only)
    path_length = len(path)
    query_length = len(query)

    # Feature 2: Character counts in full URL
    num_dots = raw_url.count('.')
    num_hyphens = raw_url.count('-')
    num_underscores = raw_url.count('_')
    num_slashes = raw_url.count('/')
    num_question_marks = raw_url.count('?')
    num_equals = raw_url.count('=')
    num_at_symbols = raw_url.count('@')
    num_ampersands = raw_url.count('&')
    num_percent = raw_url.count('%')
    num_digits = sum(c.isdigit() for c in raw_url)
    num_letters = sum(c.isalpha() for c in raw_url)
    digit_letter_ratio = (num_digits / max(num_letters, 1))
    
    # Feature 3: Host specific counts
    host_num_dots = host_only.count('.')
    host_num_hyphens = host_only.count('-')
    host_num_digits = sum(c.isdigit() for c in host_only)
    subdomain_count = len(subdomains)
    
    # Feature 4: Entropy
    url_entropy = calculate_entropy(raw_url)
    domain_entropy = calculate_entropy(host_only)
    
    # Feature 5: Security / Protocol features
    is_https = 1 if scheme == 'https' else 0
    has_ip = is_ip_address(host_only)
    has_port = 1 if parsed.port is not None else 0
    is_shortened = 1 if any(host_only == s or host_only.endswith('.' + s) for s in SHORTENER_DOMAINS) else 0
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    
    # Feature 6: Suspicious Keywords Count & Matches
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in raw_url.lower()]
    keyword_count = len(found_keywords)
    
    # Feature 7: Brand Impersonation in subdomain or path while not being official domain
    brand_impersonation = 0
    impersonated_brands = []
    for brand in TARGETED_BRANDS:
        if brand in raw_url.lower():
            # If brand is in url but the main registered domain is not exactly the brand
            if domain != brand:
                brand_impersonation = 1
                impersonated_brands.append(brand)
                
    # Feature 8: Suspicious formatting (e.g. // in path, @ in url, excessive subdomains)
    has_double_slash_path = 1 if '//' in path else 0
    has_hex_encoding = 1 if bool(re.search(r'%[0-9a-fA-F]{2}', raw_url)) else 0
    has_punycode = 1 if 'xn--' in host_only else 0
    consecutive_hyphens = 1 if '--' in raw_url else 0

    feature_dict = {
        'url_length': url_length,
        'domain_length': domain_length,
        'path_length': path_length,
        'query_length': query_length,
        'num_dots': num_dots,
        'num_hyphens': num_hyphens,
        'num_underscores': num_underscores,
        'num_slashes': num_slashes,
        'num_question_marks': num_question_marks,
        'num_equals': num_equals,
        'num_at_symbols': num_at_symbols,
        'num_ampersands': num_ampersands,
        'num_percent': num_percent,
        'num_digits': num_digits,
        'num_letters': num_letters,
        'digit_letter_ratio': float(digit_letter_ratio),
        'host_num_dots': host_num_dots,
        'host_num_hyphens': host_num_hyphens,
        'host_num_digits': host_num_digits,
        'subdomain_count': subdomain_count,
        'url_entropy': float(url_entropy),
        'domain_entropy': float(domain_entropy),
        'is_https': is_https,
        'has_ip': has_ip,
        'has_port': has_port,
        'is_shortened': is_shortened,
        'is_suspicious_tld': is_suspicious_tld,
        'keyword_count': keyword_count,
        'brand_impersonation': brand_impersonation,
        'has_double_slash_path': has_double_slash_path,
        'has_hex_encoding': has_hex_encoding,
        'has_punycode': has_punycode,
        'consecutive_hyphens': consecutive_hyphens,
    }

    metadata = {
        'raw_url': raw_url,
        'scheme': scheme,
        'hostname': host_only,
        'domain': domain,
        'tld': tld,
        'subdomains': subdomains,
        'found_keywords': found_keywords,
        'impersonated_brands': impersonated_brands,
        'has_explicit_scheme': has_explicit_scheme
    }

    return {
        'features': feature_dict,
        'metadata': metadata
    }


FEATURE_COLUMN_NAMES = [
    'url_length',
    'domain_length',
    'path_length',
    'query_length',
    'num_dots',
    'num_hyphens',
    'num_underscores',
    'num_slashes',
    'num_question_marks',
    'num_equals',
    'num_at_symbols',
    'num_ampersands',
    'num_percent',
    'num_digits',
    'num_letters',
    'digit_letter_ratio',
    'host_num_dots',
    'host_num_hyphens',
    'host_num_digits',
    'subdomain_count',
    'url_entropy',
    'domain_entropy',
    'is_https',
    'has_ip',
    'has_port',
    'is_shortened',
    'is_suspicious_tld',
    'keyword_count',
    'brand_impersonation',
    'has_double_slash_path',
    'has_hex_encoding',
    'has_punycode',
    'consecutive_hyphens'
]


def features_to_vector(feature_dict: dict) -> np.ndarray:
    """Convert feature dictionary to numpy feature vector in standard column order."""
    return np.array([feature_dict[col] for col in FEATURE_COLUMN_NAMES], dtype=np.float32).reshape(1, -1)
