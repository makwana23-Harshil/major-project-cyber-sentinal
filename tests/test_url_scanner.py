"""
Unit tests for URL Feature Extraction and URL Scanner
"""

import unittest
from ml.feature_extraction.url_features import extract_url_features
from backend.services.url_scanner import scan_url


class TestURLScanner(unittest.TestCase):

    def test_safe_url_extraction(self):
        url = "https://www.google.com/search?q=cybersecurity"
        res = extract_url_features(url)
        features = res['features']
        self.assertEqual(features['is_https'], 1)
        self.assertEqual(features['has_ip'], 0)
        self.assertEqual(features['is_suspicious_tld'], 0)
        self.assertEqual(features['brand_impersonation'], 0)

    def test_ip_based_malicious_url(self):
        url = "http://192.168.1.50/login-bank-verify"
        res = scan_url(url)
        self.assertEqual(res['prediction'], "Fake / Malicious")
        self.assertGreater(res['risk_score'], 60.0)
        self.assertIn("IP Address", str(res['indicators']))

    def test_brand_impersonation_url(self):
        url = "http://paypal-security-update.account-verification.tk/login.php"
        res = scan_url(url)
        self.assertEqual(res['prediction'], "Fake / Malicious")
        self.assertGreater(res['risk_score'], 70.0)
        self.assertIn("Brand Impersonation", str(res['indicators']))


if __name__ == "__main__":
    unittest.main()
