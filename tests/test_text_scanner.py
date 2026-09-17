"""
Unit tests for Text / Email / SMS Scanner and XAI
"""

import unittest
from backend.services.text_scanner import scan_text_content
from backend.services.rule_engine import analyze_social_engineering


class TestTextScanner(unittest.TestCase):

    def test_safe_transaction_otp(self):
        text = "Your OTP for the transaction is 482913. Do not share this OTP with anyone. Reference ID: 938491."
        res = scan_text_content(text=text, scan_type="message")
        self.assertEqual(res['prediction'], "Real / Safe")
        self.assertLessEqual(res['risk_score'], 35.0)

    def test_urgent_account_lock_smishing(self):
        text = "URGENT! Your bank account will be blocked today. Verify your identity immediately using http://bank-update.tk"
        res = scan_text_content(text=text, scan_type="message")
        self.assertEqual(res['prediction'], "Fake / Malicious")
        self.assertGreaterEqual(res['risk_score'], 60.0)
        self.assertIn("highlighted_html", res['xai_data'])

    def test_spoofed_email_detection(self):
        subject = "URGENT: Verify Your PayPal Account"
        sender = '"PayPal Security" <support@hacker-server.xyz>'
        body = "Your account has been suspended. Enter your password immediately at http://paypal-verify.xyz/auth"
        res = scan_text_content(text=body, scan_type="email", subject=subject, sender=sender)
        self.assertEqual(res['prediction'], "Fake / Malicious")
        self.assertGreaterEqual(res['risk_score'], 75.0)
        self.assertIn("Sender Domain Mismatch", str(res['indicators']))


if __name__ == "__main__":
    unittest.main()
