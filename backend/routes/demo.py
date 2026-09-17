"""
Cyber Sentinel - Demo Presets API Route
Provides synthetic test cases for demonstrations and interactive testing.
"""

from fastapi import APIRouter

router = APIRouter(prefix="/api/demo", tags=["Demo"])

DEMO_SAMPLES = [
    {
        "id": "demo-safe-url",
        "category": "URL",
        "title": "Legitimate Enterprise Portal",
        "type": "url",
        "data": {
            "url": "https://www.google.com"
        },
        "description": "Standard HTTPS domain with clean DNS reputation and no structural anomalies."
    },
    {
        "id": "demo-malicious-url-1",
        "category": "URL",
        "title": "IP-Based Phishing Kit",
        "type": "url",
        "data": {
            "url": "http://192.168.1.50/login-bank-verify?token=9482&session=auth"
        },
        "description": "Numeric IP address host, unencrypted HTTP, with credential harvesting keywords."
    },
    {
        "id": "demo-malicious-url-2",
        "category": "URL",
        "title": "Brand Impersonation & Suspicious TLD",
        "type": "url",
        "data": {
            "url": "http://paypal-security-update.account-verification.tk/login.php"
        },
        "description": "Targets PayPal brand on a .tk disposable domain with multiple deceptive subdomains."
    },
    {
        "id": "demo-safe-email",
        "category": "Email",
        "title": "Legitimate Project Status Update",
        "type": "email",
        "data": {
            "subject": "Sprint Retrospective Meeting - Agenda and Action Items",
            "sender": "David Miller <david.miller@company.org>",
            "body": "Hi Team,\n\nPlease find the agenda for our weekly sprint retrospective scheduled for tomorrow at 2:00 PM in Conference Room A.\n\nKey topics:\n1. Q3 Roadmap Review\n2. CI/CD Pipeline optimization\n3. Feature deliverables\n\nBest regards,\nDavid Miller"
        },
        "description": "Normal professional communication with standard conversational tone."
    },
    {
        "id": "demo-phishing-email",
        "category": "Email",
        "title": "Urgent Bank Account Suspension Phishing",
        "type": "email",
        "data": {
            "subject": "URGENT ACTION REQUIRED: Your Chase Account Has Been Restricted!",
            "sender": '"Chase Security Alerts" <security@chase-fraud-prevention.xyz>',
            "body": "DEAR VALUED CUSTOMER,\n\nWe detected unauthorized login attempts to your Chase online banking from an unrecognized IP address in Russia.\n\nYour account has been temporarily LOCKED to prevent fraudulent money transfers. You must verify your credentials within 12 hours or your account will be permanently deactivated.\n\nClick the link below immediately to restore your account:\nhttp://chase-security-verify.xyz/auth/login.php\n\nChase Fraud Prevention Department"
        },
        "description": "Display name spoofing, urgent coercive threats, and phishing link on .xyz TLD."
    },
    {
        "id": "demo-safe-sms",
        "category": "Message",
        "title": "Legitimate Banking Transaction OTP",
        "type": "message",
        "data": {
            "message": "Your OTP for transaction of $45.00 at Target is 482913. Valid for 10 minutes. Do not share this OTP with anyone. Reference ID: 938491."
        },
        "description": "Authentic transactional OTP warning users NOT to disclose codes."
    },
    {
        "id": "demo-smishing-sms",
        "category": "Message",
        "title": "Smishing Panic Bank Block Attack",
        "type": "message",
        "data": {
            "message": "URGENT! Your bank account will be blocked by midnight due to pending e-KYC. Verify your identity immediately at http://online-kyc-bank.tk or call customer support."
        },
        "description": "SMS smishing attack deploying urgent panic pressure and malicious link."
    },
    {
        "id": "demo-ceo-fraud",
        "category": "Text",
        "title": "Executive Wire Extortion / CEO Fraud",
        "type": "text",
        "data": {
            "text": "CONFIDENTIAL: I am currently in an urgent board meeting with overseas investors and cannot answer calls. We need to process an immediate wire transfer of $38,500 for our foreign vendor settlement today. Please initiate this transfer right now and reply with confirmation receipt."
        },
        "description": "Social engineering pressure impersonating executive authority."
    }
]


@router.get("/samples")
def get_demo_samples():
    """Retrieve demo sample test cases."""
    return DEMO_SAMPLES
