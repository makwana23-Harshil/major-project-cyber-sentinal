"""
Cyber Sentinel - Dataset Generator
Generates realistic, diverse, balanced datasets for URL phishing and Text/Email/SMS threat classification.
"""

import os
import random
import pandas as pd

# Fix random seed for reproducibility
random.seed(42)

def generate_url_dataset() -> pd.DataFrame:
    """
    Generate balanced URL dataset of Benign (label=0) and Phishing/Malicious (label=1) URLs.
    """
    benign_domains = [
        "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
        "yahoo.com", "reddit.com", "netflix.com", "linkedin.com", "microsoft.com",
        "instagram.com", "twitter.com", "github.com", "apple.com", "chase.com",
        "paypal.com", "bankofamerica.com", "wellsfargo.com", "ebay.com", "stackoverflow.com",
        "cnn.com", "nytimes.com", "bbc.co.uk", "cloudflare.com", "medium.com",
        "spotify.com", "salesforce.com", "dropbox.com", "quora.com", "zoom.us",
        "nih.gov", "harvard.edu", "mit.edu", "stanford.edu", "nasa.gov",
        "irs.gov", "who.int", "cdc.gov", "gitlab.com", "bitbucket.org",
        "coursera.org", "udemy.com", "khanacademy.org", "edx.org", "adobe.com",
        "airbnb.com", "booking.com", "uber.com", "lyft.com", "stripe.com",
        "docker.com", "kubernetes.io", "python.org", "nodejs.org", "npmjs.com",
        "pypi.org", "mozilla.org", "w3schools.com", "developer.mozilla.org", "slack.com"
    ]
    
    benign_paths = [
        "", "/home", "/about", "/contact", "/docs", "/api/v1/users", "/dashboard/overview",
        "/search?q=machine+learning", "/articles/2026/cybersecurity-trends", "/product/item-84920",
        "/categories/electronics", "/help/faq", "/terms-of-service", "/privacy-policy",
        "/blog/introducing-new-features", "/feed", "/profile/settings", "/download/latest",
        "/pricing/plans", "/solutions/enterprise", "/community/discussions", "/explore/popular",
        "/events/2026-summit", "/press-release/announcement", "/careers/openings", "/status"
    ]
    
    # Generate 1500+ Benign URLs
    benign_urls = []
    for _ in range(1600):
        domain = random.choice(benign_domains)
        path = random.choice(benign_paths)
        scheme = "https://" if random.random() > 0.1 else "http://"
        sub = "www." if random.random() > 0.4 else ("api." if random.random() > 0.7 else "")
        benign_urls.append(f"{scheme}{sub}{domain}{path}")
        
    # Phishing / Malicious patterns
    phish_brands = ["paypal", "apple", "chase", "netflix", "wellsfargo", "microsoft", "google", "amazon", "bankofamerica", "binance", "coinbase", "metamask", "secure-bank"]
    phish_keywords = ["login", "verify", "secure", "update", "account", "suspended", "confirm", "auth", "billing", "recovery", "unlock", "kyc", "alert", "session-expired"]
    phish_tlds = ["tk", "xyz", "top", "ru", "click", "fit", "gq", "work", "loan", "cam", "live", "icu", "party", "buzz", "ml"]
    
    malicious_urls = []
    
    # 1. Typosquatting and brand impersonation in subdomain/domain
    for _ in range(500):
        brand = random.choice(phish_brands)
        kw1 = random.choice(phish_keywords)
        kw2 = random.choice(phish_keywords)
        tld = random.choice(phish_tlds)
        sub = f"{brand}-{kw1}" if random.random() > 0.5 else f"{kw1}.{brand}"
        path = f"/{kw2}/index.php?token={random.randint(10000, 99999)}"
        malicious_urls.append(f"http://{sub}-security-update.{tld}{path}")
        
    # 2. IP address based phishing URLs
    for _ in range(400):
        ip = f"{random.randint(45, 218)}.{random.randint(10, 250)}.{random.randint(1, 254)}.{random.randint(2, 254)}"
        brand = random.choice(phish_brands)
        kw = random.choice(phish_keywords)
        port = f":{random.choice([8080, 8000, 8443, 3000])}" if random.random() > 0.6 else ""
        path = f"/{brand}/{kw}/verification.html"
        malicious_urls.append(f"http://{ip}{port}{path}")
        
    # 3. Excessive subdomains & deceptive hyphen chains
    for _ in range(400):
        brand = random.choice(phish_brands)
        kw1 = random.choice(phish_keywords)
        kw2 = random.choice(phish_keywords)
        tld = random.choice(phish_tlds)
        sub = f"{brand}.com.{kw1}-portal.{kw2}-service"
        malicious_urls.append(f"http://{sub}.verify-security.{tld}/auth/login.php?client_id={random.randint(100000, 999999)}")
        
    # 4. Hex encoding / @ redirects / double slashes
    for _ in range(300):
        brand = random.choice(phish_brands)
        kw = random.choice(phish_keywords)
        tld = random.choice(phish_tlds)
        if random.random() > 0.5:
            malicious_urls.append(f"http://legit-site.com@{brand}-secure-check.{tld}/login")
        else:
            malicious_urls.append(f"http://{brand}-{kw}.{tld}/webscr//cmd=login%20verify%20session")

    # Construct DataFrame
    data = []
    for u in benign_urls:
        data.append({"url": u, "label": 0})
    for u in malicious_urls:
        data.append({"url": u, "label": 1})
        
    df = pd.DataFrame(data).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


def generate_text_dataset() -> pd.DataFrame:
    """
    Generate balanced dataset of Legitimate (label=0) vs Phishing/Social Engineering/Smishing (label=1) texts.
    """
    safe_templates = [
        "Hi Team, please find attached the meeting minutes and agenda for our weekly sprint review on Tuesday.",
        "Your Amazon package with order ID #9384729 has been delivered to your front porch. Thank you for shopping with us.",
        "Your one-time verification code for GitHub is 849201. This code expires in 10 minutes. Never share this code with anyone.",
        "Reminder: Doctor appointment scheduled for tomorrow at 3:00 PM with Dr. Sharma. Reply RESCHEDULE if you need to change.",
        "Dear customer, your electricity bill of $84.50 for the month of August has been paid successfully. Receipt #93840.",
        "Hey! Are you free for lunch today at the cafeteria around 1:00 PM?",
        "Your flight ticket for AI-302 to San Francisco is confirmed. Terminal 3, Gate 42. Check-in opens 24 hours prior.",
        "Thank you for subscribing to The Daily Tech Newsletter. Here is your summary of top cybersecurity articles for this week.",
        "Your Uber driver is arriving in a Silver Toyota Camry (License: 7XYZ89). Please meet them at the pickup point.",
        "The project repository pull request #142 'Fix memory leak in buffer pool' has been merged into main.",
        "Netflix: We have updated our Terms of Use to better explain how our recommendations work. No action required.",
        "Your Google Calendar reminder: Team Retrospective starts in 15 minutes in Room B2.",
        "Your bank statement for the period ending August 2026 is now available to download inside your official banking mobile app.",
        "Security Alert: A new sign-in was detected on your Windows PC from Chrome browser. If this was you, you can ignore this alert.",
        "Hey, can you please review the slides for tomorrow's presentation and let me know if any numbers need updating?",
        "Hi John, hope you had a great weekend. Let's touch base regarding the Q3 roadmap after the standup meeting.",
        "Your Swiggy order has been picked up and is on its way. Estimated arrival time: 25 minutes.",
        "Dear Student, the semester exam schedule has been published on the university portal. Please verify your subject codes.",
        "Spotify: Your Weekly Discover playlist is ready with 30 fresh tracks based on your recent listening history.",
        "Hi, just following up on the invoice #8392. Could your finance department confirm receipt of the payment?"
    ]
    
    malicious_templates = [
        "URGENT: Your Bank of America checking account has been SUSPENDED due to suspicious activity. Verify identity immediately at http://bankofamerica-verify-session.tk/auth to restore access or account will be permanently closed.",
        "ALERT: Your Wells Fargo debit card has been locked! Unauthorized transaction of $1,429.00 detected. Click here immediately to cancel the charge: http://192.168.1.50/wellsfargo/cancel-tx",
        "Dear PayPal User, We detected an unauthorized login attempt from Russia. Your account is temporarily restricted. Update your password and credit card details now: http://paypal-resolution-center.xyz/login",
        "FINAL NOTICE: IRS Tax Refund of $3,850.00 is pending. You have 24 hours to confirm your Social Security Number and direct deposit bank details to receive funds: http://irs-refund-portal.click/claim",
        "Netflix Warning: Your monthly subscription payment failed and your account is scheduled for cancellation today. Update your billing credit card details immediately: http://netflix-billing-update.top/account",
        "SECURITY ALERT: Someone accessed your Apple ID from an unknown device in Nigeria. If this was not you, verify your identity and enter your OTP immediately at http://appleid-support-security.xyz",
        "CONGRATULATIONS! You have won $1,000,000 in the International Mobile Lottery. Send your full name, bank account number, and OTP to claim prize money immediately.",
        "URGENT! CEO Request: I am currently in a confidential client meeting and need you to urgently wire $45,000 to our vendor or purchase 10 Apple Gift Cards immediately for client gifts. Do not call me.",
        "Chase Bank Alert: A wire transfer of $5,000 was initiated from your account. If you did NOT authorize this, click here immediately to stop transfer: http://chase-security-fraud-alert.ml/block",
        "SMS Warning: Your package cannot be delivered due to missing house number and an unpaid customs fee of $2.99. Pay and update address within 12 hours: http://usps-parcel-tracking-fee.click/redelivery",
        "Your WhatsApp account will be deleted within 24 hours due to violation of service terms. Confirm your phone number and security pin here: http://whatsapp-verification-service.tk",
        "HR Department Alert: All employees must review the mandatory updated salary and bonus schedule for 2026. Enter your corporate network login and password: http://corporate-payroll-login.xyz",
        "URGENT NOTICE from IT Helpdesk: Your Office 365 mailbox is 99% full and will stop receiving emails today. Click here to upgrade storage and re-authenticate your password immediately: http://office365-helpdesk-upgrade.top",
        "Amazon Fraud Dept: We placed a hold on your order #849204 (MacBook Pro $2,399). Call 1-800-FAKE-NUM or click http://amazon-security-orders.xyz to verify your credit card immediately.",
        "Cryptocurrency Alert: MetaMask wallet security compromise detected. Sync your 12-word secret recovery seed phrase immediately to avoid loss of funds: http://metamask-seed-validation.xyz",
        "ALERT: Your SIM card is being swapped by an unauthorized user. Enter the OTP sent to your phone right now on http://sim-swap-security.tk to cancel the request.",
        "You have received a direct deposit of $4,500.00. Click here to confirm your banking credentials and accept funds: http://instant-cash-transfer.xyz/accept",
        "Dear Customer, your KYC details have expired. Your bank account will be blocked by midnight. Complete e-KYC immediately by entering PAN and Aadhaar: http://online-kyc-update.tk",
        "Your Facebook account has been reported for copyright infringement. Submit an appeal within 24 hours or your profile will be permanently deleted: http://facebook-copyright-appeal.xyz",
        "Urgent Notice: Unpaid toll road bill of $6.50. Avoid late fees and vehicle registration suspension by paying now: http://toll-violation-payment.click/pay"
    ]
    
    data = []
    
    # Generate variations of Safe texts
    for _ in range(80):
        for template in safe_templates:
            noise = f" Reference ID: {random.randint(100000, 999999)}." if random.random() > 0.5 else ""
            data.append({"text": template + noise, "label": 0})
            
    # Generate variations of Malicious texts
    for _ in range(80):
        for template in malicious_templates:
            noise = f" Case Ticket #{random.randint(10000, 99999)}." if random.random() > 0.5 else ""
            data.append({"text": template + noise, "label": 1})
            
    df = pd.DataFrame(data).sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


if __name__ == "__main__":
    os.makedirs("ml/datasets", exist_ok=True)
    url_df = generate_url_dataset()
    url_df.to_csv("ml/datasets/url_dataset.csv", index=False)
    print(f"[Dataset Generator] URL dataset generated: {len(url_df)} samples (Safe: {sum(url_df['label'] == 0)}, Malicious: {sum(url_df['label'] == 1)})")
    
    text_df = generate_text_dataset()
    text_df.to_csv("ml/datasets/text_dataset.csv", index=False)
    print(f"[Dataset Generator] Text dataset generated: {len(text_df)} samples (Safe: {sum(text_df['label'] == 0)}, Malicious: {sum(text_df['label'] == 1)})")
