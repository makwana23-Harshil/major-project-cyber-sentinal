"""
Cyber Sentinel - Email Parser & Attachment Analyzer
Parses standard emails, raw headers, .eml files, extracts embedded links,
detects sender/domain spoofing, and audits attachment security.
"""

import re
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List

DANGEROUS_EXTENSIONS = {
    'exe', 'vbs', 'scr', 'bat', 'cmd', 'ps1', 'jar', 'iso', 'img',
    'hta', 'dll', 'pif', 'wsf', 'reg', 'chm', 'cpl', 'msp', 'hta'
}

SUSPICIOUS_ARCHIVE_EXTS = {'zip', 'rar', '7z', 'tar', 'gz', 'iso'}


def extract_urls_from_text(text: str) -> List[str]:
    """Extract all HTTP/HTTPS and www URLs from plain text or HTML."""
    if not text:
        return []
    url_pattern = r'(https?://[^\s<>"\')]+|www\.[^\s<>"\')]+)'
    matches = re.findall(url_pattern, text)
    # Deduplicate while preserving order
    seen = set()
    cleaned = []
    for m in matches:
        # Strip trailing punctuation
        m_clean = m.rstrip('.,;:)]>')
        if m_clean and m_clean not in seen:
            seen.add(m_clean)
            cleaned.append(m_clean)
    return cleaned


def parse_raw_email_bytes(raw_bytes: bytes) -> Dict[str, Any]:
    """Parse raw bytes of an .eml file into structured metadata."""
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    
    subject = msg.get('subject', '')
    sender = msg.get('from', '')
    recipient = msg.get('to', '')
    date = msg.get('date', '')
    
    body_parts = []
    attachments = []
    
    for part in msg.walk():
        content_type = part.get_content_type()
        content_disposition = str(part.get_content_disposition() or '')
        
        if 'attachment' in content_disposition:
            filename = part.get_filename() or 'unknown_attachment'
            size = len(part.get_payload(decode=True) or b'')
            attachments.append({"filename": filename, "size_bytes": size, "content_type": content_type})
        elif content_type in ['text/plain', 'text/html']:
            try:
                payload = part.get_payload(decode=True)
                if payload:
                    body_parts.append(payload.decode('utf-8', errors='ignore'))
            except Exception:
                pass
                
    full_body = "\n".join(body_parts) if body_parts else str(msg.get_body() or '')
    
    return {
        "subject": subject,
        "sender": sender,
        "recipient": recipient,
        "date": date,
        "body": full_body,
        "attachments": attachments
    }


def analyze_sender_spoofing(sender: str) -> Dict[str, Any]:
    """
    Analyze if sender header exhibits display-name spoofing.
    Example: '"PayPal Support" <attacker@hacker-domain.xyz>'
    """
    if not sender:
        return {"spoofing_detected": False, "reason": "No sender specified"}
        
    sender_clean = sender.strip()
    # Match pattern: Display Name <email@domain.com>
    match = re.match(r'^(?:"?([^"<]+)"?\s*)?<([^>]+)>$', sender_clean)
    if not match:
        return {"spoofing_detected": False, "display_name": "", "email": sender_clean}
        
    display_name = (match.group(1) or "").strip().lower()
    actual_email = (match.group(2) or "").strip().lower()
    
    email_domain = actual_email.split('@')[-1] if '@' in actual_email else ''
    
    suspicious_brands = ['paypal', 'apple', 'microsoft', 'google', 'netflix', 'amazon', 'chase', 'wellsfargo', 'bank', 'support', 'security']
    
    for brand in suspicious_brands:
        if brand in display_name and brand not in email_domain:
            return {
                "spoofing_detected": True,
                "display_name": display_name,
                "actual_email": actual_email,
                "email_domain": email_domain,
                "reason": f"Display name impersonates '{brand.upper()}' but actual sending domain is '{email_domain}'"
            }
            
    return {
        "spoofing_detected": False,
        "display_name": display_name,
        "actual_email": actual_email,
        "email_domain": email_domain
    }


def audit_attachments(attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Audit attached files for dangerous malware vectors."""
    dangerous = []
    suspicious = []
    
    for att in attachments:
        fname = att.get('filename', '').lower()
        parts = fname.split('.')
        ext = parts[-1] if len(parts) > 1 else ''
        
        # Check double extensions (e.g. invoice.pdf.exe)
        if len(parts) > 2:
            suspicious.append(f"Double extension detected in attachment '{fname}'")
            
        if ext in DANGEROUS_EXTENSIONS:
            dangerous.append(f"High-Risk Executable/Script payload: '{fname}' (.{ext})")
        elif ext in SUSPICIOUS_ARCHIVE_EXTS:
            suspicious.append(f"Archive file: '{fname}' (May contain hidden scripts)")
            
    return {
        "has_dangerous": len(dangerous) > 0,
        "dangerous_files": dangerous,
        "suspicious_files": suspicious
    }
