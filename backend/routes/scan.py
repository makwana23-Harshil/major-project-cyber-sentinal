"""
Cyber Sentinel - Threat Scanning API Routes
"""

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models.scan_history import ScanHistory
from backend.schemas.scan import (
    URLScanRequest, EmailScanRequest, MessageScanRequest, TextScanRequest, ScanResponse
)
from backend.services.url_scanner import scan_url
from backend.services.text_scanner import scan_text_content
from backend.services.email_parser import parse_raw_email_bytes

router = APIRouter(prefix="/api/scan", tags=["Scanning"])


def save_scan_record(db: Session, result: dict) -> ScanHistory:
    """Helper to persist scan result into SQLite database."""
    record = ScanHistory(
        scan_type=result["scan_type"],
        input_preview=result["input_preview"],
        raw_input=result["raw_input"],
        prediction=result["prediction"],
        confidence=result["confidence"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        class_probabilities=result["class_probabilities"],
        indicators=result["indicators"],
        xai_data=result["xai_data"],
        metadata_info=result["metadata_info"]
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    return record


@router.post("/url", response_model=ScanResponse)
def api_scan_url(payload: URLScanRequest, db: Session = Depends(get_db)):
    """Scan and analyze a suspicious URL."""
    try:
        url = payload.url.strip()
        if not url:
            raise HTTPException(status_code=400, detail="URL cannot be empty")
        
        result = scan_url(url, deep_analysis=payload.deep_analysis)
        record = save_scan_record(db, result)
        
        res = record.to_dict()
        return res
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"URL scan failed: {str(e)}")


@router.post("/email", response_model=ScanResponse)
def api_scan_email(payload: EmailScanRequest, db: Session = Depends(get_db)):
    """Scan and analyze an Email content, subject, and sender."""
    try:
        if not payload.body.strip() and not payload.subject.strip():
            raise HTTPException(status_code=400, detail="Email body or subject must be provided")
            
        result = scan_text_content(
            text=payload.body,
            scan_type="email",
            subject=payload.subject,
            sender=payload.sender,
            recipient=payload.recipient
        )
        record = save_scan_record(db, result)
        return record.to_dict()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Email scan failed: {str(e)}")


@router.post("/message", response_model=ScanResponse)
def api_scan_message(payload: MessageScanRequest, db: Session = Depends(get_db)):
    """Scan and analyze an SMS / WhatsApp / chat message."""
    try:
        if not payload.message.strip():
            raise HTTPException(status_code=400, detail="Message cannot be empty")
            
        result = scan_text_content(
            text=payload.message,
            scan_type="message",
            sender=payload.sender_number
        )
        record = save_scan_record(db, result)
        return record.to_dict()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Message scan failed: {str(e)}")


@router.post("/text", response_model=ScanResponse)
def api_scan_text(payload: TextScanRequest, db: Session = Depends(get_db)):
    """Scan general suspicious text snippet."""
    try:
        if not payload.text.strip():
            raise HTTPException(status_code=400, detail="Text cannot be empty")
            
        result = scan_text_content(
            text=payload.text,
            scan_type="text"
        )
        record = save_scan_record(db, result)
        return record.to_dict()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Text scan failed: {str(e)}")


@router.post("/file", response_model=ScanResponse)
async def api_scan_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Scan uploaded .eml or .txt email file."""
    try:
        filename = file.filename or "uploaded_file.txt"
        contents = await file.read()
        
        if filename.endswith(".eml") or b"Received:" in contents[:1000] or b"From:" in contents[:1000]:
            parsed = parse_raw_email_bytes(contents)
            result = scan_text_content(
                text=parsed["body"],
                scan_type="email",
                subject=parsed["subject"],
                sender=parsed["sender"],
                recipient=parsed["recipient"],
                attachments=parsed["attachments"]
            )
        else:
            text = contents.decode("utf-8", errors="ignore")
            result = scan_text_content(
                text=text,
                scan_type="text"
            )
            
        record = save_scan_record(db, result)
        return record.to_dict()
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"File scan failed: {str(e)}")
