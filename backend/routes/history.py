"""
Cyber Sentinel - Threat History API Routes
Provides paginated query, search, filtering, and export capabilities.
"""

import csv
import io
import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_
from backend.database import get_db
from backend.models.scan_history import ScanHistory
from backend.schemas.scan import HistoryListResponse, ScanResponse

router = APIRouter(prefix="/api/history", tags=["History"])


@router.get("", response_model=HistoryListResponse)
def get_history_records(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    page_size: int = Query(15, ge=1, le=100),
    search: Optional[str] = Query(None),
    scan_type: Optional[str] = Query(None),
    prediction: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None)
):
    """Retrieve filtered scan history with pagination."""
    query = db.query(ScanHistory)

    if search:
        search_fmt = f"%{search.strip()}%"
        query = query.filter(
            or_(
                ScanHistory.input_preview.ilike(search_fmt),
                ScanHistory.raw_input.ilike(search_fmt),
                ScanHistory.prediction.ilike(search_fmt)
            )
        )

    if scan_type and scan_type != "all":
        query = query.filter(ScanHistory.scan_type == scan_type.lower())

    if prediction and prediction != "all":
        query = query.filter(ScanHistory.prediction.ilike(f"%{prediction}%"))

    if risk_level and risk_level != "all":
        query = query.filter(ScanHistory.risk_level == risk_level.upper())

    total = query.count()
    offset = (page - 1) * page_size
    records = query.order_by(desc(ScanHistory.created_at)).offset(offset).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "scans": [r.to_dict() for r in records]
    }


@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_detail(scan_id: str, db: Session = Depends(get_db)):
    """Retrieve full details of a specific scan by ID."""
    record = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    return record.to_dict()


@router.delete("/{scan_id}")
def delete_scan_record(scan_id: str, db: Session = Depends(get_db)):
    """Delete a single scan record."""
    record = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Scan record not found")
    db.delete(record)
    db.commit()
    return {"status": "success", "message": f"Scan {scan_id} deleted successfully"}


@router.post("/clear")
def clear_all_history(db: Session = Depends(get_db)):
    """Clear all records from scan history table."""
    count = db.query(ScanHistory).delete()
    db.commit()
    return {"status": "success", "message": f"Cleared {count} scan records"}


@router.get("/export/csv")
def export_history_csv(db: Session = Depends(get_db)):
    """Export threat history log as a CSV spreadsheet."""
    records = db.query(ScanHistory).order_by(desc(ScanHistory.created_at)).all()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Scan ID", "Timestamp", "Type", "Input Preview", "Prediction", "Confidence (%)", "Risk Score (0-100)", "Risk Level", "Threat Indicators"])
    
    for r in records:
        indicators_str = "; ".join(r.indicators or [])
        writer.writerow([
            r.id,
            r.created_at.strftime("%Y-%m-%d %H:%M:%S") if r.created_at else "",
            r.scan_type,
            r.input_preview,
            r.prediction,
            f"{r.confidence:.1f}",
            f"{r.risk_score:.1f}",
            r.risk_level,
            indicators_str
        ])
        
    response = Response(content=output.getvalue(), media_type="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=cyber_sentinel_threat_history.csv"
    return response


@router.get("/export/json")
def export_history_json(db: Session = Depends(get_db)):
    """Export complete threat history as JSON."""
    records = db.query(ScanHistory).order_by(desc(ScanHistory.created_at)).all()
    data = [r.to_dict() for r in records]
    
    response = Response(content=json.dumps(data, indent=2), media_type="application/json")
    response.headers["Content-Disposition"] = "attachment; filename=cyber_sentinel_threat_history.json"
    return response
