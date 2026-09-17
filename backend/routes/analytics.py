"""
Cyber Sentinel - Threat Intelligence & Analytics API Routes
"""

from collections import Counter
from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.database import get_db
from backend.models.scan_history import ScanHistory
from backend.schemas.scan import AnalyticsResponse

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])


@router.get("", response_model=AnalyticsResponse)
def get_security_analytics(db: Session = Depends(get_db)):
    """Compute aggregate analytics, threat trends, and detection metrics."""
    records = db.query(ScanHistory).order_by(desc(ScanHistory.created_at)).all()
    
    total = len(records)
    safe_count = 0
    suspicious_count = 0
    malicious_count = 0
    total_risk_score = 0.0
    
    vector_dist = {"url": 0, "email": 0, "message": 0, "text": 0}
    risk_dist = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    
    all_indicators = []
    
    # Initialize daily trends map for past 7 days
    today = datetime.now(timezone.utc).date()
    daily_map = {}
    for i in range(6, -1, -1):
        d_str = (today - timedelta(days=i)).strftime("%b %d")
        daily_map[d_str] = {"date": d_str, "safe": 0, "suspicious": 0, "malicious": 0, "total": 0}
        
    for r in records:
        pred = r.prediction.lower()
        if "safe" in pred or "real" in pred:
            safe_count += 1
            cat = "safe"
        elif "suspicious" in pred:
            suspicious_count += 1
            cat = "suspicious"
        else:
            malicious_count += 1
            cat = "malicious"
            
        total_risk_score += r.risk_score
        
        stype = (r.scan_type or "url").lower()
        vector_dist[stype] = vector_dist.get(stype, 0) + 1
        
        rlevel = (r.risk_level or "LOW").upper()
        risk_dist[rlevel] = risk_dist.get(rlevel, 0) + 1
        
        if r.indicators:
            for ind in r.indicators:
                # Strip long details to group by core category
                short_ind = ind.split(":")[0] if ":" in ind else ind
                all_indicators.append(short_ind)
                
        # Group into daily map
        if r.created_at:
            d_str = r.created_at.strftime("%b %d")
            if d_str in daily_map:
                daily_map[d_str][cat] += 1
                daily_map[d_str]["total"] += 1

    detection_rate = round(((suspicious_count + malicious_count) / max(total, 1)) * 100, 1)
    avg_risk = round(total_risk_score / max(total, 1), 1)
    
    # Top 8 indicators
    ind_counter = Counter(all_indicators)
    top_indicators = [
        {"indicator": k, "count": v}
        for k, v in ind_counter.most_common(8)
    ]
    
    recent_activity = [r.to_dict() for r in records[:6]]
    daily_trends = list(daily_map.values())
    
    return {
        "total_scans": total,
        "safe_scans": safe_count,
        "suspicious_scans": suspicious_count,
        "malicious_scans": malicious_count,
        "detection_rate": detection_rate,
        "avg_risk_score": avg_risk,
        "vector_distribution": vector_dist,
        "risk_level_distribution": risk_dist,
        "recent_activity": recent_activity,
        "top_indicators": top_indicators,
        "daily_trends": daily_trends
    }
