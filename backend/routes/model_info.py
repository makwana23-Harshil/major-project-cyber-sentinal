"""
Cyber Sentinel - Model Performance & Explainability Metrics API Routes
"""

import os
import json
from fastapi import APIRouter, HTTPException
from backend.config import METRICS_PATH

router = APIRouter(prefix="/api/model", tags=["Model Evaluation"])


@router.get("/metrics")
def get_model_evaluation_metrics():
    """Retrieve real test-set performance metrics and confusion matrices."""
    if not os.path.exists(METRICS_PATH):
        raise HTTPException(status_code=404, detail="Model metrics file not found. Please train models first.")
    
    with open(METRICS_PATH, "r") as f:
        data = json.load(f)
        
    return data
