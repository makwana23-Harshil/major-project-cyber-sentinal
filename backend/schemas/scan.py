"""
Cyber Sentinel - Pydantic Request & Response Schemas
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# Request Schemas
class URLScanRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze", min_length=1)
    deep_analysis: Optional[bool] = Field(default=True, description="Perform deep feature analysis")


class EmailScanRequest(BaseModel):
    subject: Optional[str] = Field(default="", description="Email Subject")
    sender: Optional[str] = Field(default="", description="Sender Email Address / Display Name")
    body: str = Field(..., description="Email Body Content", min_length=1)
    recipient: Optional[str] = Field(default="", description="Recipient Email Address")


class MessageScanRequest(BaseModel):
    message: str = Field(..., description="SMS / WhatsApp / Direct Message text", min_length=1)
    sender_number: Optional[str] = Field(default="", description="Sender phone number or ID")


class TextScanRequest(BaseModel):
    text: str = Field(..., description="Suspicious text or document snippet to analyze", min_length=1)


# Response Schemas
class ScanResponse(BaseModel):
    id: str
    scan_type: str
    input_preview: str
    prediction: str
    confidence: float
    risk_score: float
    risk_level: str
    class_probabilities: Dict[str, float]
    indicators: List[str]
    xai_data: Dict[str, Any]
    metadata_info: Dict[str, Any]
    created_at: str


class HistoryListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    scans: List[ScanResponse]


class AnalyticsResponse(BaseModel):
    total_scans: int
    safe_scans: int
    suspicious_scans: int
    malicious_scans: int
    detection_rate: float
    avg_risk_score: float
    vector_distribution: Dict[str, int]
    risk_level_distribution: Dict[str, int]
    recent_activity: List[Dict[str, Any]]
    top_indicators: List[Dict[str, Any]]
    daily_trends: List[Dict[str, Any]]
