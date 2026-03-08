"""
Alert Data Models
"""
from pydantic import BaseModel
from typing import Optional, List
from datetime import datetime

class Alert(BaseModel):
    """Alert model matching frontend format"""
    id: str                          # "ALERT-1001"
    timestamp: str                   # ISO format
    function: str                    # "paymentHandler"
    severity: str                    # "CRITICAL", "WARNING", "INFO"
    status: str                      # "OPEN", "CLOSED"
    anomaly_score: float             # 0.0 - 1.0
    features: dict                   # duration_ms, outbound_calls, etc.
    
class AlertDetail(Alert):
    """Extended alert with more details"""
    threat_type: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[List[str]] = None
    z_scores: Optional[dict] = None