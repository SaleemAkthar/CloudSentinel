"""
AI Insights Data Models
"""
from pydantic import BaseModel
from typing import Optional, List

class InsightCard(BaseModel):
    """Individual insight card"""
    title: str
    severity: str                    # "high", "medium", "info"
    description: str
    confidence: float
    action: str
    timestamp: str