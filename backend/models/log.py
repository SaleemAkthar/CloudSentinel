"""
Log Data Models
"""
from pydantic import BaseModel
from typing import Optional

class Log(BaseModel):
    """Log model for Behaviour Logs page"""
    timestamp: str
    function: str
    event: str                       # Event description
    user: str
    ip_address: str
    status: str                      # "success", "failed", "blocked", "throttled"
    duration: str                    # e.g., "245ms"