"""
Attack Signature Models — Cloud Sentinel
==========================================
Pydantic models for representing matched attack signatures
returned by the Layer 2 attack pattern matcher.
"""
 
from pydantic import BaseModel
from typing import Optional, List
 
 
class AttackIndicator(BaseModel):
    """A single piece of evidence that contributed to an attack match."""
    description: str             # Human-readable indicator, e.g. "High API call rate"
    severity: str                # "low", "medium", "high", "critical"
    value: Optional[str] = None  # The raw value that triggered this indicator
