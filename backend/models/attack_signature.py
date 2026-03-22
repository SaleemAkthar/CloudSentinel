"""
Attack Signature Models — Cloud Sentinel
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


class AttackSignature(BaseModel):
    """
    Represents a single matched attack pattern from Layer 2 analysis.
    Produced by attack_patterns.py and stored inside an alert's layer2_report.
    """
    attack_type: str                        # e.g. "ddos", "sql_injection", "crypto_mining"
    name: str                               # Human-readable name, e.g. "DDoS Attack"
    matched: bool                           # Whether this pattern was triggered
    confidence: float                       # Match confidence score: 0.0 – 1.0
    indicators: List[str]                   # List of indicator descriptions
    details: dict                           # Raw pattern-specific detail fields


class AttackSignatureSummary(BaseModel):
    """
    Summary of all pattern matches for a single Layer 2 scan.
    Stored as the 'patterns' block inside a layer2_report.
    """
    matched_patterns: List[AttackSignature]         # All patterns that matched (matched=True)
    top_threat: Optional[AttackSignature] = None    # Highest-confidence matched pattern
    total_matched: int                              # Number of patterns that fired
    total_checked: int                              # Total patterns evaluated
