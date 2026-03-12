"""
Data Models for Weighted Anomaly Scoring
=========================================

Pydantic models for type-safe anomaly scoring results.

Author: Raneesha (Backend Team)
Date: 2026-03-12
"""

from pydantic import BaseModel, Field, field_validator
from typing import Dict, Optional, List
from datetime import datetime
  

# ============================================================================
# COMPONENT SCORE MODELS
# ============================================================================

class FeatureScore(BaseModel):
    """
    Feature-based anomaly score details
    
    Contains Z-scores for each feature and weighted composite
    """
    z_scores: Dict[str, float] = Field(
        description="Z-score for each feature (duration, memory, etc.)"
    )
    weighted_sum: float = Field(
        ge=0.0,
        description="Sum of weighted squared Z-scores"
    )
    total_weight: float = Field(
        ge=0.0, le=1.0,
        description="Total weight applied"
    )
    raw_score: float = Field(
        ge=0.0,
        description="Unnormalized weighted score"
    )
    normalized_score: float = Field(
        ge=0.0, le=1.0,
        description="Normalized feature anomaly score (0-1)"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "z_scores": {
                    "duration": 633.33,
                    "memory_used": 160.0,
                    "num_api_calls": 2.0
                },
                "weighted_sum": 197478.0,
                "total_weight": 0.85,
                "raw_score": 232327.0,
                "normalized_score": 1.0
            }
        }


class PacketScore(BaseModel):
    """
    Packet-level anomaly score details
    """
    latency_component: float = Field(ge=0.0, le=1.0)
    size_component: float = Field(ge=0.0, le=1.0)
    size_ratio: float = Field(ge=0.0, description="Outbound/inbound ratio")
    fragmentation_component: float = Field(ge=0.0, le=1.0)
    fragment_count: int = Field(ge=0)
    packet_anomaly_score: float = Field(ge=0.0, le=1.0)
    
    class Config:
        json_schema_extra = {
            "example": {
                "latency_component": 0.15,
                "size_component": 0.80,
                "size_ratio": 20.0,
                "fragmentation_component": 0.30,
                "fragment_count": 3,
                "packet_anomaly_score": 0.82
            }
        }


class TemporalScore(BaseModel):
    """
    Temporal (time-based) anomaly score details
    """
    actual_value: float
    predicted_value: float
    prediction_std: float
    temporal_z_score: float = Field(ge=0.0)
    temporal_anomaly_score: float = Field(ge=0.0, le=1.0)
    sarima_available: bool = Field(
        default=False,
        description="Whether SARIMA forecasting is available"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "actual_value": 850.0,
                "predicted_value": 500.0,
                "prediction_std": 50.0,
                "temporal_z_score": 7.0,
                "temporal_anomaly_score": 1.0,
                "sarima_available": True
            }
        }

class BehavioralScore(BaseModel):
    """
    Behavioral (attack pattern) anomaly score details
    """
    behavioral_score: float = Field(ge=0.0, le=1.0)
    attack_type: str = Field(description="Detected attack type or 'unknown'")
    attack_confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in attack classification"
    )
    matched_patterns: List[str] = Field(
        default_factory=list,
        description="List of matched attack patterns"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "behavioral_score": 0.95,
                "attack_type": "crypto_mining",
                "attack_confidence": 0.98,
                "matched_patterns": ["high_duration", "high_memory"]
            }
        }

# ============================================================================
# COMPOSITE SCORE MODEL
# ============================================================================

class CompositeScore(BaseModel):
    """
    Complete weighted composite anomaly score
    
    Combines all detection layers into final score
    """
    # Individual component scores
    feature_score: float = Field(ge=0.0, le=1.0)
    packet_score: float = Field(ge=0.0, le=1.0)
    temporal_score: float = Field(ge=0.0, le=1.0)
    behavioral_score: float = Field(ge=0.0, le=1.0)
    
    # Final composite
    composite_score: float = Field(
        ge=0.0, le=1.0,
        description="Weighted average of all component scores"
    )
    
    # Metadata
    confidence: float = Field(
        ge=0.0, le=1.0,
        description="Confidence in detection (based on component agreement)"
    )
    severity: Optional[str] = Field(
        default=None,
        description="Severity level: CRITICAL, HIGH, MEDIUM, or None"
    )
    is_anomaly: bool = Field(
        description="Whether composite score exceeds minimum threshold (0.4)"
    )
    
    # Component weights used
    weights_applied: Dict[str, float] = Field(
        description="Weights used in composite calculation"
    )
    
    # Timestamp
    timestamp: str = Field(
        default_factory=lambda: datetime.now().isoformat(),
        description="When score was calculated"
    )
    
    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        """Ensure severity is valid (3 levels only)"""
        if v is None:
            return v
        
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM']
        if v not in valid_severities:
            raise ValueError(f"Severity must be one of {valid_severities} or None")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "feature_score": 1.0,
                "packet_score": 0.8,
                "temporal_score": 0.3,
                "behavioral_score": 0.95,
                "composite_score": 0.89,
                "confidence": 0.87,
                "severity": "CRITICAL",
                "is_anomaly": True,
                "weights_applied": {
                    "feature": 0.35,
                    "packet": 0.25,
                    "temporal": 0.20,
                    "behavioral": 0.20
                },
                "timestamp": "2026-03-09T10:30:00.000Z"
            }
        }
# ============================================================================
# DETECTION RESULT MODEL
# ============================================================================

class DetectionResult(BaseModel):
    """
    Complete detection result from Layer 1
    
    Contains all scoring details plus detection decision
    """
    # Phase
    phase: str = Field(
        description="Detection phase: 'learning' or 'detection'"
    )
    
    # Scores
    composite_score: CompositeScore
    feature_details: FeatureScore
    packet_details: Optional[PacketScore] = None
    temporal_details: Optional[TemporalScore] = None
    behavioral_details: Optional[BehavioralScore] = None
    
    # Baseline info
    baseline: Dict[str, Dict] = Field(
        description="Current baseline statistics"
    )
    
    # Request metadata
    requests_processed: int = Field(ge=0)
    anomalies_detected: int = Field(ge=0)
    
    @field_validator('phase')
    @classmethod
    def validate_phase(cls, v):
        """Ensure phase is valid"""
        if v not in ['learning', 'detection']:
            raise ValueError("Phase must be 'learning' or 'detection'")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "phase": "detection",
                "composite_score": {
                    "feature_score": 1.0,
                    "packet_score": 0.8,
                    "temporal_score": 0.0,
                    "behavioral_score": 0.95,
                    "composite_score": 0.89,
                    "confidence": 0.87,
                    "severity": "CRITICAL",
                    "is_anomaly": True,
                    "weights_applied": {
                        "feature": 0.35,
                        "packet": 0.25,
                        "temporal": 0.20,
                        "behavioral": 0.20
                    },
                    "timestamp": "2026-03-09T10:30:00Z"
                },
                "feature_details": {
                    "z_scores": {"duration": 633.33, "memory_used": 160.0},
                    "weighted_sum": 197478.0,
                    "total_weight": 0.85,
                    "raw_score": 232327.0,
                    "normalized_score": 1.0
                },
                "baseline": {
                    "duration": {"mean": 500.0, "std": 15.0, "n": 150}
                },
                "requests_processed": 150,
                "anomalies_detected": 3
            }
        }
# ============================================================================
# LEARNING PHASE RESULT
# ============================================================================

class LearningResult(BaseModel):
    """
    Result during learning phase
    """
    phase: str = Field(default='learning')
    is_anomaly: bool = Field(default=False)
    learning_progress: str = Field(
        description="Progress indicator (e.g., '50/100')"
    )
    message: str = Field(
        description="Human-readable status message"
    )
    requests_processed: int = Field(ge=0)
    
    class Config:
        json_schema_extra = {
            "example": {
                "phase": "learning",
                "is_anomaly": False,
                "learning_progress": "75/100",
                "message": "Building baseline... 75% complete",
                "requests_processed": 75
            }
        }

# ============================================================================
# BASELINE STATISTICS MODEL
# ============================================================================

class BaselineStats(BaseModel):
    """
    Statistical baseline for a single feature
    """
    n: int = Field(ge=0, description="Number of samples")
    mean: float = Field(description="Average value")
    std: float = Field(ge=0.0, description="Standard deviation")
    variance: float = Field(ge=0.0, description="Variance")
    min: float = Field(description="Minimum value seen")
    max: float = Field(description="Maximum value seen")
    
    class Config:
        json_schema_extra = {
            "example": {
                "n": 100,
                "mean": 500.0,
                "std": 15.0,
                "variance": 225.0,
                "min": 450.0,
                "max": 550.0
            }
        }
        
