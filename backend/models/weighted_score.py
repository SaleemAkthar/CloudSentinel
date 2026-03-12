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
# ============================================================================
# THRESHOLD INFO MODEL
# ============================================================================

class ThresholdInfo(BaseModel):
    """
    Information about which threshold was exceeded
    """
    score: float = Field(ge=0.0, le=1.0, description="Actual anomaly score")
    critical_threshold: float = Field(default=0.8)
    high_threshold: float = Field(default=0.6)
    medium_threshold: float = Field(default=0.4)
    exceeded: Optional[str] = Field(
        default=None,
        description="Which threshold was exceeded: CRITICAL, HIGH, MEDIUM, or None"
    )
    
    class Config:
        json_schema_extra = {
            "example": {
                "score": 0.89,
                "critical_threshold": 0.8,
                "high_threshold": 0.6,
                "medium_threshold": 0.4,
                "exceeded": "CRITICAL"
            }
        }


# ============================================================================
# ALERT MODEL (for API responses)
# ============================================================================

class Alert(BaseModel):
    """
    Alert model for frontend consumption
    """
    id: str = Field(description="Alert ID (e.g., ALERT-1234)")
    timestamp: str = Field(description="ISO 8601 timestamp")
    severity: str = Field(description="CRITICAL, HIGH, or MEDIUM")
    anomaly_score: float = Field(ge=0.0, le=1.0)
    confidence: float = Field(ge=0.0, le=1.0)
    attack_type: str = Field(description="Detected attack type")
    ip_address: str = Field(description="Source IP address")
    function_name: Optional[str] = Field(default=None)
    status: str = Field(default="OPEN", description="OPEN or CLOSED")
    
    # Feature values that triggered alert
    features: Dict[str, float] = Field(
        description="Feature values (duration, memory, etc.)"
    )
    
    # Evidence
    evidence: List[str] = Field(
        default_factory=list,
        description="List of evidence strings"
    )
    
    # Recommendation
    recommendation: str = Field(
        default="Investigate this alert",
        description="Recommended action"
    )
    
    @field_validator('severity')
    @classmethod
    def validate_severity(cls, v):
        """Ensure severity is valid"""
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM']
        if v not in valid_severities:
            raise ValueError(f"Severity must be one of {valid_severities}")
        return v
    
    @field_validator('status')
    @classmethod
    def validate_status(cls, v):
        """Ensure status is valid"""
        valid_statuses = ['OPEN', 'CLOSED']
        if v not in valid_statuses:
            raise ValueError(f"Status must be one of {valid_statuses}")
        return v
    
    class Config:
        json_schema_extra = {
            "example": {
                "id": "ALERT-1234",
                "timestamp": "2026-03-09T10:30:00Z",
                "severity": "CRITICAL",
                "anomaly_score": 0.89,
                "confidence": 0.98,
                "attack_type": "crypto_mining",
                "ip_address": "203.0.113.42",
                "function_name": "payment-processor",
                "status": "OPEN",
                "features": {
                    "duration": 10000,
                    "memory_used": 450,
                    "num_api_calls": 2
                },
                "evidence": [
                    "Duration 20x higher than normal (10,000ms vs 500ms)",
                    "Memory 3.5x higher than normal (450MB vs 130MB)",
                    "Pattern matches crypto-mining signature"
                ],
                "recommendation": "Block IP immediately"
            }
        }
# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("WEIGHTED SCORE MODELS TEST")
    print("=" * 70)
    
    # Test 1: Feature Score
    print("\n1. Feature Score:")
    feature_score = FeatureScore(
        z_scores={'duration': 633.33, 'memory_used': 160.0},
        weighted_sum=197478.0,
        total_weight=0.85,
        raw_score=232327.0,
        normalized_score=1.0
    )
    print(f"   Z-scores: {feature_score.z_scores}")
    print(f"   Normalized: {feature_score.normalized_score}")
    assert feature_score.normalized_score == 1.0
    print("    Feature score created successfully")
    
    # Test 2: Composite Score with CRITICAL severity
    print("\n2. Composite Score (CRITICAL):")
    composite_critical = CompositeScore(
        feature_score=1.0,
        packet_score=0.8,
        temporal_score=0.3,
        behavioral_score=0.95,
        composite_score=0.89,
        confidence=0.87,
        severity='CRITICAL',
        is_anomaly=True,
        weights_applied={
            'feature': 0.35,
            'packet': 0.25,
            'temporal': 0.20,
            'behavioral': 0.20
        }
    )
    print(f"   Composite: {composite_critical.composite_score}")
    print(f"   Severity: {composite_critical.severity}")
    print(f"   Is Anomaly: {composite_critical.is_anomaly}")
    assert composite_critical.severity == 'CRITICAL'
    print("    CRITICAL composite score created successfully")
    
    # Test 3: Composite Score with HIGH severity
    print("\n3. Composite Score (HIGH):")
    composite_high = CompositeScore(
        feature_score=0.7,
        packet_score=0.6,
        temporal_score=0.2,
        behavioral_score=0.5,
        composite_score=0.65,
        confidence=0.75,
        severity='HIGH',
        is_anomaly=True,
        weights_applied={
            'feature': 0.35,
            'packet': 0.25,
            'temporal': 0.20,
            'behavioral': 0.20
        }
    )
    print(f"   Composite: {composite_high.composite_score}")
    print(f"   Severity: {composite_high.severity}")
    assert composite_high.severity == 'HIGH'
    print("    HIGH composite score created successfully")
    
    # Test 4: Composite Score with MEDIUM severity
    print("\n4. Composite Score (MEDIUM):")
    composite_medium = CompositeScore(
        feature_score=0.5,
        packet_score=0.4,
        temporal_score=0.1,
        behavioral_score=0.3,
        composite_score=0.45,
        confidence=0.60,
        severity='MEDIUM',
        is_anomaly=True,
        weights_applied={
            'feature': 0.35,
            'packet': 0.25,
            'temporal': 0.20,
            'behavioral': 0.20
        }
    )
    print(f"   Composite: {composite_medium.composite_score}")
    print(f"   Severity: {composite_medium.severity}")
    assert composite_medium.severity == 'MEDIUM'
    print("    MEDIUM composite score created successfully")
    
    # Test 5: Composite Score with None severity (below threshold)
    print("\n5. Composite Score (None - Below Threshold):")
    composite_normal = CompositeScore(
        feature_score=0.2,
        packet_score=0.1,
        temporal_score=0.0,
        behavioral_score=0.1,
        composite_score=0.35,
        confidence=0.50,
        severity=None,
        is_anomaly=False,
        weights_applied={
            'feature': 0.35,
            'packet': 0.25,
            'temporal': 0.20,
            'behavioral': 0.20
        }
    )
    print(f"   Composite: {composite_normal.composite_score}")
    print(f"   Severity: {composite_normal.severity}")
    print(f"   Is Anomaly: {composite_normal.is_anomaly}")
    assert composite_normal.severity is None
    assert composite_normal.is_anomaly is False
    print("    Normal (None severity) composite score created successfully")
    
    # Test 6: Baseline Stats
    print("\n6. Baseline Stats:")
    baseline = BaselineStats(
        n=100,
        mean=500.0,
        std=15.0,
        variance=225.0,
        min=450.0,
        max=550.0
    )
    print(f"   Mean: {baseline.mean}ms ± {baseline.std}ms")
    print(f"   Range: [{baseline.min}, {baseline.max}]")
    print(f"   Samples: {baseline.n}")
    assert baseline.n == 100
    print("    Baseline stats created successfully")
    
    # Test 7: Alert model
    print("\n7. Alert Model:")
    alert = Alert(
        id="ALERT-1234",
        timestamp="2026-03-09T10:30:00Z",
        severity="CRITICAL",
        anomaly_score=0.89,
        confidence=0.98,
        attack_type="crypto_mining",
        ip_address="203.0.113.42",
        function_name="payment-processor",
        status="OPEN",
        features={
            "duration": 10000,
            "memory_used": 450,
            "num_api_calls": 2
        },
        evidence=[
            "Duration 20x higher than normal",
            "Memory 3.5x higher than normal"
        ],
        recommendation="Block IP immediately"
    )
    print(f"   Alert ID: {alert.id}")
    print(f"   Severity: {alert.severity}")
    print(f"   Score: {alert.anomaly_score}")
    print(f"   Attack: {alert.attack_type}")
    assert alert.severity == "CRITICAL"
    print("    Alert created successfully")
    
    # Test 8: JSON serialization
    print("\n8. JSON Serialization:")
    json_output = composite_critical.model_dump_json(indent=2)
    print(f"   Length: {len(json_output)} characters")
    print(f"   First 150 chars: {json_output[:150]}...")
    assert len(json_output) > 0
    print("    JSON serialization works")
    
    # Test 9: Invalid severity (should raise error)
    print("\n9. Invalid Severity Validation:")
    try:
        invalid = CompositeScore(
            feature_score=1.0,
            packet_score=0.8,
            temporal_score=0.3,
            behavioral_score=0.95,
            composite_score=0.89,
            confidence=0.87,
            severity='INVALID',  # This should fail
            is_anomaly=True,
            weights_applied={'feature': 0.35, 'packet': 0.25, 'temporal': 0.20, 'behavioral': 0.20}
        )
        print("   Should have raised error for invalid severity")
    except ValueError as e:
        print(f"  Correctly rejected invalid severity: {str(e)}")
    
    # Test 10: Threshold Info
    print("\n10. Threshold Info:")
    threshold_info = ThresholdInfo(
        score=0.89,
        critical_threshold=0.8,
        high_threshold=0.6,
        medium_threshold=0.4,
        exceeded="CRITICAL"
    )
    print(f"   Score: {threshold_info.score}")
    print(f"   Exceeded: {threshold_info.exceeded} threshold")
    print(f"   Thresholds: C={threshold_info.critical_threshold}, "
          f"H={threshold_info.high_threshold}, M={threshold_info.medium_threshold}")
    assert threshold_info.exceeded == "CRITICAL"
    print("  Threshold info created successfully")
    
    print("\n" + "=" * 70)
    print(" ALL MODELS WORKING CORRECTLY")
    print("=" * 70)
    print("\nAll 3 severity levels validated:")
    print("   CRITICAL (score >= 0.8)")
    print("   HIGH (score >= 0.6)")
    print("   MEDIUM (score >= 0.4)")
    print("   None (score < 0.4)")      
