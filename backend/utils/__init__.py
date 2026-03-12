"""
Utilities Package
=================

Mathematical functions, weight configurations, and validators.

Modules:
- formula: All mathematical formulas (Welford's, Z-scores, composite scoring)
- weights: Feature and component weights, detection thresholds
- validators: Input validation and sanitization
- helpers: General utility functions
"""

from .formula import (
    WelfordStatistics,
    calculate_z_score,
    calculate_feature_anomaly,
    calculate_packet_anomaly,
    calculate_temporal_anomaly,
    calculate_behavioral_anomaly,
    calculate_composite_anomaly_score,
    calculate_confidence_score,
    classify_severity
)

from .weights import (
    FEATURE_WEIGHTS,
    COMPONENT_WEIGHTS,
    DETECTION_THRESHOLDS,
    ANOMALY_THRESHOLD,
    SEVERITY_THRESHOLDS,
    is_anomaly,
    get_severity_from_score
)

from .validators import (
    validate_log_entry,
    validate_features,
    validate_ip_address,
    validate_alert_id
)

__all__ = [
    # Formula exports
    'WelfordStatistics',
    'calculate_z_score',
    'calculate_feature_anomaly',
    'calculate_packet_anomaly',
    'calculate_temporal_anomaly',
    'calculate_behavioral_anomaly',
    'calculate_composite_anomaly_score',
    'calculate_confidence_score',
    'classify_severity',
    
    # Weights exports
    'FEATURE_WEIGHTS',
    'COMPONENT_WEIGHTS',
    'DETECTION_THRESHOLDS',
    'ANOMALY_THRESHOLD',
    'SEVERITY_THRESHOLDS',
    'is_anomaly',
    'get_severity_from_score',
    
    # Validators exports
    'validate_log_entry',
    'validate_features',
    'validate_ip_address',
    'validate_alert_id',
]