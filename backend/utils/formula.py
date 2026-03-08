"""
Mathematical Formulas for Cloud Sentinel Anomaly Detection
===========================================================

This module contains ALL mathematical formulas used in the detection system:
1. Statistical calculations (Z-scores, variance, etc.)
2. Weighted composite scoring
3. Normalization functions
4. Distance metrics
5. Attack signature calculations

Author: Backend Team
Date: 2026-02-16
"""

import numpy as np
from typing import Dict, Tuple, List, Optional
from datetime import datetime
import math

class WelfordStatistics:
    """
    Welford's algorithm for computing mean and variance incrementally.
    
    Advantage: O(1) space complexity - doesn't store all data points
    
    Mathematical formulas:
        δ = x - μ
        μ_new = μ_old + δ/n
        δ2 = x - μ_new
        M2 = M2 + δ × δ2
        σ² = M2/(n-1)
        σ = √(σ²)
    """
    
    def __init__(self):
        self.n = 0          # Count
        self.mean = 0.0     # Running mean
        self.M2 = 0.0       # Sum of squared deviations
        self.min_val = float('inf')
        self.max_val = float('-inf')
    
    def update(self, x: float):
        """
        Update statistics with new value
        
        Args:
            x: New data point
        """
        self.n += 1
        
        # Update mean
        delta = x - self.mean
        self.mean += delta / self.n
        
        # Update M2 (for variance calculation)
        delta2 = x - self.mean
        self.M2 += delta * delta2
        
        # Update min/max
        self.min_val = min(self.min_val, x)
        self.max_val = max(self.max_val, x)
    
    def get_variance(self) -> float:
        """Calculate variance"""
        if self.n < 2:
            return 0.0
        return self.M2 / (self.n - 1)
    
    def get_std(self) -> float:
        """Calculate standard deviation"""
        return math.sqrt(self.get_variance())
    
    def get_stats(self) -> Dict:
        """Get all statistics"""
        return {
            'n': self.n,
            'mean': self.mean,
            'std': self.get_std(),
            'variance': self.get_variance(),
            'min': self.min_val,
            'max': self.max_val
        }
# ============================================================================
# SECTION 2: Z-SCORE CALCULATIONS
# ============================================================================

def calculate_z_score(value: float, mean: float, std: float) -> float:
    """
    Calculate Z-score (standardized distance from mean)
    
    Formula:
        Z = |x - μ| / σ
    
    Where:
        x = observed value
        μ = mean
        σ = standard deviation
    
    Args:
        value: Observed value
        mean: Population mean
        std: Standard deviation
    
    Returns:
        Z-score (always positive)
    
    Example:
        >>> calculate_z_score(10000, 500, 15)
        633.33
    """
    if std == 0 or std < 1e-10:  # Prevent division by zero
        return 0.0
    
    z_score = abs(value - mean) / std
    return z_score


def calculate_multi_feature_z_scores(
    features: Dict[str, float],
    baseline_stats: Dict[str, Dict]
) -> Dict[str, float]:
    """
    Calculate Z-scores for multiple features
    
    Args:
        features: {'duration': 10000, 'memory': 450, ...}
        baseline_stats: {
            'duration': {'mean': 500, 'std': 15, ...},
            'memory': {'mean': 130, 'std': 2, ...}
        }
    
    Returns:
        {'duration': 633.33, 'memory': 160.0, ...}
    """
    z_scores = {}
    
    for feature_name, value in features.items():
        if feature_name in baseline_stats:
            stats = baseline_stats[feature_name]
            mean = stats.get('mean', 0)
            std = stats.get('std', 1)
            
            z_scores[feature_name] = calculate_z_score(value, mean, std)
        else:
            z_scores[feature_name] = 0.0
    
    return z_scores
    # ============================================================================
# SECTION 3: WEIGHTED FEATURE ANOMALY SCORING
# ============================================================================

def calculate_feature_anomaly(
    features: Dict[str, float],
    baseline_stats: Dict[str, Dict],
    feature_weights: Dict[str, float]
) -> Tuple[float, Dict]:
    """
    Calculate weighted feature-based anomaly score
    
    Formula:
        A_feature = Σ(w_i × Z_i²) / Σ(w_i)
    
    Where:
        w_i = weight for feature i
        Z_i = Z-score for feature i
    
    Args:
        features: Current feature values
        baseline_stats: Statistical baselines
        feature_weights: Weight for each feature
    
    Returns:
        (anomaly_score, details_dict)
    
    Example:
        >>> features = {'duration': 10000, 'memory': 450}
        >>> baseline = {
        ...     'duration': {'mean': 500, 'std': 15},
        ...     'memory': {'mean': 130, 'std': 2}
        ... }
        >>> weights = {'duration': 0.6, 'memory': 0.4}
        >>> score, details = calculate_feature_anomaly(features, baseline, weights)
        >>> score
        1.0  (capped)
    """
    # Calculate Z-scores
    z_scores = calculate_multi_feature_z_scores(features, baseline_stats)
    
    # Calculate weighted sum of squared Z-scores
    weighted_sum = 0.0
    total_weight = 0.0
    
    for feature_name, z_score in z_scores.items():
        weight = feature_weights.get(feature_name, 0.0)
        weighted_sum += weight * (z_score ** 2)
        total_weight += weight
    
    # Normalize by total weight
    if total_weight > 0:
        weighted_score = weighted_sum / total_weight
    else:
        weighted_score = 0.0
    
    # Apply square root to get back to Z-score scale
    # Then normalize to 0-1 scale
    normalized_score = min(math.sqrt(weighted_score) / 3.0, 1.0)
    
    details = {
        'z_scores': z_scores,
        'weighted_sum': weighted_sum,
        'total_weight': total_weight,
        'raw_score': weighted_score,
        'normalized_score': normalized_score
    }
    
    return normalized_score, details

# ============================================================================
# SECTION 4: PACKET-BASED ANOMALY SCORING
# ============================================================================

def calculate_packet_anomaly(
    features: Dict[str, float],
    packet_stats: Dict[str, Dict]
) -> Tuple[float, Dict]:
    """
    Calculate packet-level anomaly score
    
    Formula:
        A_packet = √[(P_latency)² + (P_size)² + (P_fragmentation)²]
    
    Components:
        P_latency = latency Z-score
        P_size = packet size anomaly
        P_fragmentation = fragmentation indicator (0-1)
    
    Args:
        features: Request features including packet metrics
        packet_stats: Baseline packet statistics
    
    Returns:
        (anomaly_score, details_dict)
    """
    # Extract packet features
    latency = features.get('latency', 0)
    packet_size_in = features.get('packet_size_in', 0)
    packet_size_out = features.get('packet_size_out', 0)
    fragment_count = features.get('fragment_count', 0)
    
    # Component 1: Latency anomaly
    if 'latency' in packet_stats:
        latency_mean = packet_stats['latency'].get('mean', latency)
        latency_std = packet_stats['latency'].get('std', 1)
        P_latency = calculate_z_score(latency, latency_mean, latency_std) / 3.0
    else:
        P_latency = 0.0
    
    # Component 2: Packet size anomaly
    # Check for data exfiltration (large outbound vs inbound)
    size_ratio = packet_size_out / max(packet_size_in, 1)
    
    if size_ratio > 10:  # Suspicious: sending 10x more than receiving
        P_size = 0.9
    elif size_ratio > 5:
        P_size = 0.6
    elif size_ratio > 2:
        P_size = 0.3
    else:
        P_size = 0.0
    
    # Component 3: Fragmentation anomaly
    if fragment_count > 10:  # Highly fragmented (DDoS indicator)
        P_fragmentation = 1.0
    elif fragment_count > 5:
        P_fragmentation = 0.7
    elif fragment_count > 2:
        P_fragmentation = 0.3
    else:
        P_fragmentation = 0.0
    
    # Combine components (Euclidean norm, then normalize)
    A_packet = math.sqrt(P_latency**2 + P_size**2 + P_fragmentation**2) / math.sqrt(3)
    A_packet = min(A_packet, 1.0)
    
    details = {
        'latency_component': P_latency,
        'size_component': P_size,
        'size_ratio': size_ratio,
        'fragmentation_component': P_fragmentation,
        'fragment_count': fragment_count,
        'packet_anomaly_score': A_packet
    }
    
    return A_packet, details
# ============================================================================
# SECTION 5: TEMPORAL ANOMALY (SARIMA-based)
# ============================================================================

def calculate_temporal_anomaly(
    actual_value: float,
    predicted_value: float,
    prediction_std: float
) -> float:
    """
    Calculate temporal anomaly using SARIMA prediction
    
    Formula:
        A_temporal = |x_actual - x_predicted| / σ_residual
    
    Where:
        x_actual = observed value
        x_predicted = SARIMA forecast
        σ_residual = std of prediction errors
    
    Args:
        actual_value: Actual observed value
        predicted_value: SARIMA predicted value
        prediction_std: Standard deviation of SARIMA residuals
    
    Returns:
        Temporal anomaly score (0-1)
    
    Example:
        >>> # Monday 9am, SARIMA predicts 800ms, actual is 850ms
        >>> calculate_temporal_anomaly(850, 800, 50)
        0.333  # Within 1 std, not very anomalous
        
        >>> # But if actual is 5000ms
        >>> calculate_temporal_anomaly(5000, 800, 50)
        1.0  # Way beyond prediction
    """
    if prediction_std == 0 or prediction_std < 1e-10:
        return 0.0
    
    # Calculate deviation from prediction
    deviation = abs(actual_value - predicted_value)
    
    # Normalize by prediction uncertainty
    temporal_z = deviation / prediction_std
    
    # Convert to 0-1 scale (3-sigma rule)
    temporal_anomaly = min(temporal_z / 3.0, 1.0)
    
    return temporal_anomaly
# ============================================================================
# SECTION 6: BEHAVIORAL ANOMALY (Attack Signatures)
# ============================================================================

def calculate_behavioral_anomaly(
    features: Dict[str, float],
    baseline_stats: Dict[str, Dict],
    ip_history: Optional[Dict] = None
) -> Tuple[float, str]:
    """
    Calculate behavioral anomaly based on attack signatures
    
    Checks for:
    1. Crypto-mining (high duration + high memory)
    2. Data exfiltration (excessive API calls)
    3. DDoS (high request rate, low entropy)
    4. SQL injection (high DB queries + errors)
    5. Memory attack (memory near limit)
    
    Args:
        features: Current request features
        baseline_stats: Statistical baselines
        ip_history: Historical behavior of this IP
    
    Returns:
        (behavioral_score, attack_type)
    """
    duration = features.get('duration', 0)
    memory = features.get('memory_used', 0)
    api_calls = features.get('num_api_calls', 0)
    errors = features.get('error_count', 0)
    
    # Get baseline means
    mean_duration = baseline_stats.get('duration', {}).get('mean', 500)
    mean_memory = baseline_stats.get('memory_used', {}).get('mean', 130)
    
    # Initialize attack scores
    attack_scores = {}
    
    # 1. CRYPTO MINING SIGNATURE
    # High duration (>5x normal) + high memory
    if duration > mean_duration * 5 and memory > mean_memory * 2:
        S_crypto = min((duration / mean_duration) / 20, 1.0)  # Normalize
        attack_scores['crypto_mining'] = S_crypto
    
    # 2. DATA EXFILTRATION SIGNATURE
    # Excessive API calls (>10)
    if api_calls > 10:
        S_exfil = min(api_calls / 30, 1.0)  # Normalize (30 = max expected)
        attack_scores['data_exfiltration'] = S_exfil
    
    # 3. SQL INJECTION SIGNATURE
    # High DB calls + errors
    db_calls = features.get('db_queries', 0)
    if db_calls > 10 and errors > 0:
        S_injection = min((db_calls * errors) / 100, 1.0)
        attack_scores['sql_injection'] = S_injection
    
    # 4. MEMORY ATTACK SIGNATURE
    # Memory near limit (>90% of max)
    memory_limit = features.get('memory_limit', 512)
    if memory > memory_limit * 0.9:
        S_memory = memory / memory_limit
        attack_scores['memory_attack'] = S_memory
    
    # 5. DDoS SIGNATURE (if IP history available)
    if ip_history:
        request_rate = ip_history.get('request_rate', 0)
        entropy = ip_history.get('entropy', 1.0)  # Diversity of requests
        
        if request_rate > 100:  # More than 100 req/min from same IP
            S_ddos = min(request_rate / 500, 1.0) * (1 - entropy)
            attack_scores['ddos'] = S_ddos
    
    # Return highest scoring attack
    if attack_scores:
        attack_type = max(attack_scores, key=attack_scores.get)
        behavioral_score = attack_scores[attack_type]
    else:
        attack_type = 'unknown'
        behavioral_score = 0.0
    
    return behavioral_score, attack_type
# ============================================================================
# SECTION 7: COMPOSITE ANOMALY SCORE
# ============================================================================

def calculate_composite_anomaly_score(
    A_feature: float,
    A_packet: float,
    A_temporal: float,
    A_behavioral: float,
    weights: Dict[str, float]
) -> float:
    """
    Calculate final composite anomaly score
    
    Formula:
        S_composite = α·tanh(A_feature) + β·tanh(A_packet) + 
                      γ·tanh(A_temporal) + δ·A_behavioral
    
    Where:
        α + β + γ + δ = 1 (weights sum to 1)
        tanh() = hyperbolic tangent (smooth normalization)
    
    Default weights:
        α = 0.35 (feature)
        β = 0.25 (packet)
        γ = 0.20 (temporal)
        δ = 0.20 (behavioral)
    
    Args:
        A_feature: Feature-based anomaly score
        A_packet: Packet-based anomaly score
        A_temporal: Temporal anomaly score
        A_behavioral: Behavioral anomaly score
        weights: Component weights
    
    Returns:
        Composite anomaly score (0-1)
    
    Example:
        >>> calculate_composite_anomaly_score(
        ...     A_feature=1.0,
        ...     A_packet=0.8,
        ...     A_temporal=0.3,
        ...     A_behavioral=0.95,
        ...     weights={'feature': 0.35, 'packet': 0.25, 'temporal': 0.20, 'behavioral': 0.20}
        ... )
        0.89
    """
    alpha = weights.get('feature', 0.35)
    beta = weights.get('packet', 0.25)
    gamma = weights.get('temporal', 0.20)
    delta = weights.get('behavioral', 0.20)
    
    # Use tanh for smooth normalization (maps large values to ~1.0)
    S_composite = (
        alpha * np.tanh(A_feature) +
        beta * np.tanh(A_packet) +
        gamma * np.tanh(A_temporal) +
        delta * A_behavioral  # Already normalized
    )
    
    # Ensure in [0, 1] range
    S_composite = max(0.0, min(S_composite, 1.0))
    
    return S_composite


