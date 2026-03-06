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