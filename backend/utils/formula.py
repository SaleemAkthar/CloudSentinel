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
