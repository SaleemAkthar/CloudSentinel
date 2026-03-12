"""
Layer 1: Weighted Anomaly Scoring
==================================

Fast, real-time anomaly scoring using weighted composite formula.

This layer:
1. Extracts features from log
2. Calculates weighted anomaly score
3. Determines severity and confidence
4. Returns quick decision: NORMAL / SUSPICIOUS / CRITICAL

Author: Raneesha (Backend Team)
"""
import numpy as np
from typing import Dict, Tuple, Optional
from datetime import datetime

# Import our mathematical functions
from utils.formula import (
    WelfordStatistics,
    calculate_feature_anomaly,
    calculate_packet_anomaly,
    calculate_temporal_anomaly,
    calculate_behavioral_anomaly,
    calculate_composite_anomaly_score,
    calculate_confidence_score,
    classify_severity
)

# Import weight configurations
from utils.weights import (
    FEATURE_WEIGHTS,
    COMPONENT_WEIGHTS,
    ANOMALY_THRESHOLD,
    DETECTION_THRESHOLDS,
    is_anomaly as check_is_anomaly
)

class Layer1Scorer:
    """
    Real-time weighted anomaly scoring
    
    Uses composite formula:
        S = α·A_feature + β·A_packet + γ·A_temporal + δ·A_behavioral
    
    Where:
        α, β, γ, δ = component weights (from weights.py)
        A_* = anomaly scores for each component
    """
    
    def __init__(self, learning_window: int = 100):
        """
        Initialize Layer 1 Scorer
        
        Args:
            learning_window: Number of requests to learn baseline (default 100)
        """
        self.learning_window = learning_window
        
        # Feature statistics (Welford's algorithm)
        self.feature_stats = {}
        
        # Packet statistics
        self.packet_stats = {}
        
        # SARIMA forecaster (will be set later by Saleem)
        self.sarima_forecaster = None
        
        # State tracking
        self.n_requests = 0
        self.n_anomalies = 0
        self.learning_phase = True
        
        # IP history (for behavioral analysis)
        self.ip_history = {}
        
        print(" Layer 1 Scorer initialized")
        print(f"   Learning window: {learning_window} requests")
        print(f"   Detection thresholds: CRITICAL={DETECTION_THRESHOLDS['critical']}, "
              f"HIGH={DETECTION_THRESHOLDS['high']}, MEDIUM={DETECTION_THRESHOLDS['medium']}")
    
    def process_log(self, features: Dict) -> Tuple[float, Dict]:
        """
        Process log and calculate weighted anomaly score
        
        Args:
            features: {
                'duration': float (ms),
                'memory_used': float (MB),
                'num_api_calls': int,
                'error_count': int,
                'concurrency': int,
                'packet_size_in': float,
                'packet_size_out': float,
                'latency': float,
                'fragment_count': int,
                'ip_address': str,
                'timestamp': str
            }
        
        Returns:
            (composite_score, details_dict)
        
        Example:
            >>> scorer = Layer1Scorer()
            >>> features = {
            ...     'duration': 10000,
            ...     'memory_used': 450,
            ...     'num_api_calls': 2,
            ...     'error_count': 0,
            ...     'ip_address': '192.168.1.100'
            ... }
            >>> score, details = scorer.process_log(features)
            >>> score
            0.95
            >>> details['severity']
            'CRITICAL'
        """
        self.n_requests += 1
        
        # Initialize feature stats if first request
        if not self.feature_stats:
            self._initialize_feature_stats(features)
        
        # LEARNING PHASE
        if self.learning_phase:
            return self._handle_learning_phase(features)
        
        # DETECTION PHASE
        return self._handle_detection_phase(features)
    
    def _initialize_feature_stats(self, features: Dict):
        """Initialize Welford statistics for each feature"""
        feature_names = ['duration', 'memory_used', 'num_api_calls', 'error_count', 'concurrency']
        packet_names = ['latency', 'packet_size_in', 'packet_size_out']
        
        for feature_name in feature_names:
            self.feature_stats[feature_name] = WelfordStatistics()
        
        for packet_name in packet_names:
            self.packet_stats[packet_name] = WelfordStatistics()
    def _handle_learning_phase(self, features: Dict) -> Tuple[float, Dict]:
        """
        Handle learning phase (first N requests)
        Just update statistics, don't detect
        """
        # Update all feature statistics
        feature_names = ['duration', 'memory_used', 'num_api_calls', 'error_count', 'concurrency']
        for feature_name in feature_names:
            if feature_name in features and feature_name in self.feature_stats:
                value = float(features[feature_name])
                self.feature_stats[feature_name].update(value)
        
        # Update packet statistics
        packet_names = ['latency', 'packet_size_in', 'packet_size_out']
        for packet_name in packet_names:
            if packet_name in features and packet_name in self.packet_stats:
                value = float(features[packet_name])
                self.packet_stats[packet_name].update(value)
        
        # Check if learning complete
        if self.n_requests >= self.learning_window:
            self.learning_phase = False
            print(f"\nLearning complete! Baseline established from {self.learning_window} requests")
            print(" Now in detection mode\n")
            print("Baseline Statistics:")
            for name, stats in self.feature_stats.items():
                stat_dict = stats.get_stats()
                print(f"  {name:20s}: mean={stat_dict['mean']:.2f}, std={stat_dict['std']:.2f}")
        
        return 0.0, {
            'phase': 'learning',
            'is_anomaly': False,
            'learning_progress': f"{self.n_requests}/{self.learning_window}",
            'message': f"Building baseline... {(self.n_requests/self.learning_window)*100:.0f}% complete",
            'requests_processed': self.n_requests
        }
    
    def _handle_detection_phase(self, features: Dict) -> Tuple[float, Dict]:
        """
        Handle detection phase (after learning)
        Calculate weighted anomaly score
        """
        # Get baseline statistics
        baseline_stats = {
            name: stats.get_stats()
            for name, stats in self.feature_stats.items()
        }
        
        packet_stats_dict = {
            name: stats.get_stats()
            for name, stats in self.packet_stats.items()
        }
        
        # COMPONENT 1: Feature-based anomaly
        A_feature, feature_details = calculate_feature_anomaly(
            features,
            baseline_stats,
            FEATURE_WEIGHTS
        )
        
        # COMPONENT 2: Packet-based anomaly
        A_packet, packet_details = calculate_packet_anomaly(
            features,
            packet_stats_dict
        )
        
        # COMPONENT 3: Temporal anomaly (if SARIMA available)
        A_temporal = 0.0
        temporal_details = None
        
        if self.sarima_forecaster is not None and self.n_requests > 200:
            try:
                predicted = self.sarima_forecaster.predict(features.get('timestamp', datetime.now().isoformat()))
                A_temporal = calculate_temporal_anomaly(
                    features.get('duration', 0),
                    predicted['value'],
                    predicted['std']
                )
                temporal_details = {
                    'predicted_value': predicted['value'],
                    'prediction_std': predicted['std'],
                    'actual_value': features.get('duration', 0),
                    'temporal_score': A_temporal
                }
            except Exception as e:
                # SARIMA not ready yet or prediction failed
                A_temporal = 0.0
                temporal_details = {'error': str(e), 'sarima_available': False}
        
        # COMPONENT 4: Behavioral anomaly (attack patterns)
        ip_addr = features.get('ip_address', 'unknown')
        ip_hist = self.ip_history.get(ip_addr, None)
        
        A_behavioral, attack_type = calculate_behavioral_anomaly(
            features,
            baseline_stats,
            ip_hist
        )
        
        # CALCULATE COMPOSITE SCORE
        composite_score = calculate_composite_anomaly_score(
            A_feature,
            A_packet,
            A_temporal,
            A_behavioral,
            COMPONENT_WEIGHTS
        )
        
        # CALCULATE CONFIDENCE
        confidence = calculate_confidence_score(
            A_feature,
            A_packet,
            A_temporal,
            A_behavioral
        )
        
        # CLASSIFY SEVERITY (tiered system)
        severity = classify_severity(
            composite_score,
            attack_type,
            confidence
        )
        
        # DETERMINE IF ANOMALY (score >= 0.4)
        is_anomaly = check_is_anomaly(composite_score)
        
        if is_anomaly:
            self.n_anomalies += 1
        
        # Update baseline (only with normal traffic)
        if not is_anomaly:
            self._update_baseline(features)
        
        # Update IP history
        self._update_ip_history(ip_addr, features, is_anomaly, composite_score)
        
        # Build evidence list
        evidence = self._build_evidence(
            features,
            baseline_stats,
            feature_details,
            attack_type,
            is_anomaly
        )
        
        # Prepare detailed results
        details = {
            'phase': 'detection',
            'is_anomaly': is_anomaly,
            'anomaly_score': round(composite_score, 3),
            'confidence': round(confidence, 3),
            'severity': severity,
            'attack_type': attack_type if is_anomaly else None,
            'components': {
                'feature': round(A_feature, 3),
                'packet': round(A_packet, 3),
                'temporal': round(A_temporal, 3),
                'behavioral': round(A_behavioral, 3)
            },
            'feature_details': feature_details,
            'packet_details': packet_details,
            'temporal_details': temporal_details,
            'baseline': self._get_baseline_summary(),
            'threshold_info': {
                'score': composite_score,
                'critical_threshold': DETECTION_THRESHOLDS['critical'],
                'high_threshold': DETECTION_THRESHOLDS['high'],
                'medium_threshold': DETECTION_THRESHOLDS['medium'],
                'exceeded': severity
            },
            'evidence': evidence,
            'timestamp': datetime.now().isoformat(),
            'requests_processed': self.n_requests,
            'anomalies_detected': self.n_anomalies
        }
        
        return composite_score, details
    
    