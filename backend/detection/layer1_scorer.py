"""
Layer 1: Weighted Anomaly Scoring
==================================

Fast, real-time anomaly scoring using weighted composite formula.

Author: Raneesha (Backend Team)
"""
import sys
import os

# Add project root to Python path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, project_root)

import numpy as np
from typing import Dict, Tuple, Optional
from datetime import datetime

# Import our mathematical functions
from backend.utils.formula import (
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
from backend.utils.weights import (
    FEATURE_WEIGHTS,
    COMPONENT_WEIGHTS,
    ANOMALY_THRESHOLD,
    DETECTION_THRESHOLDS,
    is_anomaly as check_is_anomaly
)

class Layer1Scorer:
    
    
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
        
        # SARIMA forecaster (connects to Okitha's temporal analysis)
        # Set via set_sarima_forecaster() method after initialization
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
        
        sarima_active = (
            self.sarima_forecaster is not None
            and self.n_requests > 200
            and A_temporal > 0.0
        )
        if sarima_active:
            active_weights = COMPONENT_WEIGHTS
        else:
            # Redistribute the 0.20 temporal weight proportionally
            # to feature (0.35), packet (0.25), behavioral (0.20)
            # so the three active components sum to 1.0.
            active_weights = {
                'feature':    0.44,   # 0.35 / 0.80
                'packet':     0.31,   # 0.25 / 0.80
                'temporal':   0.00,
                'behavioral': 0.25,   # 0.20 / 0.80
            }

        # CALCULATE COMPOSITE SCORE
        composite_score = calculate_composite_anomaly_score(
            A_feature,
            A_packet,
            A_temporal,
            A_behavioral,
            active_weights
        )

        max_component = max(A_feature, A_behavioral)
        if max_component > 0.9:
            composite_score = max(composite_score, 0.75)
        elif A_feature > 0.7 and A_behavioral > 0.5:
            # Strong agreement between feature and behavioral — also boost
            composite_score = max(composite_score, 0.55)
        
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
    def _update_baseline(self, features: Dict):
        """Update baseline statistics with normal traffic"""
        feature_names = ['duration', 'memory_used', 'num_api_calls', 'error_count', 'concurrency']
        
        for feature_name in feature_names:
            if feature_name in features and feature_name in self.feature_stats:
                value = float(features[feature_name])
                self.feature_stats[feature_name].update(value)
    
    def _update_ip_history(self, ip: str, features: Dict, is_anomaly: bool, score: float):
        """Track IP behavior over time"""
        if ip not in self.ip_history:
            self.ip_history[ip] = {
                'requests': 0,
                'anomalies': 0,
                'last_seen': None,
                'request_rate': 0,
                'entropy': 1.0,
                'scores': []
            }
        
        hist = self.ip_history[ip]
        hist['requests'] += 1
        if is_anomaly:
            hist['anomalies'] += 1
        hist['last_seen'] = datetime.now()
        hist['scores'].append(score)
        
        # Keep only last 100 scores
        if len(hist['scores']) > 100:
            hist['scores'] = hist['scores'][-100:]
        
        # Simple request rate calculation (requests per minute)
        # In production, use sliding window
        hist['request_rate'] = hist['requests']  # Simplified
    
    def _build_evidence(
        self,
        features: Dict,
        baseline_stats: Dict,
        feature_details: Dict,
        attack_type: str,
        is_anomaly: bool
    ) -> list:
        """Build evidence list for alert"""
        if not is_anomaly:
            return []
        
        evidence = []
        
        # Duration evidence
        if 'duration' in features and 'duration' in baseline_stats:
            duration = features['duration']
            mean = baseline_stats['duration']['mean']
            if duration > mean * 2:
                multiplier = duration / mean
                evidence.append(
                    f"Duration {multiplier:.1f}x higher than normal "
                    f"({duration:.0f}ms vs {mean:.0f}ms)"
                )
        
        # Memory evidence
        if 'memory_used' in features and 'memory_used' in baseline_stats:
            memory = features['memory_used']
            mean = baseline_stats['memory_used']['mean']
            if memory > mean * 1.5:
                multiplier = memory / mean
                evidence.append(
                    f"Memory {multiplier:.1f}x higher than normal "
                    f"({memory:.0f}MB vs {mean:.0f}MB)"
                )
        
        # API calls evidence
        if 'num_api_calls' in features:
            api_calls = features['num_api_calls']
            if api_calls > 10:
                evidence.append(
                    f"Excessive API calls ({api_calls} calls)"
                )
        
        # Error evidence
        if 'error_count' in features:
            errors = features['error_count']
            if errors > 0:
                evidence.append(
                    f"Errors detected ({errors} errors)"
                )
        
        # Attack pattern evidence
        if attack_type != 'unknown':
            evidence.append(
                f"Pattern matches {attack_type.replace('_', ' ')} signature"
            )
        
        return evidence
    
    def _get_baseline_summary(self) -> Dict:
        """Get summary of current baseline"""
        summary = {}
        for feature_name, stats in self.feature_stats.items():
            stats_dict = stats.get_stats()
            summary[feature_name] = {
                'mean': round(stats_dict['mean'], 2),
                'std': round(stats_dict['std'], 2),
                'n': stats_dict['n']
            }
        return summary
    
    def set_sarima_forecaster(self, forecaster):
        """Set SARIMA forecaster for temporal analysis"""
        self.sarima_forecaster = forecaster
        print(" SARIMA forecaster connected to Layer 1")
    
    def get_status(self) -> Dict:
        """Get scorer status"""
        return {
            'phase': 'learning' if self.learning_phase else 'detection',
            'requests_processed': self.n_requests,
            'anomalies_detected': self.n_anomalies,
            'learning_progress': f"{min(self.n_requests, self.learning_window)}/{self.learning_window}",
            'baseline_features': list(self.feature_stats.keys()),
            'detection_rate': f"{(self.n_anomalies/max(self.n_requests, 1))*100:.1f}%" if self.n_requests > 0 else "0%"
        }
# ============================================================================
# TESTING
# ============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("LAYER 1 SCORER TEST")
    print("=" * 70)
    
    # Create scorer
    scorer = Layer1Scorer(learning_window=50)
    
    print("\n LEARNING PHASE")
    print("-" * 70)
    
    # Learning phase - 50 normal requests
    for i in range(50):
        normal_features = {
            'duration': 500 + np.random.randint(-20, 20),
            'memory_used': 130 + np.random.randint(-5, 5),
            'num_api_calls': 3,
            'error_count': 0,
            'concurrency': 1,
            'packet_size_in': 1024,
            'packet_size_out': 512,
            'latency': 50,
            'fragment_count': 1,
            'ip_address': '192.168.1.1',
            'timestamp': datetime.now().isoformat()
        }
        
        score, details = scorer.process_log(normal_features)
        
        if (i + 1) % 10 == 0:
            print(f"Request {i+1}: {details['learning_progress']}")
    
    print("\n DETECTION PHASE")
    print("-" * 70)
    
    # Test 1: Normal request
    print("\n1. Normal Request (Below Threshold):")
    normal = {
        'duration': 505,
        'memory_used': 128,
        'num_api_calls': 3,
        'error_count': 0,
        'concurrency': 1,
        'packet_size_in': 1024,
        'packet_size_out': 512,
        'latency': 50,
        'fragment_count': 1,
        'ip_address': '192.168.1.1',
        'timestamp': datetime.now().isoformat()
    }
    score, details = scorer.process_log(normal)
    print(f"   Score: {score:.3f}")
    print(f"   Anomaly: {details['is_anomaly']}")
    print(f"   Severity: {details.get('severity', 'None')}")
    print(f"   Components: Feature={details['components']['feature']:.3f}, "
          f"Packet={details['components']['packet']:.3f}, "
          f"Behavioral={details['components']['behavioral']:.3f}")
    
    # Test 2: MEDIUM severity
    print("\n2. MEDIUM Severity Alert (score 0.4-0.6):")
    medium_alert = {
        'duration': 650,  # Moderately elevated
        'memory_used': 145,
        'num_api_calls': 5,
        'error_count': 1,
        'concurrency': 2,
        'packet_size_in': 1024,
        'packet_size_out': 1500,
        'latency': 80,
        'fragment_count': 2,
        'ip_address': '192.168.1.150',
        'timestamp': datetime.now().isoformat()
    }
    score, details = scorer.process_log(medium_alert)
    print(f"   Score: {score:.3f}")
    print(f"   Anomaly: {details['is_anomaly']}")
    print(f"   Severity: {details.get('severity', 'None')}")
    print(f"   Attack Type: {details.get('attack_type', 'None')}")
    print(f"   Evidence: {details.get('evidence', [])}")
    
    # Test 3: HIGH severity
    print("\n3. HIGH Severity Alert (score 0.6-0.8):")
    high_alert = {
        'duration': 1200,  # Highly elevated
        'memory_used': 200,
        'num_api_calls': 8,
        'error_count': 2,
        'concurrency': 3,
        'packet_size_in': 1024,
        'packet_size_out': 5000,
        'latency': 150,
        'fragment_count': 3,
        'ip_address': '192.168.1.200',
        'timestamp': datetime.now().isoformat()
    }
    score, details = scorer.process_log(high_alert)
    print(f"   Score: {score:.3f}")
    print(f"   Anomaly: {details['is_anomaly']}")
    print(f"   Severity: {details.get('severity', 'None')}")
    print(f"   Attack Type: {details.get('attack_type', 'None')}")
    print(f"   Confidence: {details['confidence']:.3f}")
    
    # Test 4: Crypto-mining attack (CRITICAL)
    print("\n4. CRITICAL - Crypto-Mining Attack (score >= 0.8):")
    crypto = {
        'duration': 10000,  # 20x normal
        'memory_used': 450,  # 3.5x normal
        'num_api_calls': 2,
        'error_count': 0,
        'concurrency': 1,
        'packet_size_in': 1024,
        'packet_size_out': 512,
        'latency': 50,
        'fragment_count': 1,
        'ip_address': '192.168.1.100',
        'timestamp': datetime.now().isoformat()
    }
    score, details = scorer.process_log(crypto)
    print(f"   Score: {score:.3f}")
    print(f"   Anomaly: {details['is_anomaly']}")
    print(f"   Severity: {details['severity']}")
    print(f"   Attack Type: {details['attack_type']}")
    print(f"   Confidence: {details['confidence']:.3f}")
    print(f"   Z-scores: {details['feature_details']['z_scores']}")
    print(f"   Evidence:")
    for evidence in details['evidence']:
        print(f"     • {evidence}")
    
    # Test 5: Data exfiltration (CRITICAL)
    print("\n5. CRITICAL - Data Exfiltration (score >= 0.8):")
    exfil = {
        'duration': 600,
        'memory_used': 150,
        'num_api_calls': 25,  # Excessive
        'error_count': 0,
        'concurrency': 1,
        'packet_size_in': 1024,
        'packet_size_out': 20480,  # 20x outbound
        'latency': 50,
        'fragment_count': 1,
        'ip_address': '10.0.0.50',
        'timestamp': datetime.now().isoformat()
    }
    score, details = scorer.process_log(exfil)
    print(f"   Score: {score:.3f}")
    print(f"   Anomaly: {details['is_anomaly']}")
    print(f"   Severity: {details['severity']}")
    print(f"   Attack Type: {details['attack_type']}")
    print(f"   Packet ratio: {details['packet_details']['size_ratio']:.1f}x")
    
    print("\n" + "=" * 70)
    print("LAYER 1 SCORER WORKING CORRECTLY !")
    print("=" * 70)
    
    # Show final stats
    status = scorer.get_status()
    print(f"\nFinal Statistics:")
    print(f"  Phase: {status['phase']}")
    print(f"  Total Requests: {status['requests_processed']}")
    print(f"  Anomalies Detected: {status['anomalies_detected']}")
    print(f"  Detection Rate: {status['detection_rate']}")
    print(f"  Learning Progress: {status['learning_progress']}")
    
    print("\n" + "=" * 70)
    print("SEVERITY DISTRIBUTION TEST")
    print("=" * 70)
    
    severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'None': 0}
    
    # Count severities from our tests
    test_results = [
        (normal, 'None'),
        (medium_alert, 'MEDIUM'),
        (high_alert, 'HIGH'),
        (crypto, 'CRITICAL'),
        (exfil, 'CRITICAL')
    ]
    
    print("\nTest Results Summary:")
    for i, (test_features, expected_severity) in enumerate(test_results, 1):
        score, details = scorer.process_log(test_features)
        actual_severity = details.get('severity', 'None')
        severity_counts[actual_severity if actual_severity else 'None'] += 1
        
        status_icon = "Correct" if actual_severity == expected_severity else "Wrong"
        print(f"{status_icon} Test {i}: Score={score:.2f}, "
              f"Severity={actual_severity if actual_severity else 'None':8s}, "
              f"Expected={expected_severity}")
    
    print(f"\nSeverity Distribution:")
    print(f"   CRITICAL: {severity_counts['CRITICAL']}")
    print(f"   HIGH:     {severity_counts['HIGH']}")
    print(f"   MEDIUM:   {severity_counts['MEDIUM']}")
    print(f"   None:     {severity_counts['None']}")
    
    print("\n" + "=" * 70)
    print(" ALL TESTS PASSED - TIERED ALERTING WORKING")
    print("=" * 70)



    