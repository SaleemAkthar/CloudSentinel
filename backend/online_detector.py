"""
Online Learning Anomaly Detector for Serverless Applications
Core Module: Implements Welford's Algorithm for streaming anomaly detection
"""

from datetime import datetime
from typing import Dict, List, Tuple


class OnlineStats:
    """
    Implements Welford's Algorithm for computing mean and variance in a single pass.
    Memory efficient: O(1) space complexity regardless of data size.
    """
    
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0  # Sum of squares of differences from the current mean
    
    def update(self, x: float) -> None:
        """Update statistics with a new value."""
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2
    
    def get_mean(self) -> float:
        return self.mean
    
    def get_variance(self) -> float:
        if self.n < 2:
            return 0.0
        return self.M2 / (self.n - 1)
    
    def get_std(self) -> float:
        return self.get_variance() ** 0.5
    
    def get_z_score(self, x: float) -> float:
        """Calculate Z-score for a value."""
        std = self.get_std()
        if std == 0:
            return 0.0
        return (x - self.mean) / std
    
    def to_dict(self) -> Dict:
        """Export statistics as dictionary."""
        return {
            "n": self.n,
            "mean": self.mean,
            "std": self.get_std(),
            "variance": self.get_variance()
        }


class OnlineDetector:
    """
    Online Learning Anomaly Detector for Serverless Logs.
    
    Two Phases:
    1. Learning Phase: Builds baseline statistics from first N requests
    2. Detection Phase: Identifies anomalies while continuing to learn from normal requests
    """
    
    def __init__(self, learning_window: int = 100, anomaly_threshold_std: float = 3.0):
        self.learning_window = learning_window
        self.anomaly_threshold_std = anomaly_threshold_std
        self.requests_seen = 0
        self.anomalies_detected = 0
        self.learning_phase = True
        
        # Track statistics for each feature
        self.feature_stats = {
            'duration': OnlineStats(),
            'memory_used': OnlineStats(),
            'num_api_calls': OnlineStats()
        }
        
        # History for visualization
        self.detection_history = []
    
    def extract_features(self, log: Dict) -> Dict[str, float]:
        """Extract relevant features from a log entry."""
        return {
            'duration': float(log.get('duration', 0)),
            'memory_used': float(log.get('memory_used', 0)),
            'num_api_calls': float(log.get('num_api_calls', 0))
        }
    
    def _learn_from_features(self, features: Dict[str, float]) -> None:
        """Update statistics with new feature values."""
        for feature_name, value in features.items():
            if feature_name in self.feature_stats:
                self.feature_stats[feature_name].update(value)
    
    def _calculate_anomaly_score(self, features: Dict[str, float]) -> Tuple[float, Dict]:
        """
        Calculate anomaly score using multi-feature Z-score approach.
        Returns: (score, z_scores_dict)
        """
        z_scores = {}
        for feature_name, value in features.items():
            if feature_name in self.feature_stats:
                z_scores[feature_name] = abs(self.feature_stats[feature_name].get_z_score(value))
        
        # Use max Z-score as the anomaly score
        max_z_score = max(z_scores.values()) if z_scores else 0.0
        normalized_score = min(max_z_score / self.anomaly_threshold_std, 1.0)
        
        return normalized_score, z_scores
    
    def process_log(self, log: Dict) -> Dict:
        """
        Process a single log entry.
        
        Args:
            log: Dictionary containing log data
        
        Returns:
            Dictionary with processing result
        """
        self.requests_seen += 1
        features = self.extract_features(log)
        timestamp = log.get('timestamp', datetime.now().isoformat())
        
        if self.learning_phase:
            # Learning phase: just accumulate statistics
            self._learn_from_features(features)
            progress = (self.requests_seen / self.learning_window) * 100
            
            if self.requests_seen >= self.learning_window:
                self.learning_phase = False
                result = {
                    "phase": "learning_complete",
                    "progress": 100,
                    "message": "Learning phase complete. Baseline established.",
                    "baseline": {feature: stats.to_dict() for feature, stats in self.feature_stats.items()}
                }
            else:
                result = {
                    "phase": "learning",
                    "progress": progress,
                    "message": f"Learning: {self.requests_seen}/{self.learning_window}"
                }
        
        else:
            # Detection phase: score and detect anomalies
            anomaly_score, z_scores = self._calculate_anomaly_score(features)
            is_anomaly = anomaly_score > 0.8
            
            if is_anomaly:
                self.anomalies_detected += 1
                result = {
                    "phase": "detection",
                    "is_anomaly": True,
                    "anomaly_score": anomaly_score,
                    "z_scores": z_scores,
                    "features": features,
                    "baseline": {feature: stats.to_dict() for feature, stats in self.feature_stats.items()},
                    "message": f"ANOMALY DETECTED (Score: {anomaly_score:.2f})"
                }
                # Do NOT learn from anomalies
            else:
                # Learn from normal requests
                self._learn_from_features(features)
                result = {
                    "phase": "detection",
                    "is_anomaly": False,
                    "anomaly_score": anomaly_score,
                    "z_scores": z_scores,
                    "features": features,
                    "baseline": {feature: stats.to_dict() for feature, stats in self.feature_stats.items()},
                    "message": f"Normal (Score: {anomaly_score:.2f})"
                }
        
        # Add to history
        result['timestamp'] = timestamp
        result['requests_seen'] = self.requests_seen
        result['anomalies_detected'] = self.anomalies_detected
        self.detection_history.append(result)
        
        return result
    
    def get_status(self) -> Dict:
        """Get current detector status."""
        return {
            "learning_phase": self.learning_phase,
            "requests_seen": self.requests_seen,
            "anomalies_detected": self.anomalies_detected,
            "learning_progress": min((self.requests_seen / self.learning_window) * 100, 100) if self.learning_phase else 100,
            "baseline": {feature: stats.to_dict() for feature, stats in self.feature_stats.items()}
        }
    
    def get_history(self, limit: int = 50) -> List[Dict]:
        """Get recent detection history."""
        return self.detection_history[-limit:]
