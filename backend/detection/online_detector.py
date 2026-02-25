"""
Cloud Sentinel:Learning Anomaly Detector
Welford's Algorithm, Multi-feature Z-scoring, and Severity Classification
"""

from datetime import datetime
from typing import Dict, List, Tuple

class OnlineStats:
    """Welford's Algorithm for computing running mean and variance."""
    def __init__(self):
        self.n = 0
        self.mean = 0.0
        self.M2 = 0.0 
    
    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        delta2 = x - self.mean
        self.M2 += delta * delta2
    
    def get_mean(self) -> float:
        return self.mean
    
    def get_variance(self) -> float:
        return self.M2 / (self.n - 1) if self.n >= 2 else 0.0
    
    def get_std(self) -> float:
        return self.get_variance() ** 0.5
    
    def get_z_score(self, x: float) -> float:
        std = self.get_std()
        return (x - self.mean) / std if std > 0 else 0.0

    def to_dict(self) -> Dict:
        return {"n": self.n, "mean": self.mean, "std": self.get_std()}

class SeverityClassifier:
    """
    Saleem's Component: Logic to classify anomalies into threat types.
    """
    def classify(self, features: Dict, z_scores: Dict) -> Dict:
        dur_z = abs(z_scores.get('duration', 0))
        mem_z = abs(z_scores.get('memory_used', 0))
        api_z = abs(z_scores.get('num_api_calls', 0))

        # 1. Crypto Mining: Long duration and high memory usage
        if dur_z > 4.0 and mem_z > 2.0:
            return {"type": "Crypto Mining", "severity": "CRITICAL", "confidence": 0.95}
        
        # 2. Data Exfiltration: Unusual number of API/Outbound calls
        if api_z > 4.0:
            return {"type": "Data Exfiltration", "severity": "HIGH", "confidence": 0.88}
            
        # 3. Memory Leak: Extreme memory usage
        if mem_z > 5.0:
            return {"type": "Memory Exhaustion", "severity": "HIGH", "confidence": 0.92}

        return {"type": "Anomalous Behavior", "severity": "MEDIUM", "confidence": 0.65}

class OnlineDetector:
    def __init__(self, learning_window: int = 100, anomaly_threshold: float = 3.0):
        self.learning_window = learning_window
        self.threshold = anomaly_threshold
        self.requests_seen = 0
        self.anomalies_detected = 0
        self.learning_phase = True
        
        self.feature_stats = {
            'duration': OnlineStats(),
            'memory_used': OnlineStats(),
            'num_api_calls': OnlineStats()
        }
        self.classifier = SeverityClassifier()
        self.detection_history = []

    def extract_features(self, log: Dict) -> Dict[str, float]:
        return {
            'duration': float(log.get('duration', 0)),
            'memory_used': float(log.get('memory_used', 0) or log.get('memoryUsed', 0)),
            'num_api_calls': float(len(log.get('apiCalls', [])) if isinstance(log.get('apiCalls'), list) else log.get('num_api_calls', 0))
        }

    def process_log(self, log: Dict) -> Dict:
        self.requests_seen += 1
        features = self.extract_features(log)
        
        if self.learning_phase:
            for feat, val in features.items():
                self.feature_stats[feat].update(val)
            
            if self.requests_seen >= self.learning_window:
                self.learning_phase = False
            
            return {"phase": "learning", "progress": (self.requests_seen / self.learning_window) * 100}

        # Detection Phase
        z_scores = {f: self.feature_stats[f].get_z_score(v) for f, v in features.items()}
        max_z = max([abs(z) for z in z_scores.values()])
        is_anomaly = max_z > self.threshold

        if is_anomaly:
            self.anomalies_detected += 1
            threat = self.classifier.classify(features, z_scores)
            result = {
                "is_anomaly": True,
                "threat_type": threat["type"],
                "severity": threat["severity"],
                "confidence": threat["confidence"],
                "anomaly_score": round(max_z, 2),
                "z_scores": z_scores
            }
        else:
            # Update baseline only with normal data to prevent poisoning
            for feat, val in features.items():
                self.feature_stats[feat].update(val)
            result = {"is_anomaly": False, "anomaly_score": round(max_z, 2)}

        result.update({"timestamp": datetime.now().isoformat(), "features": features})
        self.detection_history.append(result)
        return result

    def get_status(self):
        return {
            "requests_processed": self.requests_seen,
            "anomalies_found": self.anomalies_detected,
            "phase": "Detection" if not self.learning_phase else "Learning"
        }