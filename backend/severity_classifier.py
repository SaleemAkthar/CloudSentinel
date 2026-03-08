"""
Severity & Threat Classifier
Classifies anomalies into specific threat types and assigns severity levels.
"""

from typing import Dict, Tuple

class SeverityClassifier:
    def __init__(self):
        # Thresholds for classification
        self.CRITICAL_Z_SCORE = 5.0
        self.HIGH_Z_SCORE = 4.0
        self.MEDIUM_Z_SCORE = 2.5

    def classify_threat(self, features: Dict, z_scores: Dict) -> Tuple[str, str, float]:
        """
        Saleem's Logic: Identifies the type of attack based on feature patterns.
        Returns: (threat_type, severity, confidence)
        """
        duration_z = z_scores.get('duration', 0)
        memory_z = z_scores.get('memory_used', 0)
        api_z = z_scores.get('num_api_calls', 0)
        
        # 1. Crypto Mining Detection (High Duration + High Memory)
        if duration_z > self.HIGH_Z_SCORE and memory_z > self.HIGH_Z_SCORE:
            return "Crypto Mining", "CRITICAL", 0.95
            
        # 2. Data Exfiltration (High API Calls + Moderate Duration)
        if api_z > self.HIGH_Z_SCORE:
            return "Data Exfiltration", "HIGH", 0.88
            
        # 3. Memory Leak / DoS (Extreme Memory Usage)
        if memory_z > self.CRITICAL_Z_SCORE:
            return "Memory Exhaustion", "HIGH", 0.85
            
        # 4. Injection Attacks (High API variability or Error patterns)
        if api_z > self.MEDIUM_Z_SCORE and duration_z < 1.0:
            return "Injection Attempt", "MEDIUM", 0.70

        # Default fallback
        return "Unknown Anomaly", "LOW", 0.50

    def get_confidence_score(self, max_z: float) -> float:
        """Calculates a normalized confidence score (0.0 to 1.0)"""
        return min(max_z / 10.0, 1.0)