# ml_model.py

import json

class AnomalyDetector:
    def __init__(self, baseline_path="baseline.json"):
        with open(baseline_path, "r") as f:
            self.baseline = json.load(f)

    def infer(self, features):
        score = 0

        if features["execution_time_ms"] > self.baseline["max_execution_time_ms"]:
            score += 0.5

        if features["network_call_count"] > self.baseline["max_network_calls"]:
            score += 0.5

        is_anomalous = score >= 0.5

        return {
            "anomaly_score": score,
            "anomalous": is_anomalous
        }
