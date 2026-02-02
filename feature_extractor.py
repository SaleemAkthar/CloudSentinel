# feature_extractor.py

class FeatureExtractor:
    def extract(self, telemetry):
        features = {
            "execution_time_ms": telemetry["execution_time_ms"],
            "network_call_count": telemetry["network_calls"],
            "error_count": telemetry["errors"]
        }
        return features
