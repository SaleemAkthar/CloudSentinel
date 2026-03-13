# Run from the project root:
#   python -m pytest tests/test_severity.py -v

import unittest
from backend.detection.online_detector import OnlineDetector


class TestSeverityClassifier(unittest.TestCase):
    """Tests that the detector correctly labels anomalous logs with the right
    threat category and severity level."""

    def setUp(self):
        # learning_window=1 so the baseline is established after one warm-up
        # log — avoids sending 100 logs before each test.
        self.det = OnlineDetector(learning_window=1)
        self.det.process_log({"duration": 10, "memory_used": 100, "num_api_calls": 1})

    def test_crypto_mining_detection(self):
        """Extreme duration and memory spike should be labelled Crypto Mining at CRITICAL."""
        result = self.det.process_log({"duration": 5000, "memory_used": 9000, "num_api_calls": 1})

        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["threat_type"], "Crypto Mining")
        self.assertEqual(result["severity"], "CRITICAL")

    def test_data_exfiltration_detection(self):
        """Abnormally high outbound call count should be labelled Data Exfiltration."""
        result = self.det.process_log({"duration": 200, "memory_used": 150, "num_api_calls": 500})

        self.assertTrue(result["is_anomaly"])
        self.assertEqual(result["threat_type"], "Data Exfiltration")
        self.assertIn(result["severity"], ["CRITICAL", "HIGH"])

    def test_normal_log_no_false_positive(self):
        """A normal execution profile should not be flagged as an anomaly."""
        result = self.det.process_log({"duration": 12, "memory_used": 105, "num_api_calls": 1})

        self.assertFalse(result["is_anomaly"], f"False positive on normal log: {result}")

    def test_response_contains_required_keys(self):
        """Every detection-phase response must contain the keys the frontend depends on."""
        result = self.det.process_log({"duration": 20, "memory_used": 110, "num_api_calls": 2})

        for key in ["is_anomaly", "threat_type", "severity", "anomaly_score", "confidence", "z_scores"]:
            self.assertIn(key, result, f"Missing required key: '{key}'")


if __name__ == "__main__":
    unittest.main(verbosity=2)
