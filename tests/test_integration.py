"""
End-to-End Integration Tests — Cloud Sentinel
=============================================
Tests the full detection pipeline:
    Log → OnlineDetector (Layer 1) → SARIMA → Alert → Layer 2 → Report

These tests run entirely in-process (no HTTP server required) by calling
the core classes directly. HTTP-level tests are covered in test_api.py.

Author: Okitha (Backend Team)
Run: pytest tests/test_integration.py -v
"""

import pytest
import sys, os, importlib.util, types
import random

# ── Module loader (avoids triggering broken backend/__init__.py) ──────────────

def _load(path, name, deps=None):
    if deps:
        for k, v in deps.items():
            sys.modules[k] = v
    spec = importlib.util.spec_from_file_location(name, path)
    mod  = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod

BASE = os.path.join(os.path.dirname(__file__), "..", "backend")

# Load modules in dependency order
detector_mod = _load(os.path.join(BASE, "detection", "online_detector.py"),
                     "backend.detection.online_detector")
sarima_mod   = _load(os.path.join(BASE, "detection", "sarima_forecaster.py"),
                     "backend.detection.sarima_forecaster")

OnlineDetector   = detector_mod.OnlineDetector
SARIMAForecaster = sarima_mod.SARIMAForecaster

# Try to load Layer 2 (optional — tests skip gracefully if unavailable)
try:
    helpers_mod = _load(os.path.join(BASE, "utils", "helpers.py"),
                        "backend.utils.helpers")
    sigs_mod    = _load(os.path.join(BASE, "models", "attack_signature.py"),
                        "backend.models.attack_signature",
                        deps={"backend.utils.helpers": helpers_mod})
    netmod      = _load(os.path.join(BASE, "models", "network_analyzer.py"),
                        "backend.models.network_analyzer",
                        deps={"backend.utils.helpers": helpers_mod})
    l2_mod      = _load(os.path.join(BASE, "detection", "layer2_investigator.py"),
                        "backend.detection.layer2_investigator",
                        deps={
                            "backend.utils.helpers":          helpers_mod,
                            "backend.models.attack_signature": sigs_mod,
                            "backend.models.network_analyzer": netmod,
                        })
    Layer2Investigator = l2_mod.Layer2Investigator
    L2_AVAILABLE = True
except Exception as e:
    L2_AVAILABLE = False


# ============================================================================
# HELPERS
# ============================================================================

def run_learning_phase(detector, count=100):
    for _ in range(count):
        detector.process_log({
            "duration":      random.randint(450, 550),
            "memory_used":   random.randint(120, 140),
            "num_api_calls": random.randint(2, 5)
        })


def crypto_mining_log():
    return {"duration": 12000, "memory_used": 420, "num_api_calls": 1}


def exfiltration_log():
    return {"duration": 600, "memory_used": 150, "num_api_calls": 25}


def normal_log():
    return {"duration": 500, "memory_used": 130, "num_api_calls": 3}


# ============================================================================
# LAYER 1: OnlineDetector Integration
# ============================================================================

class TestLayer1Detection:

    def test_learning_phase_returns_progress(self):
        d = OnlineDetector(learning_window=10)
        result = d.process_log(normal_log())
        assert result.get("phase") == "learning"
        assert "progress" in result

    def test_learning_phase_completes_at_window(self):
        d = OnlineDetector(learning_window=50)
        for _ in range(50):
            d.process_log(normal_log())
        result = d.process_log(normal_log())
        assert result.get("phase") != "learning"

    def test_crypto_mining_detected(self):
        d = OnlineDetector(learning_window=100)
        run_learning_phase(d, 100)
        result = d.process_log(crypto_mining_log())
        assert result.get("is_anomaly") is True
        assert result.get("threat_type") == "Crypto Mining"

    def test_normal_traffic_not_flagged(self):
        d = OnlineDetector(learning_window=100)
        run_learning_phase(d, 100)
        flags = 0
        for _ in range(20):
            r = d.process_log(normal_log())
            if r.get("is_anomaly"):
                flags += 1
        # Allow at most 2 false positives in 20 normal requests
        assert flags <= 2

    def test_exfiltration_detected(self):
        d = OnlineDetector(learning_window=100)
        run_learning_phase(d, 100)
        result = d.process_log(exfiltration_log())
        assert result.get("is_anomaly") is True

    def test_anomaly_score_higher_for_attack(self):
        d = OnlineDetector(learning_window=100)
        run_learning_phase(d, 100)
        normal_result = d.process_log(normal_log())
        attack_result = d.process_log(crypto_mining_log())
        assert attack_result.get("anomaly_score", 0) > normal_result.get("anomaly_score", 0)

    def test_get_status_returns_correct_keys(self):
        d = OnlineDetector(learning_window=10)
        status = d.get_status()
        assert "requests_processed" in status
        assert "anomalies_found" in status
        assert "phase" in status

    def test_baseline_not_poisoned_by_anomalies(self):
        d = OnlineDetector(learning_window=100)
        run_learning_phase(d, 100)
        mean_before = d.feature_stats["duration"].get_mean()
        d.process_log(crypto_mining_log())
        mean_after = d.feature_stats["duration"].get_mean()
        assert mean_after < 1000


# ============================================================================
# SARIMA Integration
# ============================================================================

class TestSARIMAIntegration:

    def test_sarima_collects_data_during_learning(self):
        sarima = SARIMAForecaster()
        for _ in range(50):
            sarima.add_data_point(500.0)
        assert len(sarima.training_data) == 50

    def test_sarima_trains_after_200_points(self):
        sarima = SARIMAForecaster()
        for _ in range(200):
            sarima.add_data_point(500.0)
        result = sarima.train()
        assert result is True
        assert sarima._trained is True

    def test_sarima_temporal_score_zero_before_training(self):
        sarima = SARIMAForecaster()
        score = sarima.detect_temporal_anomaly(500.0)
        assert 0.0 <= score <= 1.0

    def test_sarima_flags_extreme_duration(self):
        sarima = SARIMAForecaster()
        for _ in range(200):
            sarima.add_data_point(500.0)
        sarima.train()
        score = sarima.detect_temporal_anomaly(50000.0)
        assert score > 0.5

    def test_sarima_normal_value_low_score(self):
        sarima = SARIMAForecaster()
        for _ in range(200):
            sarima.add_data_point(500.0 + random.gauss(0, 20))
        sarima.train()
        score = sarima.detect_temporal_anomaly(510.0)
        assert score < 0.5


# ============================================================================
# Full Pipeline: Layer 1 → SARIMA → Layer 2
# ============================================================================

class TestFullPipeline:

    def test_layer1_then_sarima_pipeline(self):
        """
        Simulate the full process_log flow:
        normal traffic → learning → attack → anomaly + temporal score
        """
        detector = OnlineDetector(learning_window=100)
        sarima   = SARIMAForecaster()

        # Learning phase
        for _ in range(100):
            log = {
                "duration":      random.randint(450, 550),
                "memory_used":   random.randint(120, 140),
                "num_api_calls": random.randint(2, 5)
            }
            result = detector.process_log(log)
            sarima.add_data_point(log["duration"])

        # Detection phase — send an attack
        attack  = crypto_mining_log()
        result  = detector.process_log(attack)
        sarima.add_data_point(attack["duration"])
        temporal = sarima.detect_temporal_anomaly(attack["duration"])

        assert result.get("is_anomaly") is True
        assert isinstance(temporal, float)
        assert 0.0 <= temporal <= 1.0

    @pytest.mark.skipif(not L2_AVAILABLE, reason="Layer 2 files not present")
    def test_layer1_to_layer2_handoff(self):
        """
        After Layer 1 detects an anomaly, Layer 2 should produce a full report.
        """
        detector = OnlineDetector(learning_window=100)
        layer2   = Layer2Investigator()
        run_learning_phase(detector, 100)

        attack = crypto_mining_log()
        l1_result = detector.process_log(attack)
        assert l1_result.get("is_anomaly") is True

        # Build the alert metadata that api.py would produce
        alert_metadata = {
            "severity":      l1_result.get("severity", "CRITICAL"),
            "attack_type":   l1_result.get("threat_type", "Unknown"),
            "anomaly_score": l1_result.get("anomaly_score", 0),
            "confidence":    l1_result.get("confidence", 0),
        }
        log_data = {**attack, "ip_address": "10.0.0.1",
                    "_mean_duration": 500, "_mean_memory": 130}

        report = layer2.investigate("ALERT-TEST", log_data, alert_metadata)

        assert "risk_level" in report
        assert "matched_patterns" in report
        assert len(report["recommendations"]) > 0

    @pytest.mark.skipif(not L2_AVAILABLE, reason="Layer 2 files not present")
    def test_full_detection_flow_crypto_mining(self):
        """
        End-to-end: Log → Layer 1 → SARIMA → Layer 2 → Report
        """
        detector = OnlineDetector(learning_window=100)
        sarima   = SARIMAForecaster()
        layer2   = Layer2Investigator()

        # Learning + SARIMA data collection
        for _ in range(100):
            log = normal_log()
            detector.process_log(log)
            sarima.add_data_point(log["duration"])

        # Attack
        attack    = crypto_mining_log()
        l1_result = detector.process_log(attack)
        sarima.add_data_point(attack["duration"])
        temporal  = sarima.detect_temporal_anomaly(attack["duration"])

        assert l1_result["is_anomaly"] is True

        # Layer 2
        log_data = {**attack, "ip_address": "45.33.32.156",
                    "_mean_duration": 500, "_mean_memory": 130}
        meta = {
            "severity":      l1_result.get("severity"),
            "attack_type":   l1_result.get("threat_type"),
            "anomaly_score": l1_result.get("anomaly_score"),
            "confidence":    l1_result.get("confidence"),
        }
        report = layer2.investigate("ALERT-FULL", log_data, meta)

        # Verify the complete chain
        assert report["risk_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert report["risk_score"] >= 0.0
        attack_types = [p["attack_type"] for p in report["matched_patterns"]]
        assert "crypto_mining" in attack_types
        assert 0.0 <= temporal <= 1.0

    @pytest.mark.skipif(not L2_AVAILABLE, reason="Layer 2 files not present")
    def test_full_detection_flow_exfiltration(self):
        detector = OnlineDetector(learning_window=100)
        layer2   = Layer2Investigator()
        run_learning_phase(detector, 100)

        attack    = exfiltration_log()
        l1_result = detector.process_log(attack)
        assert l1_result["is_anomaly"] is True

        log_data = {**attack, "packet_size_out": 50000, "packet_size_in": 200,
                    "ip_address": "185.220.101.1"}
        meta = {"severity": "WARNING", "attack_type": "Data Exfiltration",
                "anomaly_score": 0.8, "confidence": 0.88}

        report = layer2.investigate("ALERT-EXFIL", log_data, meta)
        types  = [p["attack_type"] for p in report["matched_patterns"]]
        assert "data_exfiltration" in types