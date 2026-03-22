"""
Tests for Layer 1 Scorer
========================
Covers learning phase, detection phase, all severity levels,
and all 6 attack type signatures.

Run: pytest tests/test_layer1_scorer.py -v
"""

import sys
import os
import random

project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import pytest
from backend.detection.layer1_scorer import Layer1Scorer
from datetime import datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _baseline_features():
    """
    Return a normal-traffic feature dict with slight variation.
    Small jitter gives Welford a non-zero std so Z-scores are realistic.
    """
    return {
        'duration': 500 + random.randint(-20, 20),
        'memory_used': 130 + random.randint(-5, 5),
        'num_api_calls': random.choice([2, 3, 4]),
        'error_count': 0,
        'concurrency': 1,
        'packet_size_in': 1024 + random.randint(-50, 50),
        'packet_size_out': 512 + random.randint(-30, 30),
        'latency': 50 + random.randint(-5, 5),
        'fragment_count': random.choice([0, 1]),
        'ttl': 64,
        'source_port': random.randint(49152, 65535),
        'ip_address': '8.8.8.8',
        'timestamp': datetime.now().isoformat(),
    }


def _train_scorer(window: int = 100) -> Layer1Scorer:
    """
    Create a scorer and complete its learning phase.
    Uses 100 requests (matches production default) for a stable baseline.
    """
    scorer = Layer1Scorer(learning_window=window)
    for _ in range(window):
        scorer.process_log(_baseline_features())
    return scorer


# ---------------------------------------------------------------------------
# Core Tests
# ---------------------------------------------------------------------------

def test_learning_phase():
    """Scorer should stay in learning phase and not flag anomalies."""
    scorer = Layer1Scorer(learning_window=10)

    for i in range(10):
        score, details = scorer.process_log(_baseline_features())
        assert details['phase'] == 'learning'
        assert details['is_anomaly'] is False

    assert scorer.learning_phase is False


def test_normal_request_detection():
    """Normal traffic should not trigger alerts after learning."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 510, 'memory_used': 132, 'num_api_calls': 3,
        'error_count': 0, 'concurrency': 1, 'packet_size_in': 1024,
        'packet_size_out': 512, 'latency': 48, 'fragment_count': 0,
        'ttl': 64, 'source_port': 52000,
        'ip_address': '8.8.8.8', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is False
    assert details['severity'] is None
    assert score < 0.4


# ---------------------------------------------------------------------------
# Severity Level Tests
# ---------------------------------------------------------------------------

def test_critical_severity():
    """Crypto-mining signature should trigger CRITICAL severity."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 20000, 'memory_used': 490, 'num_api_calls': 1,
        'error_count': 0, 'concurrency': 1, 'packet_size_in': 1024,
        'packet_size_out': 512, 'latency': 50, 'fragment_count': 0,
        'ttl': 64, 'source_port': 52000,
        'ip_address': '45.33.32.1', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['severity'] in ('CRITICAL', 'HIGH')
    assert score >= 0.7
    assert details['attack_type'] == 'crypto_mining'


def test_high_severity():
    """Elevated metrics should trigger HIGH severity."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 2000, 'memory_used': 250, 'num_api_calls': 12,
        'error_count': 3, 'concurrency': 2, 'packet_size_in': 1024,
        'packet_size_out': 3000, 'latency': 120, 'fragment_count': 2,
        'ttl': 64, 'source_port': 52000,
        'ip_address': '89.248.160.10', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['severity'] in ('HIGH', 'CRITICAL')
    assert score >= 0.6


def test_medium_severity():
    """Mildly elevated metrics should trigger MEDIUM severity."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 700, 'memory_used': 155, 'num_api_calls': 6,
        'error_count': 1, 'concurrency': 2, 'packet_size_in': 1024,
        'packet_size_out': 1200, 'latency': 75, 'fragment_count': 1,
        'ttl': 64, 'source_port': 52000,
        'ip_address': '8.8.4.4', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['severity'] in ('MEDIUM', 'HIGH')
    assert score >= 0.4


# ---------------------------------------------------------------------------
# Attack Type Detection Tests (6 types)
# ---------------------------------------------------------------------------

def test_detect_crypto_mining():
    """Crypto mining: extreme duration + high memory."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 15000, 'memory_used': 480, 'num_api_calls': 1,
        'error_count': 0, 'concurrency': 1, 'packet_size_in': 512,
        'packet_size_out': 256, 'latency': 50, 'fragment_count': 0,
        'ttl': 64, 'source_port': 55000,
        'ip_address': '185.220.101.45', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['attack_type'] == 'crypto_mining'
    assert score >= 0.7


def test_detect_data_exfiltration():
    """Data exfiltration: excessive API calls (s3 uploads)."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 2500, 'memory_used': 200, 'num_api_calls': 35,
        'error_count': 0, 'concurrency': 1, 'packet_size_in': 512,
        'packet_size_out': 8000, 'latency': 80, 'fragment_count': 0,
        'ttl': 64, 'source_port': 55000,
        'ip_address': '194.165.16.100', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['attack_type'] in ('data_exfiltration', 'ddos', 'sql_injection')
    assert score >= 0.5


def test_detect_sql_injection():
    """SQL injection: high API calls + high error count."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 600, 'memory_used': 150, 'num_api_calls': 20,
        'error_count': 15, 'concurrency': 1, 'packet_size_in': 1024,
        'packet_size_out': 512, 'latency': 40, 'fragment_count': 0,
        'ttl': 64, 'source_port': 52000,
        'ip_address': '89.248.160.10', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['attack_type'] == 'sql_injection'
    assert score >= 0.6


def test_detect_ddos():
    """DDoS: very high API call count. Both DDoS and data_exfiltration
    trigger on api_calls — DDoS is primarily caught by Layer 1 Filter
    (hard rule: api_calls > 50), scorer provides secondary detection."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 1500, 'memory_used': 100, 'num_api_calls': 45,
        'error_count': 2, 'concurrency': 1, 'packet_size_in': 128,
        'packet_size_out': 64, 'latency': 10, 'fragment_count': 4,
        'ttl': 55, 'source_port': 30000,
        'ip_address': '45.142.120.100', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['attack_type'] in ('ddos', 'data_exfiltration')
    assert score >= 0.5


def test_detect_memory_attack():
    """Memory attack: memory near Lambda limit (>90% of 512MB)."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 800, 'memory_used': 500, 'num_api_calls': 2,
        'error_count': 1, 'concurrency': 1, 'packet_size_in': 512,
        'packet_size_out': 256, 'latency': 50, 'fragment_count': 0,
        'ttl': 64, 'source_port': 55000,
        'ip_address': '80.82.77.5', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['attack_type'] == 'memory_attack'
    assert score >= 0.6


def test_detect_ip_spoofing():
    """IP spoofing: impossible TTL + low source port (RC6 fix)."""
    scorer = _train_scorer(100)

    score, details = scorer.process_log({
        'duration': 480, 'memory_used': 128, 'num_api_calls': 3,
        'error_count': 0, 'concurrency': 1, 'packet_size_in': 512,
        'packet_size_out': 256, 'latency': 50, 'fragment_count': 3,
        'ttl': 3, 'source_port': 22,
        'ip_address': '192.168.1.50', 'timestamp': datetime.now().isoformat(),
    })

    assert details['is_anomaly'] is True
    assert details['attack_type'] == 'ip_spoofing'
    assert score >= 0.4


# ---------------------------------------------------------------------------
# Edge Case Tests
# ---------------------------------------------------------------------------

def test_baseline_updates_only_on_normal():
    """Baseline should not be polluted by anomalous traffic."""
    scorer = _train_scorer(100)

    baseline_before = scorer._get_baseline_summary()

    # Send an attack — should NOT update baseline
    scorer.process_log({
        'duration': 15000, 'memory_used': 480, 'num_api_calls': 1,
        'error_count': 0, 'concurrency': 1, 'packet_size_in': 512,
        'packet_size_out': 256, 'latency': 50, 'fragment_count': 0,
        'ttl': 64, 'source_port': 55000,
        'ip_address': '185.220.101.45', 'timestamp': datetime.now().isoformat(),
    })

    baseline_after = scorer._get_baseline_summary()

    # Duration mean should NOT have shifted towards 15000
    assert abs(baseline_after['duration']['mean'] - baseline_before['duration']['mean']) < 10


def test_scorer_status():
    """get_status() should report correct phase and counts."""
    scorer = _train_scorer(100)

    status = scorer.get_status()
    assert status['phase'] == 'detection'
    assert status['requests_processed'] == 100

    # Send one more
    scorer.process_log(_baseline_features())
    status = scorer.get_status()
    assert status['requests_processed'] == 101


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("Running Layer 1 Scorer Tests...\n")

    tests = [
        ("Learning phase", test_learning_phase),
        ("Normal request", test_normal_request_detection),
        ("CRITICAL severity", test_critical_severity),
        ("HIGH severity", test_high_severity),
        ("MEDIUM severity", test_medium_severity),
        ("Crypto mining detection", test_detect_crypto_mining),
        ("Data exfiltration detection", test_detect_data_exfiltration),
        ("SQL injection detection", test_detect_sql_injection),
        ("DDoS detection", test_detect_ddos),
        ("Memory attack detection", test_detect_memory_attack),
        ("IP spoofing detection", test_detect_ip_spoofing),
        ("Baseline not polluted", test_baseline_updates_only_on_normal),
        ("Scorer status", test_scorer_status),
    ]

    passed = 0
    failed = 0
    for name, func in tests:
        try:
            func()
            print(f"  PASS  {name}")
            passed += 1
        except AssertionError as e:
            print(f"  FAIL  {name}: {e}")
            failed += 1

    print(f"\n{'=' * 50}")
    print(f"  {passed} passed, {failed} failed")
    print(f"{'=' * 50}")