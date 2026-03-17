"""
Tests for Layer 1 Scorer
========================

Tests learning phase, detection phase, and all severity levels.
"""

import sys
import os
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

import pytest
from backend.detection.layer1_scorer import Layer1Scorer
from datetime import datetime

def test_learning_phase():
    """Test that scorer learns baseline correctly"""
    scorer = Layer1Scorer(learning_window=10)
    
    # Send 10 normal requests
    for i in range(10):
        features = {
            'duration': 500,
            'memory_used': 130,
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
        score, details = scorer.process_log(features)
        
        # During learning, should not detect anomalies
        assert details['phase'] == 'learning'
        assert details['is_anomaly'] == False
    
    # After 10 requests, should be in detection phase
    assert scorer.learning_phase == False

    def test_normal_request_detection():
        """
        Test that normal requests don't trigger alerts
        """

    scorer = Layer1Scorer(learning_window=10)
    
    # Learn baseline
    for i in range(10):
        scorer.process_log({
            'duration': 500, 'memory_used': 130, 'num_api_calls': 3,
            'error_count': 0, 'concurrency': 1, 'packet_size_in': 1024,
            'packet_size_out': 512, 'latency': 50, 'fragment_count': 1,
            'ip_address': '192.168.1.1', 'timestamp': datetime.now().isoformat()
        })
    
    # Test normal request
    score, details = scorer.process_log({
        'duration': 505, 'memory_used': 128, 'num_api_calls': 3,
        'error_count': 0, 'concurrency': 1, 'packet_size_in': 1024,
        'packet_size_out': 512, 'latency': 50, 'fragment_count': 1,
        'ip_address': '192.168.1.1', 'timestamp': datetime.now().isoformat()
    })
    
    assert details['is_anomaly'] == False
    assert details['severity'] is None
    assert score < 0.4

    def test_critical_severity():
    """
    Test CRITICAL severity detection (crypto-mining)
    """
    scorer = Layer1Scorer(learning_window=10)
    # Learn baseline
    for i in range(10):
        scorer.process_log({
            'duration': 500, 'memory_used': 130, 'num_api_calls': 3,
            'error_count': 0, 'concurrency': 1, 'packet_size_in': 1024,
            'packet_size_out': 512, 'latency': 50, 'fragment_count': 1,
            'ip_address': '192.168.1.1', 'timestamp': datetime.now().isoformat()
        })
    # Test crypto-mining attack
    score, details = scorer.process_log({
        'duration': 10000,  # 20x normal
        'memory_used': 450,  # 3.5x normal
        'num_api_calls': 2,
        'error_count': 0, 'concurrency': 1, 'packet_size_in': 1024,
        'packet_size_out': 512, 'latency': 50, 'fragment_count': 1,
        'ip_address': '192.168.1.100', 'timestamp': datetime.now().isoformat()
    })
    assert details['is_anomaly'] == True
    assert details['severity'] == 'CRITICAL'
    assert score >= 0.8
    assert details['attack_type'] == 'crypto_mining'

    def test_high_severity():
    """Test HIGH severity detection"""
    scorer = Layer1Scorer(learning_window=10)
    
    # Learn baseline
    for i in range(10):
        scorer.process_log({
            'duration': 500, 'memory_used': 130, 'num_api_calls': 3,
            'error_count': 0, 'concurrency': 1, 'packet_size_in': 1024,
            'packet_size_out': 512, 'latency': 50, 'fragment_count': 1,
            'ip_address': '192.168.1.1', 'timestamp': datetime.now().isoformat()
        })
    
    # Test high severity
    score, details = scorer.process_log({
        'duration': 1200, 'memory_used': 200, 'num_api_calls': 8,
        'error_count': 2, 'concurrency': 3, 'packet_size_in': 1024,
        'packet_size_out': 5000, 'latency': 150, 'fragment_count': 3,
        'ip_address': '192.168.1.200', 'timestamp': datetime.now().isoformat()
    })
    
    assert details['is_anomaly'] == True
    assert details['severity'] == 'HIGH'
    assert 0.6 <= score < 0.8


def test_medium_severity():
    """Test MEDIUM severity detection"""
    scorer = Layer1Scorer(learning_window=10)
    
    # Learn baseline
    for i in range(10):
        scorer.process_log({
            'duration': 500, 'memory_used': 130, 'num_api_calls': 3,
            'error_count': 0, 'concurrency': 1, 'packet_size_in': 1024,
            'packet_size_out': 512, 'latency': 50, 'fragment_count': 1,
            'ip_address': '192.168.1.1', 'timestamp': datetime.now().isoformat()
        })
    
    # Test medium severity
    score, details = scorer.process_log({
        'duration': 650, 'memory_used': 145, 'num_api_calls': 5,
        'error_count': 1, 'concurrency': 2, 'packet_size_in': 1024,
        'packet_size_out': 1500, 'latency': 80, 'fragment_count': 2,
        'ip_address': '192.168.1.150', 'timestamp': datetime.now().isoformat()
    })
    
    assert details['is_anomaly'] == True
    assert details['severity'] == 'MEDIUM'
    assert 0.4 <= score < 0.6

    if __name__ == "__main__":
    # Run tests
    print("Running Layer 1 Scorer Tests...\n")
    
    test_learning_phase()
    print("Learning phase test passed")
    
    test_normal_request_detection()
    print(" Normal request test passed")
    
    test_critical_severity()
    print("CRITICAL severity test passed")
    
    test_high_severity()
    print(" HIGH severity test passed")
    
    test_medium_severity()
    print(" MEDIUM severity test passed")
    
    print("\n" + "="*50)
    print("ALL TESTS PASSED")
    print("="*50)



