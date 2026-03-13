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