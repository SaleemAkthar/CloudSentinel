"""
Cloud Sentinel — Cluster Test Script
======================================
Tests the clustered setup by sending traffic through the load balancer
and verifying that all 3 backend nodes are receiving requests.

Usage:
    python test_cluster.py              (test local Docker cluster)
    python test_cluster.py http://ALB   (test AWS cluster)

Author: Backend Team
"""

import requests
import sys
import time
import random
import json

LB_URL = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


def test_health():
    """Check load balancer and backend health."""
    section("TEST 1 — Health Check")

    # Load balancer health
    try:
        resp = requests.get(f"{LB_URL}/health", timeout=5)
        print(f"  Load balancer: {resp.json()}")
    except Exception as e:
        print(f"  Load balancer: FAILED — {e}")
        return False

    # Backend health (routed through LB)
    try:
        resp = requests.get(f"{LB_URL}/status", timeout=5)
        data = resp.json()
        print(f"  Backend status: {data.get('status')}")
        print(f"  Pipeline: {data.get('pipeline')}")
        print(f"  AI phase: {data.get('detector_stats', {}).get('phase')}")
        node = resp.headers.get("X-Backend-Node", "unknown")
        print(f"  Handled by: {node}")
    except Exception as e:
        print(f"  Backend: FAILED — {e}")
        return False

    return True


def test_node_distribution():
    """Send 30 requests and check which nodes handle them."""
    section("TEST 2 — Node Distribution")

    node_counts = {}

    for i in range(30):
        try:
            # Use different source headers to test sticky session distribution
            headers = {"X-Forwarded-For": f"10.0.{i % 10}.{random.randint(1,254)}"}
            resp = requests.get(f"{LB_URL}/status", headers=headers, timeout=5)
            node = resp.headers.get("X-Backend-Node", "unknown")
            node_counts[node] = node_counts.get(node, 0) + 1
        except:
            node_counts["FAILED"] = node_counts.get("FAILED", 0) + 1

    print("  Request distribution across nodes:")
    for node, count in sorted(node_counts.items()):
        bar = "█" * count
        print(f"    {node:30s} │ {count:3d} │ {bar}")

    if len(node_counts) >= 2 and "FAILED" not in node_counts:
        print(f"\n  Traffic routed to {len(node_counts)} nodes")
    else:
        print(f"\n  WARNING: Traffic only hitting {len(node_counts)} node(s)")


def test_learning_phase():
    """Send normal traffic to build the AI model baseline."""
    section("TEST 3 — Learning Phase (100 normal requests)")

    normal = {
        "duration": 450, "memory_used": 130, "num_api_calls": 3,
        "function_name": "authService", "ip_address": "203.45.67.89",
        "ttl": 64, "packet_size_in": 512, "packet_size_out": 256,
        "dest_port": 443,
    }

    allowed = 0
    for i in range(100):
        try:
            resp = requests.post(f"{LB_URL}/process_log", json=normal, timeout=5)
            data = resp.json()
            if data.get("decision") == "ALLOW":
                allowed += 1
            if (i + 1) % 25 == 0:
                node = resp.headers.get("X-Backend-Node", "?")
                print(f"    {i+1}/100 — decision: {data.get('decision')} (node: {node})")
        except Exception as e:
            print(f"    Request {i+1} FAILED: {e}")

    print(f"\n  {allowed}/100 normal requests allowed")


def test_attack_detection():
    """Send attacks and verify they get caught."""
    section("TEST 4 — Attack Detection")

    attacks = [
        {
            "name": "Crypto Mining",
            "body": {
                "duration": 12000, "memory_used": 450, "num_api_calls": 2,
                "function_name": "paymentHandler", "ip_address": "185.220.101.45",
                "ttl": 44, "packet_size_in": 128, "packet_size_out": 64,
                "dest_port": 443,
            },
        },
        {
            "name": "DDoS",
            "body": {
                "duration": 30, "memory_used": 60, "num_api_calls": 120,
                "function_name": "apiHandler", "ip_address": "194.165.16.100",
                "ttl": 42, "packet_size_in": 64, "packet_size_out": 32,
                "fragment_count": 14, "dest_port": 80,
            },
        },
        {
            "name": "Data Exfiltration",
            "body": {
                "duration": 550, "memory_used": 380, "num_api_calls": 30,
                "function_name": "dataProcessor", "ip_address": "45.142.212.100",
                "ttl": 48, "packet_size_in": 150, "packet_size_out": 5000,
                "dest_port": 443, "unique_destinations": 10,
            },
        },
        {
            "name": "SQL Injection",
            "body": {
                "duration": 6000, "memory_used": 300, "num_api_calls": 12,
                "function_name": "userProfileService", "ip_address": "89.248.160.10",
                "ttl": 55, "packet_size_in": 512, "packet_size_out": 1200,
                "dest_port": 1433, "error_count": 8,
            },
        },
        {
            "name": "IP Spoofing",
            "body": {
                "duration": 200, "memory_used": 100, "num_api_calls": 15,
                "function_name": "authService", "ip_address": "192.168.1.50",
                "ttl": 20, "packet_size_in": 400, "packet_size_out": 300,
                "dest_port": 22, "unique_destinations": 6,
            },
        },
        {
            "name": "Memory Attack",
            "body": {
                "duration": 9000, "memory_used": 490, "num_api_calls": 5,
                "function_name": "imageResizer", "ip_address": "80.82.77.5",
                "ttl": 48, "packet_size_in": 256, "packet_size_out": 128,
                "error_count": 4, "dest_port": 443,
            },
        },
    ]

    caught = 0
    for attack in attacks:
        try:
            resp = requests.post(f"{LB_URL}/process_log", json=attack["body"], timeout=10)
            data = resp.json()
            decision = data.get("decision", "?")
            severity = data.get("severity", "?")
            violations = data.get("layer1", {}).get("violations", [])
            node = resp.headers.get("X-Backend-Node", "?")

            is_caught = decision in ("BLOCK", "INVESTIGATE")
            if is_caught:
                caught += 1

            status = "CAUGHT" if is_caught else "MISSED"
            print(f"  {status:7s} │ {attack['name']:20s} │ {decision:11s} │ {severity:8s} │ node: {node}")
            if violations:
                print(f"          │ L1: {violations[0]}")
        except Exception as e:
            print(f"  FAILED  │ {attack['name']:20s} │ {e}")

    print(f"\n  Detection rate: {caught}/{len(attacks)} attacks caught")


def test_alerts():
    """Check that alerts were created."""
    section("TEST 5 — Alert Verification")

    try:
        resp = requests.get(f"{LB_URL}/api/alerts", timeout=5)
        alerts = resp.json()
        print(f"  Total alerts: {len(alerts)}")

        open_alerts = [a for a in alerts if a.get("status") == "OPEN"]
        print(f"  Open alerts:  {len(open_alerts)}")

        if alerts:
            print(f"\n  Latest alerts:")
            for a in alerts[:5]:
                print(f"    {a['id']} │ {a.get('severity'):8s} │ {a.get('threat_type'):20s} │ {a.get('decision')}")

            # Test block action on first alert
            first_id = alerts[0]["id"]
            print(f"\n  Blocking alert {first_id}...")
            resp = requests.patch(f"{LB_URL}/api/alerts/{first_id}/block", timeout=5)
            result = resp.json()
            print(f"  Result: {result.get('resolution')}")
    except Exception as e:
        print(f"  FAILED: {e}")


def test_model_health():
    """Check AI model status."""
    section("TEST 6 — AI Model Health")

    try:
        resp = requests.get(f"{LB_URL}/api/model/health", timeout=5)
        data = resp.json()

        print(f"  Phase:              {data.get('ensemble', {}).get('phase')}")
        print(f"  Isolation Forest:   {'Trained' if data.get('ensemble', {}).get('isolation_forest_trained') else 'Learning'}")
        print(f"  Random Forest:      {'Trained' if data.get('ensemble', {}).get('random_forest_trained') else 'Waiting for data'}")
        print(f"  Labeled examples:   {data.get('ensemble', {}).get('labeled_examples')}")
        print(f"  Accuracy:           {data.get('accuracy')}%")
        print(f"  Precision:          {data.get('precision')}%")
        print(f"  Recall:             {data.get('recall')}%")
        print(f"  SARIMA trained:     {data.get('sarima_trained')}")
    except Exception as e:
        print(f"  FAILED: {e}")


def main():
    print("=" * 60)
    print("  CLOUD SENTINEL — CLUSTER TEST")
    print(f"  Target: {LB_URL}")
    print("=" * 60)

    if not test_health():
        print("\n  Cannot reach cluster. Is it running?")
        print("  docker-compose up --build")
        return

    test_node_distribution()
    test_learning_phase()
    test_attack_detection()
    test_alerts()
    test_model_health()

    section("CLUSTER TEST COMPLETE")
    print("  All tests finished. Check results above.\n")


if __name__ == "__main__":
    main()