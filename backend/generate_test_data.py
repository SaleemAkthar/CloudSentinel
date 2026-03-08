"""
Test Data Generator — Cloud Sentinel
======================================
Generates realistic synthetic log data to populate all frontend dashboard pages
during development and demo sessions.

Usage (run from project root after starting the API):
    python -m backend.generate_test_data

Author: Okitha (Backend Team)
"""

import random
import time
import datetime
import requests

BASE_URL = "http://localhost:8000"

FUNCTION_NAMES = [
    "paymentHandler",
    "authService",
    "dataProcessor",
    "imageResizer",
    "notificationSender",
    "reportGenerator",
    "userProfileService",
    "orderProcessor",
]

PRIVATE_IPS = [f"192.168.1.{i}" for i in range(1, 51)]
PUBLIC_IPS  = [f"203.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
               for _ in range(20)]


# ============================================================================
# PHASE 1 — LEARNING PHASE: Normal Traffic
# ============================================================================

def generate_learning_phase_data(count: int = 100, verbose: bool = True):
    """
    Send `count` normal Lambda execution logs to build the statistical baseline.
    The detector stays in learning phase until it receives 100 logs.
    """
    if verbose:
        print(f"\n[1/4] Generating learning phase data ({count} normal requests)...")

    for i in range(count):
        log = {
            "duration":      random.randint(450, 550),
            "memory_used":   random.randint(120, 140),
            "num_api_calls": random.randint(2, 5),
            "function_name": random.choice(FUNCTION_NAMES),
            "ip_address":    random.choice(PRIVATE_IPS),
        }
        try:
            response = requests.post(f"{BASE_URL}/process_log", json=log, timeout=5)
            if verbose and (i + 1) % 20 == 0:
                print(f"   Progress: {i + 1}/{count}")
        except requests.exceptions.ConnectionError:
            print("  ✗ Cannot connect to API. Is the server running?")
            return False

    if verbose:
        print(f"  ✓ Learning phase complete ({count} normal requests sent)")
    return True


# ============================================================================
# PHASE 2 — ATTACK DATA: Various Attack Patterns
# ============================================================================

def generate_attack_data(verbose: bool = True):
    """
    Send logs that simulate known attack patterns so the detector flags them
    and the alerts dashboard has data to display.
    """
    if verbose:
        print("\n[2/4] Generating attack pattern data...")

    attacks = [
        # Crypto mining — long duration, high memory, low API calls
        {"duration": 12000, "memory_used": 420, "num_api_calls": 1,
         "function_name": "dataProcessor",    "ip_address": "45.33.32.156"},
        {"duration": 15000, "memory_used": 480, "num_api_calls": 2,
         "function_name": "reportGenerator",  "ip_address": "104.21.18.5"},

        # Data exfiltration — excessive outbound API calls
        {"duration": 600,  "memory_used": 150, "num_api_calls": 28,
         "function_name": "paymentHandler",   "ip_address": "185.220.101.1"},
        {"duration": 550,  "memory_used": 145, "num_api_calls": 22,
         "function_name": "userProfileService","ip_address": "185.220.101.2"},

        # Memory exhaustion — near Lambda memory limit
        {"duration": 800,  "memory_used": 495, "num_api_calls": 3,
         "function_name": "imageResizer",     "ip_address": "91.108.4.10"},

        # Anomalous behaviour — combination of spikes
        {"duration": 8000, "memory_used": 380, "num_api_calls": 15,
         "function_name": "authService",      "ip_address": "77.83.247.15"},
        {"duration": 9500, "memory_used": 410, "num_api_calls": 18,
         "function_name": "orderProcessor",   "ip_address": "198.51.100.5"},
    ]

    sent = 0
    for attack in attacks:
        try:
            requests.post(f"{BASE_URL}/process_log", json=attack, timeout=5)
            sent += 1
            time.sleep(0.1)
        except requests.exceptions.ConnectionError:
            print("  ✗ Cannot connect to API.")
            return False

    if verbose:
        print(f"  ✓ {sent} attack logs sent")
    return True


# ============================================================================
# PHASE 3 — MIXED TRAFFIC: Normal + Occasional Anomalies
# ============================================================================

def generate_mixed_traffic(count: int = 50, anomaly_rate: float = 0.15,
                            verbose: bool = True):
    """
    Send a mix of normal and anomalous traffic to populate the Behaviour Logs
    page with realistic data variety.

    Args:
        count:        Total number of requests to send.
        anomaly_rate: Fraction of requests that are anomalous (0–1).
    """
    if verbose:
        print(f"\n[3/4] Generating mixed traffic ({count} requests, "
              f"{int(anomaly_rate * 100)}% anomaly rate)...")

    normal_count  = 0
    anomaly_count = 0

    for _ in range(count):
        fn = random.choice(FUNCTION_NAMES)

        if random.random() < anomaly_rate:
            # Anomalous request
            log = {
                "duration":      random.randint(5000, 14000),
                "memory_used":   random.randint(300, 500),
                "num_api_calls": random.randint(1, 30),
                "function_name": fn,
                "ip_address":    random.choice(PUBLIC_IPS),
            }
            anomaly_count += 1
        else:
            # Normal request
            log = {
                "duration":      random.randint(300, 700),
                "memory_used":   random.randint(100, 160),
                "num_api_calls": random.randint(1, 6),
                "function_name": fn,
                "ip_address":    random.choice(PRIVATE_IPS),
            }
            normal_count += 1

        try:
            requests.post(f"{BASE_URL}/process_log", json=log, timeout=5)
            time.sleep(0.05)
        except requests.exceptions.ConnectionError:
            print("  ✗ Cannot connect to API.")
            return False

    if verbose:
        print(f"  ✓ {normal_count} normal + {anomaly_count} anomalous requests sent")
    return True


# ============================================================================
# PHASE 4 — SARIMA WARM-UP: Time-series Data
# ============================================================================

def generate_sarima_warmup(count: int = 200, verbose: bool = True):
    """
    Send enough normal requests to allow the SARIMA forecaster to train.
    Adds realistic time-of-day variation to the duration values.
    """
    if verbose:
        print(f"\n[4/4] Generating SARIMA warm-up data ({count} requests)...")

    now  = datetime.datetime.utcnow()
    hour = now.hour

    for i in range(count):
        # Simulate hourly traffic pattern (busier at 9-17)
        hour_factor = 1.0 + 0.3 * max(0, 1 - abs(hour - 13) / 4)
        duration    = random.gauss(500 * hour_factor, 40)
        duration    = max(200, duration)

        log = {
            "duration":      round(duration, 1),
            "memory_used":   random.randint(110, 150),
            "num_api_calls": random.randint(2, 5),
            "function_name": random.choice(FUNCTION_NAMES),
            "ip_address":    random.choice(PRIVATE_IPS),
        }
        try:
            requests.post(f"{BASE_URL}/process_log", json=log, timeout=5)
            if verbose and (i + 1) % 50 == 0:
                print(f"   Progress: {i + 1}/{count}")
        except requests.exceptions.ConnectionError:
            print("  ✗ Cannot connect to API.")
            return False

    if verbose:
        print(f"  ✓ SARIMA warm-up complete ({count} data points added)")
    return True


# ============================================================================
# MAIN RUNNER
# ============================================================================

def generate_all_test_data(verbose: bool = True):
    """
    Run all four phases in sequence to fully populate the dashboard.
    Expected runtime: ~60 seconds.
    """
    if verbose:
        print("=" * 55)
        print("  Cloud Sentinel — Test Data Generator")
        print("=" * 55)

    steps = [
        lambda: generate_learning_phase_data(100, verbose),
        lambda: generate_attack_data(verbose),
        lambda: generate_mixed_traffic(50, 0.15, verbose),
        lambda: generate_sarima_warmup(200, verbose),
    ]

    for step in steps:
        if not step():
            print("\n✗ Generation stopped due to connection error.")
            print("  Make sure the API is running: uvicorn backend.api:app --reload --port 8000")
            return False

    if verbose:
        print("\n" + "=" * 55)
        print("  ✓ All test data generated successfully!")
        print("  Open http://localhost:5173 to see the dashboard.")
        print("=" * 55)
    return True


if __name__ == "__main__":
    generate_all_test_data()