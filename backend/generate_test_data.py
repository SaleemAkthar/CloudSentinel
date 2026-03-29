"""
Test Data Generator — Cloud Sentinel (Unified Pipeline)
Generates realistic traffic with full packet-level fields so
the unified pipeline (Layer 1 Filter → Layer 2 → AI Model)
can be tested end-to-end.

Usage (run from project root after starting the API):
    python -m backend.generate_test_data

Author: Okitha (Backend Team)
"""

import random
import time
import datetime
import os
import requests

BASE_URL = os.environ.get("API_URL", "https://dfz05quh5rzd4.cloudfront.net")

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

# Known malicious IPs for attack simulation
MALICIOUS_IPS = [
    "185.220.101.45", "45.142.212.100", "194.165.16.100",
    "89.248.160.10", "80.82.77.5", "171.25.193.20",
    "62.210.105.116", "185.100.87.206",
]



# NORMAL TRAFFIC — passes Layer 1 Filter

def _normal_log() -> dict:
    """Normal Lambda execution — all fields within safe thresholds."""
    return {
        "duration":             random.randint(300, 600),
        "memory_used":          random.randint(100, 160),
        "num_api_calls":        random.randint(1, 8),
        "function_name":        random.choice(FUNCTION_NAMES),
        "ip_address":           random.choice(PUBLIC_IPS),
        "error_count":          0,
        # Packet fields — all within Layer1Filter safe ranges
        "ttl":                  random.choice([64, 128]),     # normal OS TTL
        "packet_size_in":       random.randint(200, 1500),
        "packet_size_out":      random.randint(100, 800),
        "fragment_count":       0,
        "dest_port":            443,
        "source_port":          random.randint(1024, 65535),
        "network_latency":      random.uniform(5, 50),
        "unique_destinations":  1,
    }



# ATTACK PATTERNS — designed to FAIL Layer 1 Filter

def _crypto_mining_log() -> dict:
    """
    Crypto mining: extreme duration + high memory.
    Fails Layer 1 on: duration > 3000ms
    """
    return {
        "duration":             random.randint(8000, 15000),   # way above 3000ms threshold
        "memory_used":          random.randint(400, 500),
        "num_api_calls":        random.randint(1, 3),
        "function_name":        random.choice(FUNCTION_NAMES),
        "ip_address":           random.choice(MALICIOUS_IPS),
        "error_count":          0,
        "ttl":                  random.randint(40, 50),        # slightly unusual TTL
        "packet_size_in":       random.randint(100, 200),
        "packet_size_out":      random.randint(50, 100),
        "fragment_count":       0,
        "dest_port":            443,
        "source_port":          random.randint(50000, 60000),
        "network_latency":      random.uniform(5, 15),
        "unique_destinations":  1,
    }


def _ddos_log() -> dict:
    """
    DDoS: massive API call count.
    Fails Layer 1 on: num_api_calls > 50 (the PRIMARY DDoS gate)
    """
    return {
        "duration":             random.randint(20, 60),        # DDoS is fast
        "memory_used":          random.randint(40, 80),        # low memory
        "num_api_calls":        random.randint(60, 150),       # way above 50 threshold
        "function_name":        random.choice(FUNCTION_NAMES),
        "ip_address":           random.choice(MALICIOUS_IPS),
        "error_count":          0,
        "ttl":                  random.randint(35, 45),
        "packet_size_in":       random.randint(40, 80),
        "packet_size_out":      random.randint(20, 40),
        "fragment_count":       random.randint(8, 15),         # also fails fragmentation check
        "dest_port":            80,
        "source_port":          random.randint(10000, 20000),
        "network_latency":      random.uniform(1, 5),
        "unique_destinations":  1,
    }


def _data_exfiltration_log() -> dict:
    """
    Data exfiltration: huge outbound data.
    Fails Layer 1 on: outbound_ratio > 8.0 (packet_size_out / packet_size_in)
    """
    size_in = random.randint(100, 300)
    return {
        "duration":             random.randint(400, 800),
        "memory_used":          random.randint(300, 400),
        "num_api_calls":        random.randint(15, 35),
        "function_name":        random.choice(FUNCTION_NAMES),
        "ip_address":           random.choice(MALICIOUS_IPS),
        "error_count":          0,
        "ttl":                  random.randint(45, 55),
        "packet_size_in":       size_in,
        "packet_size_out":      size_in * random.randint(10, 20),  # 10-20x ratio, fails > 8.0
        "fragment_count":       0,
        "dest_port":            443,
        "source_port":          random.randint(55000, 65000),
        "network_latency":      random.uniform(10, 30),
        "unique_destinations":  random.randint(5, 12),
    }


def _sql_injection_log() -> dict:
    """
    SQL injection: targets DB port, high duration, errors.
    Fails Layer 1 on: duration > 3000ms, suspicious port 1433
    """
    return {
        "duration":             random.randint(4000, 7000),
        "memory_used":          random.randint(200, 350),
        "num_api_calls":        random.randint(5, 15),
        "function_name":        random.choice(FUNCTION_NAMES),
        "ip_address":           random.choice(MALICIOUS_IPS),
        "error_count":          random.randint(3, 10),
        "ttl":                  random.randint(50, 60),
        "packet_size_in":       random.randint(400, 600),
        "packet_size_out":      random.randint(800, 1500),
        "fragment_count":       0,
        "dest_port":            1433,                          # MSSQL — suspicious port
        "source_port":          random.randint(45000, 55000),
        "network_latency":      random.uniform(10, 25),
        "unique_destinations":  1,
    }


def _ip_spoofing_log() -> dict:
    """
    IP spoofing: private IP pretending to be external.
    Fails Layer 1 on: private IP as external source
    """
    return {
        "duration":             random.randint(100, 500),
        "memory_used":          random.randint(80, 150),
        "num_api_calls":        random.randint(5, 20),
        "function_name":        random.choice(FUNCTION_NAMES),
        "ip_address":           random.choice(PRIVATE_IPS),    # private IP = spoofing flag
        "error_count":          0,
        "ttl":                  random.randint(20, 28),        # also fails TTL < 30
        "packet_size_in":       random.randint(300, 600),
        "packet_size_out":      random.randint(200, 400),
        "fragment_count":       0,
        "dest_port":            22,                            # SSH — suspicious port
        "source_port":          random.randint(30000, 40000),
        "network_latency":      random.uniform(1, 5),
        "unique_destinations":  random.randint(3, 8),
    }


def _memory_attack_log() -> dict:
    """
    Memory exhaustion: extreme memory + duration.
    Fails Layer 1 on: duration > 3000ms
    """
    return {
        "duration":             random.randint(7000, 12000),
        "memory_used":          random.randint(460, 510),
        "num_api_calls":        random.randint(3, 8),
        "function_name":        random.choice(FUNCTION_NAMES),
        "ip_address":           random.choice(MALICIOUS_IPS),
        "error_count":          random.randint(2, 6),
        "ttl":                  random.randint(42, 52),
        "packet_size_in":       random.randint(200, 400),
        "packet_size_out":      random.randint(100, 200),
        "fragment_count":       0,
        "dest_port":            443,
        "source_port":          random.randint(55000, 60000),
        "network_latency":      random.uniform(5, 15),
        "unique_destinations":  1,
    }


ATTACK_GENERATORS = {
    "Crypto Mining":      _crypto_mining_log,
    "DDoS":               _ddos_log,
    "Data Exfiltration":  _data_exfiltration_log,
    "SQL Injection":      _sql_injection_log,
    "IP Spoofing":        _ip_spoofing_log,
    "Memory Attack":      _memory_attack_log,
}



# PHASE 1 — LEARNING: Normal traffic (builds AI model baseline)

def generate_learning_phase(count: int = 100, verbose: bool = True):
    """Send normal traffic to build the Layer1Scorer baseline."""
    if verbose:
        print(f"\n[1/4] Learning phase — {count} normal requests...")

    for i in range(count):
        log = _normal_log()
        try:
            resp = requests.post(f"{BASE_URL}/process_log", json=log, timeout=5)
            data = resp.json()
            if verbose and (i + 1) % 25 == 0:
                decision = data.get("decision", data.get("phase", "?"))
                print(f"   {i+1}/{count} — decision: {decision}")
        except requests.exceptions.ConnectionError:
            print("  Cannot connect to API. Is the server running?")
            return False

    if verbose:
        print(f"  Learning phase complete ({count} normal requests)")
    return True


# PHASE 2 — ATTACKS: Traffic that should fail Layer 1 Filter

def generate_attack_data(count_per_type: int = 5, verbose: bool = True):
    """Send attack traffic — each type designed to fail specific Layer 1 checks."""
    if verbose:
        print(f"\n[2/4] Attack phase — {count_per_type} per type, {len(ATTACK_GENERATORS)} types...")

    results = {"BLOCK": 0, "INVESTIGATE": 0, "ALLOW": 0}

    for attack_name, generator in ATTACK_GENERATORS.items():
        for i in range(count_per_type):
            log = generator()
            try:
                resp = requests.post(f"{BASE_URL}/process_log", json=log, timeout=10)
                data = resp.json()
                decision = data.get("decision", "?")
                results[decision] = results.get(decision, 0) + 1

                if verbose and i == 0:
                    l1_violations = data.get("layer1", {}).get("violations", [])
                    print(f"   {attack_name}: decision={decision}, "
                          f"L1 violations={l1_violations[:2]}")
            except requests.exceptions.ConnectionError:
                print("  Connection error")
                return False

    if verbose:
        total = sum(results.values())
        caught = results.get("BLOCK", 0) + results.get("INVESTIGATE", 0)
        print(f"  Attack phase complete — {caught}/{total} caught "
              f"(BLOCK={results['BLOCK']}, INVESTIGATE={results['INVESTIGATE']}, "
              f"ALLOW={results['ALLOW']})")
    return True



# PHASE 3 — MIXED: Realistic blend of normal + attack

def generate_mixed_traffic(count: int = 50, attack_rate: float = 0.15, verbose: bool = True):
    """Send mixed traffic to simulate real-world conditions."""
    if verbose:
        print(f"\n[3/4] Mixed traffic — {count} requests ({attack_rate*100:.0f}% attack rate)...")

    attack_types = list(ATTACK_GENERATORS.values())

    for i in range(count):
        if random.random() < attack_rate:
            log = random.choice(attack_types)()
        else:
            log = _normal_log()

        try:
            requests.post(f"{BASE_URL}/process_log", json=log, timeout=5)
            if verbose and (i + 1) % 25 == 0:
                print(f"   {i+1}/{count}")
        except requests.exceptions.ConnectionError:
            print("  Connection error")
            return False

    if verbose:
        print(f"  Mixed traffic complete ({count} requests)")
    return True



# PHASE 4 — SARIMA warm-up

def generate_sarima_warmup(count: int = 200, verbose: bool = True):
    """Send additional normal traffic so SARIMA has enough data points to train."""
    if verbose:
        print(f"\n[4/4] SARIMA warm-up — {count} normal requests...")

    for i in range(count):
        log = _normal_log()
        try:
            requests.post(f"{BASE_URL}/process_log", json=log, timeout=5)
            if verbose and (i + 1) % 50 == 0:
                print(f"   {i+1}/{count}")
        except requests.exceptions.ConnectionError:
            print("  Connection error")
            return False

    if verbose:
        print(f"  SARIMA warm-up complete ({count} data points)")
    return True


# MAIN

def generate_all_test_data(verbose: bool = True):
    """Run all four phases to fully populate the dashboard."""
    if verbose:
        print("=" * 55)
        print("  Cloud Sentinel — Test Data Generator (Unified Pipeline)")
        print(f"  Target: {BASE_URL}")
        print("=" * 55)

    # Verify API is running
    try:
        resp = requests.get(f"{BASE_URL}/status", timeout=5)
        data = resp.json()
        pipeline = data.get("pipeline", "unknown")
        if verbose:
            print(f"  API status: {data.get('status')} (pipeline: {pipeline})")
    except:
        print(f"\n  Cannot connect to {BASE_URL}")
        print("  Make sure the API is running: uvicorn backend.api:app --reload --port 8000")
        return False

    steps = [
        lambda: generate_learning_phase(100, verbose),
        lambda: generate_attack_data(5, verbose),
        lambda: generate_mixed_traffic(50, 0.15, verbose),
        lambda: generate_sarima_warmup(200, verbose),
    ]

    for step in steps:
        if not step():
            print("\n  Generation stopped due to connection error.")
            return False

    if verbose:
        # Print final status
        try:
            resp = requests.get(f"{BASE_URL}/status", timeout=5)
            status = resp.json()
            det = status.get("detector_stats", {})
            sar = status.get("sarima_status", {})

            print("\n" + "=" * 55)
            print("  All test data generated successfully!")
            print(f"  Requests processed: {det.get('requests_processed', 0)}")
            print(f"  Anomalies detected: {det.get('anomalies_detected', 0)}")
            print(f"  SARIMA trained: {sar.get('trained', False)}")
            print(f"  Open http://localhost:5173 to see the dashboard.")
            print("=" * 55)
        except:
            print("\n  Test data generated. Check the dashboard.")

    return True


if __name__ == "__main__":
    generate_all_test_data()
