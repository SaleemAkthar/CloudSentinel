"""
Cloud Sentinel — Latency Timing Test
======================================
Measures exactly how fast Cloud Sentinel detects attacks.

Run this after warming up the baseline:
    python warm_up_baseline.py
    python timing_test.py

Or test against AWS:
    python timing_test.py http://your-alb-url.amazonaws.com
"""

import requests
import time
import sys
import statistics

API_URL     = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000"
PROCESS_URL = f"{API_URL}/process_log"

NORMAL_PACKET = {
    "duration":       450,
    "memory_used":    130,
    "num_api_calls":  3,
    "function_name":  "paymentHandler",
    "ip_address":     "54.239.28.85",
    "ttl":            64,
    "packet_size_in": 512,
    "dest_port":      443,
    "error_count":    0,
}

CRYPTO_ATTACK = {
    "duration":       12000,
    "memory_used":    450,
    "num_api_calls":  2,
    "function_name":  "paymentHandler",
    "ip_address":     "185.220.101.45",
    "ttl":            44,
    "packet_size_in": 128,
    "dest_port":      443,
    "error_count":    0,
}

DDOS_ATTACK = {
    "duration":       30,
    "memory_used":    60,
    "num_api_calls":  120,
    "function_name":  "apiHandler",
    "ip_address":     "194.165.16.100",
    "ttl":            42,
    "packet_size_in": 64,
    "dest_port":      80,
    "fragment_count": 14,
    "error_count":    0,
}


def measure(label: str, packet: dict, count: int = 30):
    times   = []
    decisions = {}

    print(f"\n  Testing: {label}")

    for i in range(count):
        start   = time.perf_counter()
        try:
            resp    = requests.post(PROCESS_URL, json=packet, timeout=10)
            elapsed = (time.perf_counter() - start) * 1000
            times.append(elapsed)
            d = resp.json().get("decision", "ERR")
            decisions[d] = decisions.get(d, 0) + 1
        except Exception as e:
            print(f"    Request {i+1} failed: {e}")

    if not times:
        print("    No successful requests")
        return

    print(f"    Min:    {min(times):6.2f}ms")
    print(f"    Avg:    {statistics.mean(times):6.2f}ms")
    print(f"    Median: {statistics.median(times):6.2f}ms")
    print(f"    p95:    {sorted(times)[int(len(times)*0.95)]:6.2f}ms")
    print(f"    Max:    {max(times):6.2f}ms")
    print(f"    Decisions: {decisions}")


def main():
    print("=" * 55)
    print("  CLOUD SENTINEL LATENCY TEST")
    print(f"  Target: {API_URL}")
    print("=" * 55)

    try:
        r = requests.get(f"{API_URL}/status", timeout=5)
        d = r.json()
        print(f"\n  Status:    {d.get('status')}")
        print(f"  L2 mode:   {d.get('layer2_mode')}")
    except Exception as e:
        print(f"\n  Cannot connect: {e}")
        return

    measure("Normal traffic   (expect ALLOW)",      NORMAL_PACKET, 30)
    measure("Crypto mining    (expect INVESTIGATE)", CRYPTO_ATTACK, 20)
    measure("DDoS attack      (expect INVESTIGATE)", DDOS_ATTACK,   20)

    # Layer 2 test
    print(f"\n  Testing Layer 2 (investigate endpoint)...")
    try:
        alerts = requests.get(f"{API_URL}/api/alerts?limit=1").json()
        if alerts:
            aid   = alerts[0]["id"]
            start = time.perf_counter()
            r     = requests.post(f"{API_URL}/api/alerts/{aid}/investigate", timeout=30)
            ms    = (time.perf_counter() - start) * 1000
            data  = r.json()
            print(f"    Round trip:  {ms:.1f}ms")
            print(f"    L2 internal: {data.get('report',{}).get('elapsed_ms','N/A')}ms")
            print(f"    Severity:    {data.get('severity','N/A')}")
            print(f"    Decision:    {data.get('decision','N/A')}")
        else:
            print("    No alerts yet. Send attack packet first.")
    except Exception as e:
        print(f"    Layer 2 test failed: {e}")

    print("\n" + "=" * 55)


if __name__ == "__main__":
    main()