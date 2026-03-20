"""
CloudSentinel — Baseline Warm-up Script
========================================
Feeds 100 normal Lambda execution requests to the API to complete
the learning phase before anomaly detection kicks in.

Run from project root:
    python warm_up_baseline.py
"""

import requests
import random
import time

API_URL = "http://localhost:8000/process_log"

# Normal public AWS IPs to simulate real Lambda traffic
NORMAL_IPS = [
    "52.94.0.1", "52.94.0.2", "54.239.28.85", "54.239.28.86",
    "18.184.0.1", "18.184.0.2", "35.180.0.1", "35.180.0.2",
    "13.226.0.1", "13.226.0.2",
]

def make_normal_packet():
    """Generate a realistic normal Lambda execution packet."""
    return {
        "ip_address":      random.choice(NORMAL_IPS),
        "duration":        random.randint(200, 800),      # normal: 200–800ms
        "memory_used":     random.choice([128, 256, 512]),
        "num_api_calls":   random.randint(1, 10),         # normal: low
        "packet_size_in":  random.randint(256, 1024),
        "packet_size_out": random.randint(128, 512),
        "fragment_count":  random.randint(0, 2),          # normal: low
        "ttl":             random.randint(50, 70),
        "error_count":     random.randint(0, 1),
    }

def warm_up(n=110):
    print(f"Warming up baseline with {n} normal requests...\n")
    success = 0
    failed  = 0

    for i in range(1, n + 1):
        packet = make_normal_packet()
        try:
            resp = requests.post(API_URL, json=packet, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                phase    = data.get("layer1", {}).get("scorer_result", {}).get("phase", "?")
                progress = data.get("layer1", {}).get("scorer_result", {}).get("learning_progress", "?")
                decision = data.get("decision", "?")
                success += 1
                print(f"  [{i:>3}] {progress:<8} phase={phase:<10} decision={decision}")
            else:
                failed += 1
                print(f"  [{i:>3}] ERROR {resp.status_code}")
        except Exception as e:
            failed += 1
            print(f"  [{i:>3}] FAILED: {e}")

        time.sleep(0.05)  # small delay to avoid hammering

    print(f"\nDone! {success} successful, {failed} failed.")
    print("Baseline is ready — anomaly detection is now active.")
    print("\nNow test a DDoS packet and you should get BLOCK.")

if __name__ == "__main__":
    warm_up()
