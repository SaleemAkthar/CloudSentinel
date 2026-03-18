"""
simulation/validate_dataset.py
================================
Validates the generated Cloud Sentinel dataset.

Checks performed:
  1. Record counts — total, normal vs attack, per attack type.
  2. Per-group statistics — mean duration, memory, API calls, errors.
  3. Cluster separation — how distinct each attack type is from normal
     traffic on the key features the anomaly detector uses.
  4. Missing values — flags any empty fields that would break training.

A dataset is considered suitable for anomaly detection when at least
one of duration or memory shows > 1.5x separation from the normal mean.
Anything below 1.3x is flagged as WEAK and may need tuning in
attack_scripts.py.

Usage:
  python simulation/validate_dataset.py

Author: Okitha (LocalStack Simulation — Option 2: direct generation)
"""

import csv
import os
from collections import defaultdict


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DATASET_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "dataset",
    "cloud_sentinel_dataset.csv",
)

ATTACK_TYPES = [
    "crypto_mining",
    "data_exfiltration",
    "sql_injection",
    "ddos",
    "memory_attack",
    "ip_spoofing",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def mean(values: list) -> float:
    """Return the arithmetic mean of a list, or 0.0 if empty."""
    return sum(values) / len(values) if values else 0.0


def load_dataset() -> list:
    """
    Load the CSV dataset and cast numeric fields to their correct types.

    Returns:
        List of record dicts with numeric fields already converted.

    Raises:
        FileNotFoundError: if the dataset CSV does not exist yet.
    """
    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {DATASET_PATH}\n"
            "Run simulation/run_simulation.py first."
        )

    records = []
    with open(DATASET_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row["duration"]      = float(row["duration"])
            row["memory_used"]   = float(row["memory_used"])
            row["num_api_calls"] = int(row["num_api_calls"])
            row["error_count"]   = int(row["error_count"])
            row["concurrency"]   = int(row["concurrency"])
            row["ttl"]           = int(row["ttl"])
            # attack_type is empty string for normal records — normalise to None.
            row["attack_type"]   = row["attack_type"] or None
            records.append(row)

    return records


# ---------------------------------------------------------------------------
# Validation checks
# ---------------------------------------------------------------------------

def check_record_counts(records: list):
    """Print total record count and label distribution."""
    from collections import Counter

    total   = len(records)
    labels  = Counter(r["label"] for r in records)
    attacks = Counter(r["attack_type"] for r in records if r["attack_type"])

    print(f"Total records : {total}")
    print(f"  Normal      : {labels.get('normal', 0)}")
    print(f"  Attack      : {labels.get('attack', 0)}")

    print("\nPer attack type:")
    for atype in ATTACK_TYPES:
        count  = attacks.get(atype, 0)
        status = "OK" if count >= 50 else "LOW — expected 50"
        print(f"  {atype:<25}: {count:>4}  {status}")


def check_per_group_stats(groups: dict):
    """Print mean duration, memory, API calls, and errors per group."""
    header = f"{'Type':<25} {'Count':>6} {'Avg Duration':>14} {'Avg Memory':>12} {'Avg API':>9} {'Avg Errors':>11}"
    print(header)
    print("-" * 80)

    ordered = ["normal"] + ATTACK_TYPES
    for gtype in ordered:
        if gtype not in groups:
            continue
        g = groups[gtype]
        print(
            f"{gtype:<25} {len(g):>6} "
            f"{mean([r['duration'] for r in g]):>13.1f}ms "
            f"{mean([r['memory_used'] for r in g]):>11.1f}MB "
            f"{mean([r['num_api_calls'] for r in g]):>8.1f} "
            f"{mean([r['error_count'] for r in g]):>10.1f}"
        )


def check_cluster_separation(groups: dict):
    """
    Compare each attack type against the normal baseline.

    Four features are checked: duration, memory, API calls, and TTL.
    Different attack types are detectable on different features:
      - Crypto mining / memory attack  → duration and memory
      - Data exfiltration / SQL inject → API calls and errors
      - DDoS                           → concurrency and API calls
      - IP spoofing                    → TTL (abnormally low)

    A dataset is considered suitable when at least one feature shows
    a ratio above 1.5x (or below 0.5x for TTL where low = suspicious).
    """
    normal = groups.get("normal", [])
    if not normal:
        print("  No normal records found — cannot compute separation.")
        return

    normal_dur = mean([r["duration"]      for r in normal])
    normal_mem = mean([r["memory_used"]   for r in normal])
    normal_api = mean([r["num_api_calls"] for r in normal])
    normal_ttl = mean([int(r["ttl"])      for r in normal])

    print(f"{'Attack Type':<25} {'Dur':>7} {'Mem':>7} {'API':>7} {'TTL':>7}  Verdict")
    print("-" * 72)

    for atype in ATTACK_TYPES:
        if atype not in groups:
            print(f"  {atype:<25}: NO DATA")
            continue

        g       = groups[atype]
        dur_r   = mean([r["duration"]      for r in g]) / max(normal_dur, 1)
        mem_r   = mean([r["memory_used"]   for r in g]) / max(normal_mem, 1)
        api_r   = mean([r["num_api_calls"] for r in g]) / max(normal_api, 1)
        ttl_r   = mean([int(r["ttl"])      for r in g]) / max(normal_ttl, 1)

        # Good separation if any primary feature deviates significantly.
        # TTL is reversed — low TTL is the anomaly for IP spoofing.
        if dur_r > 2.0 or mem_r > 2.0 or api_r > 3.0 or ttl_r < 0.5:
            verdict = "GOOD"
        elif dur_r > 1.3 or mem_r > 1.3 or api_r > 1.5 or ttl_r < 0.7:
            verdict = "MODERATE"
        else:
            verdict = "WEAK"

        print(
            f"  {atype:<25} {dur_r:>6.2f}x {mem_r:>6.2f}x "
            f"{api_r:>6.2f}x {ttl_r:>6.2f}x  {verdict}"
        )


def check_missing_values(records: list):
    """Flag any records with empty required fields."""
    required = ["duration", "memory_used", "num_api_calls", "label"]
    issues   = 0

    for i, record in enumerate(records):
        for field in required:
            if record.get(field) == "" or record.get(field) is None:
                print(f"  Row {i+2}: missing '{field}'")
                issues += 1

    if issues == 0:
        print("  No missing values found.")
    else:
        print(f"  {issues} missing value(s) found — check attack_scripts.py generators.")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def validate():
    print("=" * 68)
    print("CLOUD SENTINEL — DATASET VALIDATION REPORT")
    print("=" * 68)

    records = load_dataset()

    # Group records by attack type (normal records go under "normal").
    groups = defaultdict(list)
    for r in records:
        key = r["attack_type"] if r["label"] == "attack" else "normal"
        groups[key].append(r)

    print("\n── Record Counts ──────────────────────────────────────────")
    check_record_counts(records)

    print("\n── Per-Group Statistics ───────────────────────────────────")
    check_per_group_stats(groups)

    print("\n── Cluster Separation ─────────────────────────────────────")
    check_cluster_separation(groups)

    print("\n── Missing Values ─────────────────────────────────────────")
    check_missing_values(records)

    print("\n" + "=" * 68)
    print("Validation complete.")
    print("=" * 68)


if __name__ == "__main__":
    validate()
