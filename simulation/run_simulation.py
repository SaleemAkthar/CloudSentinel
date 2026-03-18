"""
simulation/run_simulation.py
==============================
Main dataset generator for Cloud Sentinel.

Generates a labelled CSV dataset of 1000 Lambda execution records
by calling the traffic generators in attack_scripts.py directly,
without requiring a running LocalStack or Docker environment.

Dataset composition:
  - 700 normal records  — spread across all 4 Lambda function types
  - 300 attack records  — 50 records per attack type (6 types)

Records are interleaved in chronological order to simulate realistic
mixed traffic, rather than batching all attacks together. This is
important for time-series models like SARIMA that would otherwise
see an unrealistic step change in the data.

Output:
  simulation/dataset/cloud_sentinel_dataset.csv

Usage:
  python simulation/run_simulation.py

Author: Okitha (LocalStack Simulation — Option 2: direct generation)
"""

import csv
import os
import random
from datetime import datetime, timedelta
from collections import Counter

from attack_scripts import generate_normal_record, ATTACK_GENERATORS


# ---------------------------------------------------------------------------
# Dataset configuration
# ---------------------------------------------------------------------------

TOTAL_NORMAL  = 700
ATTACKS_PER_TYPE = 50   # 6 types × 50 = 300 attack records
ATTACK_TYPES  = list(ATTACK_GENERATORS.keys())

# Output path — created automatically if it does not exist.
DATASET_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
DATASET_PATH = os.path.join(DATASET_DIR, "cloud_sentinel_dataset.csv")

# CSV column order — must match the keys returned by every generator.
FIELDNAMES = [
    "timestamp", "function_name", "duration", "memory_used",
    "num_api_calls", "error_count", "concurrency", "ip_address",
    "ttl", "packet_size_in", "packet_size_out", "latency",
    "fragment_count", "source_port", "status_code", "label", "attack_type",
]


# ---------------------------------------------------------------------------
# Timestamp generation
# ---------------------------------------------------------------------------

def generate_timestamps(n: int, start: datetime = None) -> list:
    """
    Generate n timestamps spread over a 24-hour window.

    Timestamps are spaced with small random jitter (1–30 seconds apart)
    to simulate realistic Lambda invocation intervals rather than
    artificially regular spacing.

    Args:
        n:     Number of timestamps to generate.
        start: Start time. Defaults to 24 hours ago in UTC.

    Returns:
        Sorted list of ISO-format timestamp strings.
    """
    if start is None:
        start = datetime.utcnow() - timedelta(hours=24)

    timestamps = []
    current = start
    for _ in range(n):
        current += timedelta(seconds=random.randint(1, 30))
        timestamps.append(current.isoformat())

    return timestamps


# ---------------------------------------------------------------------------
# Dataset generation
# ---------------------------------------------------------------------------

def generate_dataset() -> list:
    """
    Build the full list of 1000 labelled records.

    Normal and attack records are generated separately, then shuffled
    together and re-sorted by timestamp so the final dataset reads
    as a natural chronological event stream rather than two distinct
    blocks. This prevents time-based models from trivially separating
    the classes purely on position in the file.

    Returns:
        List of record dicts, sorted by timestamp ascending.
    """
    total_records = TOTAL_NORMAL + (ATTACKS_PER_TYPE * len(ATTACK_TYPES))
    timestamps    = generate_timestamps(total_records)
    ts_iter       = iter(timestamps)

    records = []

    # Normal traffic — evenly distributed across the 24h window.
    print(f"  Generating {TOTAL_NORMAL} normal records...")
    for _ in range(TOTAL_NORMAL):
        record = generate_normal_record(timestamp=next(ts_iter))
        records.append(record)

    # Attack traffic — 50 records per type.
    for attack_type, generator_fn in ATTACK_GENERATORS.items():
        print(f"  Generating {ATTACKS_PER_TYPE} {attack_type} records...")
        for _ in range(ATTACKS_PER_TYPE):
            record = generator_fn(timestamp=next(ts_iter))
            records.append(record)

    # Shuffle then re-sort by timestamp to interleave normal and attack traffic.
    random.shuffle(records)
    records.sort(key=lambda r: r["timestamp"])

    return records


# ---------------------------------------------------------------------------
# CSV writer
# ---------------------------------------------------------------------------

def write_csv(records: list):
    """
    Write the dataset to a CSV file at DATASET_PATH.

    The output directory is created if it does not already exist.
    attack_type is written as an empty string for normal records
    so the CSV has no missing values.

    Args:
        records: List of record dicts produced by generate_dataset().
    """
    os.makedirs(DATASET_DIR, exist_ok=True)

    with open(DATASET_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()

        for record in records:
            # Replace None with empty string for clean CSV output.
            row = {k: ("" if v is None else v) for k, v in record.items()}
            writer.writerow(row)

    print(f"\n  Dataset saved to: {DATASET_PATH}")


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def print_summary(records: list):
    """
    Print a human-readable summary of the generated dataset.
    Shows record counts, label distribution, and basic duration/memory stats.
    """
    total    = len(records)
    labels   = Counter(r["label"] for r in records)
    attacks  = Counter(r["attack_type"] for r in records if r["attack_type"])

    durations = [r["duration"] for r in records]
    memories  = [r["memory_used"] for r in records]

    print("\n" + "=" * 60)
    print("DATASET SUMMARY")
    print("=" * 60)
    print(f"Total records : {total}")
    print(f"Normal        : {labels['normal']}")
    print(f"Attack        : {labels['attack']}")

    print("\nAttack breakdown:")
    for atype in ATTACK_TYPES:
        print(f"  {atype:<25}: {attacks.get(atype, 0)}")

    print(f"\nDuration  — min: {min(durations):.0f}ms, "
          f"max: {max(durations):.0f}ms, "
          f"mean: {sum(durations)/len(durations):.0f}ms")
    print(f"Memory    — min: {min(memories):.0f}MB, "
          f"max: {max(memories):.0f}MB, "
          f"mean: {sum(memories)/len(memories):.0f}MB")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run_simulation():
    print("=" * 60)
    print("CLOUD SENTINEL — DATASET GENERATION")
    print("=" * 60)
    print(f"\nTarget: {TOTAL_NORMAL} normal + "
          f"{ATTACKS_PER_TYPE * len(ATTACK_TYPES)} attack records\n")

    records = generate_dataset()
    write_csv(records)
    print_summary(records)

    print("\n" + "=" * 60)
    print("DONE — run validate_dataset.py to verify cluster separation")
    print("=" * 60)


if __name__ == "__main__":
    run_simulation()
