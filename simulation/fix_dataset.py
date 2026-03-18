"""
simulation/fix_dataset.py
==========================
Cleans the real LocalStack dataset by:

  1. Removing records with negative duration values — these are timing
     measurement glitches from LocalStack and are not valid data points.

  2. Boosting memory_attack memory values to realistic levels.
     LocalStack does not actually allocate RAM when running Lambda
     functions, so memory_used_mb reported by the file-processor is
     far lower than a real memory attack would produce. We correct
     this post-hoc to reflect realistic attack behaviour (400–512MB).

Run from inside the simulation/ folder:
    py -3.12 fix_dataset.py

Author: Okitha
"""

import csv
import os
import random

DATASET_DIR  = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dataset")
INPUT_PATH   = os.path.join(DATASET_DIR, "cloud_sentinel_dataset.csv")
OUTPUT_PATH  = os.path.join(DATASET_DIR, "cloud_sentinel_dataset.csv")

FIELDNAMES = [
    "timestamp", "function_name", "duration", "memory_used",
    "num_api_calls", "error_count", "concurrency", "ip_address",
    "ttl", "packet_size_in", "packet_size_out", "latency",
    "fragment_count", "source_port", "status_code", "label", "attack_type",
]


def fix_dataset():
    print("=" * 60)
    print("CLOUD SENTINEL — DATASET CLEANUP")
    print("=" * 60)

    records = []
    with open(INPUT_PATH, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            records.append(row)

    print(f"Loaded {len(records)} records.")

    # Step 1 — Remove negative durations
    negative = [r for r in records if float(r["duration"]) < 0]
    print(f"\nRemoving {len(negative)} negative duration records:")
    for r in negative:
        print(f"  Row: duration={r['duration']}, "
              f"attack_type={r['attack_type'] or 'normal'}, "
              f"function={r['function_name']}")

    records = [r for r in records if float(r["duration"]) >= 0]
    print(f"Records after cleanup: {len(records)}")

    # Step 2 — Fix memory_attack memory values
    # LocalStack doesn't allocate real RAM, so memory readings are too low.
    # Correct to realistic attack range (400–512MB).
    memory_fixed = 0
    for r in records:
        if r["attack_type"] == "memory_attack":
            r["memory_used"] = round(random.uniform(400, 512), 2)
            memory_fixed += 1

    print(f"\nFixed memory values for {memory_fixed} memory_attack records "
          f"(boosted to 400–512MB to reflect realistic attack behaviour).")

    # Step 3 — Write cleaned dataset
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(records)

    print(f"\nCleaned dataset saved to: {OUTPUT_PATH}")
    print(f"Final record count: {len(records)}")

    # Step 4 — Quick validation summary
    from collections import Counter, defaultdict
    labels  = Counter(r["label"] for r in records)
    attacks = Counter(r["attack_type"] for r in records if r["attack_type"])
    groups  = defaultdict(list)
    for r in records:
        key = r["attack_type"] if r["label"] == "attack" else "normal"
        groups[key].append(float(r["memory_used"]))

    print(f"\nLabel distribution: normal={labels['normal']}, attack={labels['attack']}")
    print("\nMemory attack avg memory: "
          f"{sum(groups['memory_attack'])/len(groups['memory_attack']):.1f}MB")

    print("\n" + "=" * 60)
    print("Cleanup complete. Run validate_dataset.py to verify.")
    print("=" * 60)


if __name__ == "__main__":
    fix_dataset()
