"""
evaluate_model.py
------------------
Run the synthetic dataset through Layer1Scorer and calculate
precision, recall, F1 score, and confusion matrix.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.detection.layer1_scorer import Layer1Scorer
from backend.data_generator import EnhancedLogGenerator
from datetime import datetime
from collections import defaultdict


def evaluate():
    scorer = Layer1Scorer(learning_window=100)
    generator = EnhancedLogGenerator(attack_rate=0.30)

    # Generate 1000 logs (700 normal, 300 attack approximately)
    logs = generator.generate_batch(1000)

    # Counters
    tp = 0  # true positive: attack detected as attack
    fp = 0  # false positive: normal detected as attack
    tn = 0  # true negative: normal detected as normal
    fn = 0  # false negative: attack detected as normal

    # Per-attack-type tracking
    per_type = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})

    for i, log in enumerate(logs):
        # Build features dict matching what layer1_scorer expects
        features = {
            "duration": float(log.get("duration", 500)),
            "memory_used": float(log.get("memoryUsed", 130)),
            "num_api_calls": len(log.get("apiCalls", [])) if isinstance(log.get("apiCalls"), list) else int(log.get("num_api_calls", 3)),
            "error_count": 1 if log.get("errorMessage") else 0,
            "concurrency": 1,
            "packet_size_in": 512,
            "packet_size_out": 256,
            "latency": 50,
            "fragment_count": 0,
            "ip_address": "192.168.1.1",
            "timestamp": datetime.now().isoformat(),
        }

        score, details = scorer.process_log(features)

        # Ground truth
        is_actually_attack = "attack_type" in log
        actual_type = log.get("attack_type", "normal")

        # System prediction
        system_says_attack = details.get("is_anomaly", False)

        # First 100 are learning phase — skip those for evaluation
        if details.get("phase") == "learning":
            continue

        if is_actually_attack and system_says_attack:
            tp += 1
            per_type[actual_type]["tp"] += 1
        elif is_actually_attack and not system_says_attack:
            fn += 1
            per_type[actual_type]["fn"] += 1
        elif not is_actually_attack and system_says_attack:
            fp += 1
        elif not is_actually_attack and not system_says_attack:
            tn += 1

    # Calculate metrics
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    f1 = 2 * (precision * recall) / max(precision + recall, 0.001)
    accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
    fpr = fp / max(fp + tn, 1)

    print("=" * 60)
    print("CLOUD SENTINEL — MODEL EVALUATION")
    print("=" * 60)

    print(f"\nConfusion Matrix:")
    print(f"                  Predicted Attack  Predicted Normal")
    print(f"  Actual Attack       {tp:>6}            {fn:>6}")
    print(f"  Actual Normal       {fp:>6}            {tn:>6}")

    print(f"\nOverall Metrics:")
    print(f"  Accuracy:    {accuracy * 100:.1f}%")
    print(f"  Precision:   {precision * 100:.1f}%")
    print(f"  Recall:      {recall * 100:.1f}%")
    print(f"  F1 Score:    {f1 * 100:.1f}%")
    print(f"  FP Rate:     {fpr * 100:.1f}%")

    print(f"\nPer-Attack-Type Recall:")
    for atype in sorted(per_type.keys()):
        d = per_type[atype]
        type_recall = d["tp"] / max(d["tp"] + d["fn"], 1)
        print(f"  {atype:<25s}  {d['tp']}/{d['tp']+d['fn']} detected  "
              f"({type_recall*100:.0f}% recall)")

    print("\n" + "=" * 60)


if __name__ == "__main__":
    evaluate()