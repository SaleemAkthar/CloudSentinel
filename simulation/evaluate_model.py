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

import numpy as np
import matplotlib.pyplot as plt
import matplotlib
matplotlib.use("Agg")          # save to file without needing a display
import seaborn as sns


def evaluate():
    scorer = Layer1Scorer(learning_window=100)
    generator = EnhancedLogGenerator(attack_rate=0.30)

    # Generate 1000 logs (700 normal, 300 attack approximately)
    logs = generator.generate_batch(1000)

    # Counters
    tp = 0  #  attack detected as attack
    fp = 0  #  normal detected as attack
    tn = 0  #  normal detected as normal
    fn = 0  # attack detected as normal

    # Per-attack-type tracking
    per_type = defaultdict(lambda: {"tp": 0, "fn": 0, "fp": 0})

    for i, log in enumerate(logs):
        # Build features dict matching what layer1_scorer expects
        features = {
            "duration":        float(log.get("duration", 500)),
            "memory_used":     float(log.get("memoryUsed", 130)),
            "num_api_calls":   len(log.get("apiCalls", [])) if isinstance(log.get("apiCalls"), list) else int(log.get("num_api_calls", 3)),
            "error_count":     1 if log.get("errorMessage") else 0,
            "concurrency":     1,
            "packet_size_in":  512,
            "packet_size_out": 256,
            "latency":         50,
            "fragment_count":  int(log.get("fragment_count", 0)),
            "ip_address":      log.get("ip_address", "192.168.1.1"),
            "ttl":             int(log.get("ttl", 55)),
            "source_port":     int(log.get("source_port", 443)),
            "timestamp":       datetime.now().isoformat(),
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

    # ── Visual confusion matrix (seaborn heatmap — same as Google Colab) ────
    plot_confusion_matrix(tp, fp, fn, tn)

    # ── Per-attack-type recall bar chart ─────────────────────────────────────
    plot_per_type_recall(per_type)


def plot_confusion_matrix(tp: int, fp: int, fn: int, tn: int):
    """
    Render a colour-coded confusion matrix heatmap identical to the one
    produced by sklearn + seaborn in Google Colab.
    Saves → simulation/confusion_matrix.png
    """
    cm = np.array([[tp, fn],
                   [fp, tn]])

    labels = ["Attack", "Normal"]

    fig, ax = plt.subplots(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Predicted Attack", "Predicted Normal"],
        yticklabels=["Actual Attack",    "Actual Normal"],
        linewidths=0.5,
        linecolor="grey",
        ax=ax,
    )

    # Annotate each cell with label (TP / FN / FP / TN)
    cell_labels = [["TP", "FN"], ["FP", "TN"]]
    for i in range(2):
        for j in range(2):
            ax.text(
                j + 0.5, i + 0.75,
                cell_labels[i][j],
                ha="center", va="center",
                fontsize=9, color="grey",
            )

    ax.set_title("Cloud Sentinel — Confusion Matrix", fontsize=14, fontweight="bold", pad=12)
    ax.set_ylabel("Actual Label",    fontsize=11)
    ax.set_xlabel("Predicted Label", fontsize=11)
    plt.tight_layout()

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confusion_matrix.png")
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"\n  Confusion matrix saved → {out_path}")


def plot_per_type_recall(per_type: dict):
    """
    Horizontal bar chart showing recall % per attack type.
    Saves → simulation/per_type_recall.png
    """
    type_order = [
        "crypto_mining", "data_exfiltration", "ddos_loop",
        "sql_injection",  "ip_spoofing",       "memory_attack",
    ]

    labels, recalls, totals = [], [], []
    for atype in type_order:
        if atype not in per_type:
            continue
        d = per_type[atype]
        total = d["tp"] + d["fn"]
        if total == 0:
            continue
        recall = d["tp"] / total * 100
        labels.append(atype.replace("_", " ").title())
        recalls.append(recall)
        totals.append(total)

    if not labels:
        return

    colours = ["#2ecc71" if r >= 80 else "#f39c12" if r >= 50 else "#e74c3c" for r in recalls]

    fig, ax = plt.subplots(figsize=(8, max(3, len(labels) * 0.7)))
    bars = ax.barh(labels, recalls, color=colours, edgecolor="white", height=0.55)

    # Value labels on bars
    for bar, recall, total in zip(bars, recalls, totals):
        ax.text(
            min(recall + 1, 97), bar.get_y() + bar.get_height() / 2,
            f"{recall:.0f}%  (n={total})",
            va="center", fontsize=9,
        )

    ax.set_xlim(0, 110)
    ax.set_xlabel("Recall (%)", fontsize=11)
    ax.set_title("Cloud Sentinel — Detection Rate per Attack Type", fontsize=13, fontweight="bold")
    ax.axvline(80, color="grey", linestyle="--", linewidth=0.8, label="80% target")
    ax.legend(fontsize=9)
    ax.invert_yaxis()
    plt.tight_layout()

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "per_type_recall.png")
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  Per-type recall chart saved → {out_path}\n")


if __name__ == "__main__":
    evaluate()