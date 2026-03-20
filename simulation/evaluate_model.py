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
    Colour-normalised confusion matrix heatmap with count + percentage
    annotations per cell and inline metric strip.
    Saves → simulation/confusion_matrix.png
    """
    cm      = np.array([[tp, fn], [fp, tn]])
    total   = tp + fp + fn + tn
    cm_pct  = cm / max(total, 1) * 100   # percentage per cell
    # Normalise for colour scale (each row independently so colours are
    # meaningful — actual-attack row vs actual-normal row)
    cm_norm = cm.astype(float)
    for row in range(2):
        row_sum = cm_norm[row].sum()
        if row_sum > 0:
            cm_norm[row] /= row_sum

    # Pre-compute metrics for the strip
    precision = tp / max(tp + fp, 1)
    recall    = tp / max(tp + fn, 1)
    f1        = 2 * precision * recall / max(precision + recall, 1e-6)
    accuracy  = (tp + tn) / max(total, 1)

    fig, (ax_cm, ax_strip) = plt.subplots(
        2, 1, figsize=(7, 6.5),
        gridspec_kw={'height_ratios': [5, 1]}, constrained_layout=True
    )

    # ── Heatmap ──────────────────────────────────────────────────────────────
    sns.heatmap(
        cm_norm,
        annot=False,           # we draw custom annotations below
        cmap="Blues",
        vmin=0, vmax=1,
        xticklabels=["Predicted\nAttack", "Predicted\nNormal"],
        yticklabels=["Actual\nAttack",    "Actual\nNormal"],
        linewidths=0.8,
        linecolor="white",
        cbar=False,
        ax=ax_cm,
    )

    # Custom cell annotations: count (bold) + percentage + TP/FP/FN/TN label
    cell_labels = [["TP", "FN"], ["FP", "TN"]]
    cell_values = [[tp, fn], [fp, tn]]
    cell_pcts   = [[tp/max(total,1)*100, fn/max(total,1)*100],
                   [fp/max(total,1)*100, tn/max(total,1)*100]]
    text_colours = [["white" if cm_norm[i][j] > 0.5 else "#333333"
                     for j in range(2)] for i in range(2)]

    for i in range(2):
        for j in range(2):
            tc = text_colours[i][j]
            ax_cm.text(
                j + 0.5, i + 0.30,
                f"{cell_values[i][j]:,}",
                ha="center", va="center",
                fontsize=18, fontweight="bold", color=tc,
            )
            ax_cm.text(
                j + 0.5, i + 0.55,
                f"{cell_pcts[i][j]:.1f}% of total",
                ha="center", va="center",
                fontsize=8, color=tc, alpha=0.85,
            )
            ax_cm.text(
                j + 0.5, i + 0.78,
                cell_labels[i][j],
                ha="center", va="center",
                fontsize=9, color=tc, style="italic",
            )

    ax_cm.set_title(
        "Cloud Sentinel — Confusion Matrix",
        fontsize=13, fontweight="bold", pad=10,
    )
    ax_cm.set_ylabel("Actual Label",    fontsize=10)
    ax_cm.set_xlabel("Predicted Label", fontsize=10)
    ax_cm.tick_params(labelsize=9)

    # ── Metrics strip ────────────────────────────────────────────────────────
    ax_strip.axis("off")
    metrics_text = (
        f"Precision: {precision*100:.1f}%    "
        f"Recall: {recall*100:.1f}%    "
        f"F1: {f1*100:.1f}%    "
        f"Accuracy: {accuracy*100:.1f}%    "
        f"n = {total:,}"
    )
    ax_strip.text(
        0.5, 0.5, metrics_text,
        ha="center", va="center",
        fontsize=9, color="#444444",
        bbox=dict(boxstyle="round,pad=0.4", facecolor="#f0f4f8", edgecolor="#cbd5e0"),
        transform=ax_strip.transAxes,
    )

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "confusion_matrix.png")
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"\n  Confusion matrix saved → {out_path}")


def plot_per_type_recall(per_type: dict):
    """
    Side-by-side Recall + Precision horizontal bar chart per attack type.
    Bug fix: uses 'ddos_loop' to match the generator's attack_type key.
    Saves → simulation/per_type_recall.png
    """
    # 'ddos_loop' is the actual key set by generate_ddos_attack() line 223
    type_order = [
        "crypto_mining", "data_exfiltration", "ddos_loop",
        "sql_injection",  "ip_spoofing",       "memory_attack",
    ]
    display_names = {
        "crypto_mining":     "Crypto Mining",
        "data_exfiltration": "Data Exfiltration",
        "ddos_loop":         "DDoS",
        "sql_injection":     "SQL Injection",
        "ip_spoofing":       "IP Spoofing",
        "memory_attack":     "Memory Attack",
    }

    labels, recalls, precisions, totals = [], [], [], []

    # Global FP count for approximate per-type precision
    total_fp  = sum(d["fp"] for d in per_type.values())
    total_tp  = sum(d["tp"] for d in per_type.values())
    # Global precision estimate (best available without per-type FP tracking)
    global_prec = total_tp / max(total_tp + total_fp, 1)

    for atype in type_order:
        if atype not in per_type:
            continue
        d     = per_type[atype]
        total = d["tp"] + d["fn"]
        if total == 0:
            continue
        recall = d["tp"] / total * 100
        labels.append(display_names.get(atype, atype))
        recalls.append(recall)
        precisions.append(global_prec * 100)   # global precision as reference line
        totals.append(total)

    if not labels:
        return

    y      = np.arange(len(labels))
    height = 0.38

    fig, ax = plt.subplots(figsize=(10, max(4, len(labels) * 0.9)))

    # Recall bars
    recall_colours = [
        "#27ae60" if r >= 80 else "#f39c12" if r >= 50 else "#e74c3c"
        for r in recalls
    ]
    bars_recall = ax.barh(
        y + height / 2, recalls, height=height,
        color=recall_colours, edgecolor="white", label="Recall"
    )

    # Precision reference bars (global precision, semi-transparent)
    bars_prec = ax.barh(
        y - height / 2, precisions, height=height,
        color="#3498db", alpha=0.55, edgecolor="white", label="Precision (global)"
    )

    # Value labels
    for bar, val, total in zip(bars_recall, recalls, totals):
        ax.text(
            min(val + 1, 105), bar.get_y() + bar.get_height() / 2,
            f"{val:.0f}%  (n={total})",
            va="center", fontsize=8.5, fontweight="bold",
        )
    for bar, val in zip(bars_prec, precisions):
        ax.text(
            min(val + 1, 105), bar.get_y() + bar.get_height() / 2,
            f"{val:.0f}%",
            va="center", fontsize=8, color="#2980b9",
        )

    ax.set_yticks(y)
    ax.set_yticklabels(labels, fontsize=10)
    ax.set_xlim(0, 115)
    ax.set_xlabel("Score (%)", fontsize=11)
    ax.set_title(
        "Cloud Sentinel — Recall & Precision per Attack Type",
        fontsize=13, fontweight="bold",
    )
    ax.axvline(80, color="#7f8c8d", linestyle="--", linewidth=0.9, label="80% target")
    ax.legend(fontsize=9, loc="lower right")
    ax.invert_yaxis()
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()

    out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "per_type_recall.png")
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"  Per-type recall chart saved → {out_path}\n")


if __name__ == "__main__":
    evaluate()