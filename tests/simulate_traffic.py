"""
Cloud Sentinel — Traffic Simulation Engine
==========================================
Generates 1000 realistic Lambda traffic packets (50% normal, 50% attacks)
and feeds them through the full pipeline, printing live results.

Run from project root:
    python tests/simulate_traffic.py

Author: Backend Team
"""

import sys
import os
import time
import random
import math
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ── Colours ───────────────────────────────────────────────────────────────────
R  = "\033[91m"   # Red
G  = "\033[92m"   # Green
Y  = "\033[93m"   # Yellow
B  = "\033[94m"   # Blue
M  = "\033[95m"   # Magenta
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White
DIM= "\033[2m"
BOLD="\033[1m"
RST= "\033[0m"

# ── Decision colours ──────────────────────────────────────────────────────────
DECISION_COLOUR = {
    "ALLOW":       G,
    "INVESTIGATE": Y,
    "BLOCK":       R,
}

SEVERITY_COLOUR = {
    "SAFE":     G,
    "LOW":      G,
    "MEDIUM":   Y,
    "HIGH":     M,
    "CRITICAL": R,
}

# ============================================================================
# PACKET GENERATORS
# ============================================================================

# Realistic AWS IP ranges for normal traffic
NORMAL_IPS = [
    "52.94.{}.{}",
    "54.239.{}.{}",
    "18.144.{}.{}",
    "3.5.{}.{}",
]

# Known bad IPs for attack traffic
ATTACK_IPS = {
    "crypto_mining":    ["185.220.101.45", "185.220.102.8",  "45.142.212.100"],
    "data_exfil":       ["194.165.16.100", "194.165.17.200", "89.248.160.10"],
    "ddos":             ["45.142.120.100", "185.220.101.99", "194.165.16.55"],
    "sql_injection":    ["89.248.160.10",  "80.82.77.5",     "185.220.101.20"],
    "ip_spoofing":      ["10.0.0.1",       "192.168.1.100",  "172.16.0.1"],
    "memory_attack":    ["80.82.77.5",     "198.98.51.100",  "45.142.212.55"],
}

FUNCTION_NAMES = [
    "process-orders", "user-auth", "api-handler",
    "image-resize",   "send-email", "data-sync",
    "report-gen",     "payment-handler",
]

ATTACK_FUNCTION_NAMES = {
    "crypto_mining":  ["hash-worker", "compute-node", "cpu-task"],
    "data_exfil":     ["export-data", "backup-sync", "data-transfer"],
    "ddos":           ["api-handler", "request-handler", "gateway"],
    "sql_injection":  ["user-lookup", "db-query", "search-handler"],
    "ip_spoofing":    ["internal-sync", "vpc-connector", "lambda-proxy"],
    "memory_attack":  ["image-processor", "video-encoder", "large-compute"],
}


def _rand_ip(template: str) -> str:
    return template.format(random.randint(1, 254), random.randint(1, 254))


def _normal_packet(req_num: int, hour: int) -> dict:
    """Generate a realistic normal Lambda execution packet."""
    # Peak hours have naturally higher duration and memory
    is_peak     = 8 <= hour <= 20
    dur_base    = 480 if is_peak else 350
    mem_base    = 130 if is_peak else 118
    api_base    = 3   if is_peak else 2

    ip_template = random.choice(NORMAL_IPS)

    return {
        "ip_address":          _rand_ip(ip_template),
        "ttl":                 random.randint(50, 64),
        "duration":            dur_base + random.randint(-60, 120),
        "memory_used":         mem_base + random.randint(-10, 20),
        "num_api_calls":       api_base + random.randint(0, 2),
        "packet_size_in":      random.randint(256, 1024),
        "packet_size_out":     random.randint(128, 512),
        "fragment_count":      0,
        "protocol":            "HTTPS",
        "dest_port":           443,
        "source_port":         random.randint(49152, 65535),
        "network_latency":     random.uniform(5, 25),
        "unique_destinations": 1,
        "error_count":         0,
        "memory_limit":        512,
        "function_name":       random.choice(FUNCTION_NAMES),
        "region":              "us-east-1",
        "db_queries":          random.randint(0, 3),
        "_traffic_type":       "normal",
    }


def _crypto_mining_packet() -> dict:
    return {
        "ip_address":          random.choice(ATTACK_IPS["crypto_mining"]),
        "ttl":                 random.randint(40, 52),
        "duration":            random.randint(8000, 14999),
        "memory_used":         random.randint(380, 510),
        "num_api_calls":       random.randint(0, 2),
        "packet_size_in":      random.randint(64, 256),
        "packet_size_out":     random.randint(32, 128),
        "fragment_count":      0,
        "protocol":            "HTTPS",
        "dest_port":           443,
        "source_port":         random.randint(49152, 65535),
        "network_latency":     random.uniform(2, 10),
        "unique_destinations": 1,
        "error_count":         0,
        "memory_limit":        512,
        "function_name":       random.choice(ATTACK_FUNCTION_NAMES["crypto_mining"]),
        "region":              "us-east-1",
        "db_queries":          0,
        "_traffic_type":       "crypto_mining",
    }


def _data_exfil_packet() -> dict:
    size_in  = random.randint(100, 300)
    size_out = random.randint(200000, 600000)
    return {
        "ip_address":          random.choice(ATTACK_IPS["data_exfil"]),
        "ttl":                 random.randint(46, 58),
        "duration":            random.randint(400, 900),
        "memory_used":         random.randint(280, 400),
        "num_api_calls":       random.randint(20, 40),
        "packet_size_in":      size_in,
        "packet_size_out":     size_out,
        "fragment_count":      0,
        "protocol":            "HTTPS",
        "dest_port":           443,
        "source_port":         random.randint(49152, 65535),
        "network_latency":     random.uniform(15, 40),
        "unique_destinations": random.randint(5, 12),
        "error_count":         0,
        "memory_limit":        512,
        "function_name":       random.choice(ATTACK_FUNCTION_NAMES["data_exfil"]),
        "region":              "us-east-1",
        "db_queries":          random.randint(8, 20),
        "_traffic_type":       "data_exfiltration",
    }


def _ddos_packet() -> dict:
    return {
        "ip_address":          random.choice(ATTACK_IPS["ddos"]),
        "ttl":                 random.randint(38, 52),
        "duration":            random.randint(20, 60),
        "memory_used":         random.randint(40, 80),
        "num_api_calls":       random.randint(80, 150),
        "packet_size_in":      random.randint(32, 96),
        "packet_size_out":     random.randint(16, 48),
        "fragment_count":      random.randint(8, 16),
        "protocol":            "TCP",
        "dest_port":           80,
        "source_port":         random.randint(1024, 5000),
        "network_latency":     random.uniform(1, 5),
        "unique_destinations": 1,
        "error_count":         0,
        "memory_limit":        512,
        "function_name":       random.choice(ATTACK_FUNCTION_NAMES["ddos"]),
        "region":              "us-east-1",
        "db_queries":          0,
        "_traffic_type":       "ddos",
    }


def _sql_injection_packet() -> dict:
    return {
        "ip_address":          random.choice(ATTACK_IPS["sql_injection"]),
        "ttl":                 random.randint(48, 60),
        "duration":            random.randint(4500, 8000),
        "memory_used":         random.randint(200, 320),
        "num_api_calls":       random.randint(6, 12),
        "packet_size_in":      random.randint(256, 768),
        "packet_size_out":     random.randint(512, 2048),
        "fragment_count":      0,
        "protocol":            "HTTPS",
        "dest_port":           3306,
        "source_port":         random.randint(49152, 65535),
        "network_latency":     random.uniform(10, 30),
        "unique_destinations": 1,
        "error_count":         random.randint(4, 10),
        "memory_limit":        512,
        "function_name":       random.choice(ATTACK_FUNCTION_NAMES["sql_injection"]),
        "region":              "us-east-1",
        "db_queries":          random.randint(30, 60),
        "_traffic_type":       "sql_injection",
    }


def _ip_spoofing_packet() -> dict:
    return {
        "ip_address":          random.choice(ATTACK_IPS["ip_spoofing"]),
        "ttl":                 random.choice([1, 3, 250, 254, 0]),   # impossible TTLs
        "duration":            random.randint(200, 600),
        "memory_used":         random.randint(100, 160),
        "num_api_calls":       random.randint(2, 8),
        "packet_size_in":      random.randint(512, 1024),
        "packet_size_out":     random.randint(256, 512),
        "fragment_count":      random.randint(2, 6),
        "protocol":            "HTTPS",
        "dest_port":           443,
        "source_port":         random.randint(1, 1023),   # low port = suspicious
        "network_latency":     random.uniform(1, 8),
        "unique_destinations": random.randint(1, 3),
        "error_count":         random.randint(0, 2),
        "memory_limit":        512,
        "function_name":       random.choice(ATTACK_FUNCTION_NAMES["ip_spoofing"]),
        "region":              "us-east-1",
        "db_queries":          0,
        "_traffic_type":       "ip_spoofing",
    }


def _memory_attack_packet() -> dict:
    memory = random.randint(470, 512)
    duration = random.randint(6000, 12000)
    return {
        "ip_address":          random.choice(ATTACK_IPS["memory_attack"]),
        "ttl":                 random.randint(44, 58),
        "duration":            duration,
        "memory_used":         memory,
        "num_api_calls":       random.randint(3, 8),
        "packet_size_in":      random.randint(128, 512),
        "packet_size_out":     random.randint(64, 256),
        "fragment_count":      0,
        "protocol":            "HTTPS",
        "dest_port":           443,
        "source_port":         random.randint(49152, 65535),
        "network_latency":     random.uniform(5, 20),
        "unique_destinations": 1,
        "error_count":         random.randint(1, 5),
        "memory_limit":        512,
        "function_name":       random.choice(ATTACK_FUNCTION_NAMES["memory_attack"]),
        "region":              "us-east-1",
        "db_queries":          0,
        "_traffic_type":       "memory_attack",
    }


ATTACK_GENERATORS = [
    _crypto_mining_packet,
    _data_exfil_packet,
    _ddos_packet,
    _sql_injection_packet,
    _ip_spoofing_packet,
    _memory_attack_packet,
]


# ============================================================================
# TRAFFIC SEQUENCE BUILDER
# 1000 packets: 500 normal, 500 attacks (all 6 types ~evenly distributed)
# Shuffled so attacks are interspersed with normal traffic
# ============================================================================

def build_traffic_sequence(total: int = 1000, attack_ratio: float = 0.5) -> list:
    n_attacks   = int(total * attack_ratio)
    n_normal    = total - n_attacks

    # Distribute attacks evenly across 6 types
    per_type    = n_attacks // len(ATTACK_GENERATORS)
    remainder   = n_attacks % len(ATTACK_GENERATORS)

    packets = []

    # Normal traffic — vary hour to simulate peak/off-peak
    for i in range(n_normal):
        hour = (8 + int(i / n_normal * 14)) % 24   # ramp from 8am to 10pm
        packets.append(_normal_packet(i, hour))

    # Attack traffic
    for idx, gen in enumerate(ATTACK_GENERATORS):
        count = per_type + (1 if idx < remainder else 0)
        for _ in range(count):
            packets.append(gen())

    random.shuffle(packets)
    return packets


# ============================================================================
# SIMULATION RUNNER
# ============================================================================

class SimulationRunner:

    def __init__(self):
        self.stats = {
            "total":       0,
            "allow":       0,
            "investigate": 0,
            "block":       0,
            "by_type":     defaultdict(lambda: {"allow": 0, "investigate": 0, "block": 0, "total": 0}),
            "layer_stops": {"layer1": 0, "ai_model": 0},
            "elapsed_ms":  [],
            "correct":     0,   # attack got INVESTIGATE or BLOCK
            "missed":      0,   # attack got ALLOW
            "false_pos":   0,   # normal got BLOCK or INVESTIGATE
        }

    def run(self, packets: list):
        from backend.detection.pipeline import CloudSentinelPipeline
        pipeline = CloudSentinelPipeline()

        self._print_header(len(packets))

        # Seed pipeline with 100 normal packets first (learning phase)
        self._seed_learning_phase(pipeline, packets)

        print(f"\n{BOLD}{C}{'─'*75}{RST}")
        print(f"{BOLD}{W}  LIVE TRAFFIC SIMULATION — {len(packets)} PACKETS{RST}")
        print(f"{C}{'─'*75}{RST}\n")

        for i, packet in enumerate(packets, 1):
            result       = pipeline.process(packet)
            traffic_type = packet.get("_traffic_type", "normal")
            self._record(result, traffic_type)
            self._print_packet(i, len(packets), packet, result)

            # Print summary every 100 packets
            if i % 100 == 0:
                self._print_interim_summary(i)

        self._print_final_summary()

    def _seed_learning_phase(self, pipeline, packets):
        """Feed 100 normal packets to establish AI model baseline."""
        print(f"\n{BOLD}{B}  PHASE 1 — AI Model Learning Baseline (100 normal packets){RST}")
        print(f"{DIM}  Feeding normal traffic to establish detection baseline...{RST}")

        normal_packets = [p for p in packets if p.get("_traffic_type") == "normal"][:100]

        for i, pkt in enumerate(normal_packets, 1):
            pipeline.process(pkt)
            if i % 25 == 0:
                bar = "█" * (i // 5) + "░" * (20 - i // 5)
                print(f"  [{bar}] {i}/100", end="\r")

        print(f"  [{BOLD}{'█'*20}{RST}] 100/100  {G}✓ Baseline established{RST}          ")

    def _record(self, result: dict, traffic_type: str):
        decision = result["decision"]
        self.stats["total"] += 1
        self.stats[decision.lower()] += 1
        self.stats["by_type"][traffic_type]["total"] += 1
        self.stats["by_type"][traffic_type][decision.lower()] += 1
        self.stats["layer_stops"][result.get("stopped_at", "ai_model")] += 1
        self.stats["elapsed_ms"].append(result["elapsed_ms"])

        is_attack  = traffic_type != "normal"
        if is_attack and decision in ("INVESTIGATE", "BLOCK"):
            self.stats["correct"] += 1
        elif is_attack and decision == "ALLOW":
            self.stats["missed"] += 1
        elif not is_attack and decision in ("INVESTIGATE", "BLOCK"):
            self.stats["false_pos"] += 1

    def _print_header(self, total: int):
        print(f"\n{BOLD}{B}{'═'*75}{RST}")
        print(f"{BOLD}{W}  CLOUD SENTINEL — TRAFFIC SIMULATION ENGINE{RST}")
        print(f"{DIM}  Full Pipeline: Layer 1 → Layer 2 → SARIMA → AI Model{RST}")
        print(f"{BOLD}{B}{'═'*75}{RST}")
        print(f"  Total packets : {BOLD}{total}{RST}")
        print(f"  Normal traffic: {G}500 packets (50%){RST}")
        print(f"  Attack traffic: {R}500 packets (50%){RST}  "
              f"[{', '.join(['crypto','exfil','ddos','sqli','spoof','memory'])}]")
        print(f"  Started at    : {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')} UTC")

    def _print_packet(self, i: int, total: int, packet: dict, result: dict):
        decision     = result["decision"]
        severity     = result["severity"]
        traffic_type = packet.get("_traffic_type", "normal")
        stopped_at   = result.get("stopped_at", "?")
        confidence   = result.get("confidence", 0)
        elapsed      = result.get("elapsed_ms", 0)

        dc   = DECISION_COLOUR.get(decision, W)
        sc   = SEVERITY_COLOUR.get(severity, W)
        type_colour = G if traffic_type == "normal" else R

        # Shorten type label
        type_label = {
            "normal":           "NORMAL  ",
            "crypto_mining":    "CRYPTO  ",
            "data_exfiltration":"EXFIL   ",
            "ddos":             "DDOS    ",
            "sql_injection":    "SQLI    ",
            "ip_spoofing":      "SPOOF   ",
            "memory_attack":    "MEMORY  ",
        }.get(traffic_type, traffic_type[:8].upper().ljust(8))

        # Missed attack flag
        missed = ""
        if traffic_type != "normal" and decision == "ALLOW":
            missed = f" {Y}⚠ MISSED{RST}"
        elif traffic_type == "normal" and decision == "BLOCK":
            missed = f" {M}⚠ FALSE+{RST}"

        print(
            f"  {DIM}#{i:04d}{RST} "
            f"{type_colour}{type_label}{RST} "
            f"│ {dc}{decision:11s}{RST} "
            f"│ {sc}{severity:8s}{RST} "
            f"│ conf={BOLD}{confidence:.0%}{RST} "
            f"│ {DIM}stopped@{stopped_at:<8}{RST} "
            f"│ {DIM}{elapsed:.1f}ms{RST}"
            f"{missed}"
        )

    def _print_interim_summary(self, processed: int):
        s = self.stats
        total = s["total"]
        print(f"\n  {BOLD}{C}── Checkpoint @ {processed} packets ──────────────────────────{RST}")
        print(f"  {G}ALLOW{RST}:       {s['allow']:4d}  ({s['allow']/total*100:.1f}%)")
        print(f"  {Y}INVESTIGATE{RST}: {s['investigate']:4d}  ({s['investigate']/total*100:.1f}%)")
        print(f"  {R}BLOCK{RST}:       {s['block']:4d}  ({s['block']/total*100:.1f}%)")
        attacks_processed = sum(
            v["total"] for k, v in s["by_type"].items() if k != "normal"
        )
        if attacks_processed > 0:
            detection_rate = (s["correct"] / attacks_processed) * 100
            print(f"  {B}Detection rate{RST}: {detection_rate:.1f}%  "
                  f"| Missed: {s['missed']}  | False+: {s['false_pos']}")
        print()

    def _print_final_summary(self):
        s     = self.stats
        total = s["total"]
        times = s["elapsed_ms"]

        attacks_total = sum(v["total"] for k, v in s["by_type"].items() if k != "normal")
        normal_total  = s["by_type"]["normal"]["total"]
        detection_rate = (s["correct"] / max(attacks_total, 1)) * 100
        false_pos_rate = (s["false_pos"] / max(normal_total, 1)) * 100
        avg_ms = sum(times) / len(times) if times else 0
        p95_ms = sorted(times)[int(len(times) * 0.95)] if times else 0

        print(f"\n{BOLD}{B}{'═'*75}{RST}")
        print(f"{BOLD}{W}  SIMULATION COMPLETE — FINAL REPORT{RST}")
        print(f"{BOLD}{B}{'═'*75}{RST}\n")

        # Decision breakdown
        print(f"  {BOLD}DECISION BREAKDOWN{RST}")
        print(f"  {'─'*45}")
        print(f"  {G}✓ ALLOW{RST}       : {s['allow']:5d}  ({s['allow']/total*100:5.1f}%)")
        print(f"  {Y}⚑ INVESTIGATE{RST} : {s['investigate']:5d}  ({s['investigate']/total*100:5.1f}%)")
        print(f"  {R}✗ BLOCK{RST}       : {s['block']:5d}  ({s['block']/total*100:5.1f}%)\n")

        # Detection performance
        print(f"  {BOLD}DETECTION PERFORMANCE{RST}")
        print(f"  {'─'*45}")
        print(f"  Attacks processed   : {attacks_total}")
        print(f"  Correctly detected  : {G}{s['correct']}{RST} ({detection_rate:.1f}%)")
        print(f"  Missed attacks      : {R if s['missed'] > 0 else G}{s['missed']}{RST}")
        print(f"  False positives     : {Y if s['false_pos'] > 0 else G}{s['false_pos']}{RST} ({false_pos_rate:.1f}%)\n")

        # Per attack type
        print(f"  {BOLD}PER ATTACK TYPE{RST}")
        print(f"  {'─'*65}")
        print(f"  {'Type':<22} {'Total':>6} {'ALLOW':>7} {'INVEST':>8} {'BLOCK':>7} {'Caught%':>8}")
        print(f"  {'─'*65}")

        type_order = [
            "normal", "crypto_mining", "data_exfiltration",
            "ddos", "sql_injection", "ip_spoofing", "memory_attack"
        ]
        for ttype in type_order:
            if ttype not in s["by_type"]:
                continue
            d         = s["by_type"][ttype]
            ttl_count = d["total"]
            allow     = d["allow"]
            invest    = d["investigate"]
            block     = d["block"]
            tc        = G if ttype == "normal" else R
            if ttype == "normal":
                caught_pct = f"{(1 - allow/max(ttl_count,1))*100:.0f}% false+"
                caught_c   = G if s['false_pos'] == 0 else Y
            else:
                caught     = invest + block
                caught_pct = f"{caught/max(ttl_count,1)*100:.0f}% caught"
                caught_c   = G if caught/max(ttl_count,1) >= 0.8 else (Y if caught/max(ttl_count,1) >= 0.5 else R)

            label = ttype.replace("_", " ").title()
            print(f"  {tc}{label:<22}{RST} {ttl_count:>6} {allow:>7} {invest:>8} {block:>7} "
                  f"{caught_c}{caught_pct:>8}{RST}")

        # Layer stops
        print(f"\n  {BOLD}WHERE TRAFFIC WAS STOPPED{RST}")
        print(f"  {'─'*45}")
        l1_stops = s["layer_stops"]["layer1"]
        ai_stops = s["layer_stops"]["ai_model"]
        print(f"  Stopped at Layer 1 (fast gate) : {G}{l1_stops:5d}{RST}  "
              f"({l1_stops/total*100:.1f}%)  — no Layer 2 needed")
        print(f"  Reached AI model (full pipeline): {B}{ai_stops:5d}{RST}  "
              f"({ai_stops/total*100:.1f}%)  — full scan ran")

        # Performance
        print(f"\n  {BOLD}PERFORMANCE{RST}")
        print(f"  {'─'*45}")
        print(f"  Average pipeline time : {avg_ms:.2f}ms")
        print(f"  95th percentile time  : {p95_ms:.2f}ms")
        print(f"  Peak time             : {max(times):.2f}ms")
        fast = sum(1 for t in times if t < 5)
        print(f"  Packets under 5ms     : {fast} ({fast/total*100:.1f}%)")

        # SARIMA status
        try:
            from backend.detection.pipeline import _sarima
            sarima_status = _sarima.get_status()
            print(f"\n  {BOLD}SARIMA STATUS{RST}")
            print(f"  {'─'*45}")
            print(f"  Trained    : {G if sarima_status['trained'] else Y}"
                  f"{sarima_status['trained']}{RST}")
            print(f"  Data points: {sarima_status['data_points']}")
            print(f"  Progress   : {sarima_status['progress_pct']}%")
            print(f"  Using fallback: {sarima_status['using_fallback']}")
        except Exception:
            pass

        print(f"\n{BOLD}{B}{'═'*75}{RST}")
        grade = (
            f"{G}EXCELLENT{RST}" if detection_rate >= 90 else
            f"{Y}GOOD{RST}"      if detection_rate >= 75 else
            f"{M}FAIR{RST}"      if detection_rate >= 60 else
            f"{R}NEEDS TUNING{RST}"
        )
        print(f"  {BOLD}Overall Grade: {grade}  "
              f"(detection {detection_rate:.1f}% | false+ {false_pos_rate:.1f}%){RST}")
        print(f"{BOLD}{B}{'═'*75}{RST}\n")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    random.seed(42)   # reproducible results

    print(f"{BOLD}{C}")
    print("  ╔═══════════════════════════════════════════════════════════╗")
    print("  ║        CLOUD SENTINEL — SIMULATION ENGINE v1.0           ║")
    print("  ║   Layer1 → Layer2 → SARIMA → AI Model → ALLOW/INVEST/BLOCK ║")
    print("  ╚═══════════════════════════════════════════════════════════╝")
    print(f"{RST}")

    packets = build_traffic_sequence(total=1000, attack_ratio=0.5)
    runner  = SimulationRunner()

    try:
        runner.run(packets)
    except KeyboardInterrupt:
        print(f"\n\n{Y}  Simulation interrupted by user.{RST}\n")
        runner._print_final_summary()
    except ImportError as e:
        print(f"\n{R}  Import error: {e}{RST}")
        print(f"  Make sure all pipeline files are in backend/detection/")
        print(f"  Required: pipeline.py, layer1_filter.py, layer2_scanner.py,")
        print(f"            sarima_forecaster.py, layer1_scorer.py\n")
        sys.exit(1)