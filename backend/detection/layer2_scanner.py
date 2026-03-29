"""
Layer 2 Scanner — Cloud Sentinel
==================================
Orchestrates all Layer 2 deep analysis modules:
  1. IP Analyzer        — geolocation, ASN, reputation, spoofing, history
  2. Packet Analyzer    — size, fragmentation, latency, protocol, exfiltration
  3. Attack Patterns    — DDoS, spoofing, SQLi, crypto mining, exfil, memory
  4. Network Topology   — routing path, hop count, transit providers
  5. Risk Scorer        — composite risk, confidence, severity, recommendation

Author: Saleem Akthar
"""

import time
import uuid
from datetime import datetime
from typing import Optional

from backend.detection.ip_analyzer       import IPAnalyzer
from backend.detection.packet_analyzer   import PacketAnalyzer
from backend.detection.attack_patterns   import match_all_patterns
from backend.detection.network_topology  import NetworkTopologyAnalyzer
from backend.detection.risk_scorer       import RiskScorer


# ── Module singletons (loaded once at startup) ────────────────────────────────
_ip_analyzer       = IPAnalyzer()
_packet_analyzer   = PacketAnalyzer()
_topology_analyzer = NetworkTopologyAnalyzer()
_risk_scorer       = RiskScorer()


class Layer2Scanner:
    """
    Deep packet / behavioural scanner for Cloud Sentinel.

    Usage:
        scanner = Layer2Scanner()
        report  = scanner.scan(packet_data, layer1_result)
    """

    def scan(self, packet: dict, layer1_result: Optional[dict] = None) -> dict:
        t0       = time.perf_counter()
        scan_id  = f"L2-{uuid.uuid4().hex[:12].upper()}"
        ts       = datetime.utcnow().isoformat() + "Z"

        if layer1_result is None:
            layer1_result = {"pass": False, "checks": {}, "reason": "No Layer 1 result provided"}

        # ── Step 1: IP Analysis ───────────────────────────────────────────────
        ip_str     = packet.get("ip_address", "10.0.0.1")
        ttl        = packet.get("ttl", 64)
        ip_result  = _ip_analyzer.analyze(ip_str, ttl)

        # ── Step 2: Packet Analysis ───────────────────────────────────────────
        pkt_result = _packet_analyzer.analyze(packet)

        # ── Step 3: Attack Pattern Matching ───────────────────────────────────
        pattern_result = match_all_patterns(packet, ip_result, pkt_result)

        # ── Step 4: Network Topology ──────────────────────────────────────────
        topo_result = _topology_analyzer.analyze(packet, ip_result)

        # ── Step 5: Risk Scoring ──────────────────────────────────────────────
        risk_result = _risk_scorer.score(
            packet           = packet,
            ip_analysis      = ip_result,
            packet_analysis  = pkt_result,
            pattern_results  = pattern_result,
            topology_analysis = topo_result,
            layer1_result    = layer1_result,
        )

        elapsed_ms = round((time.perf_counter() - t0) * 1000, 3)

        return {
            "scan_id":    scan_id,
            "timestamp":  ts,
            "elapsed_ms": elapsed_ms,
            "severity":   risk_result["severity"],
            "decision":   risk_result["recommendation"]["action"],

            # Module outputs
            "ip":         ip_result,
            "packet":     pkt_result,
            "patterns":   pattern_result,
            "topology":   topo_result,
            "risk":       risk_result,

            # Layer 1 context
            "layer1":     layer1_result,
        }