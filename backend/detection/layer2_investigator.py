# backend/detection/layer2_scanner.py
"""
Layer 2 Deep Scanner — Cloud Sentinel
======================================
Runs only on packets that failed Layer 1.
Extracts IP header info, payload data, latency,
categorises severity, and calls the AI for a recommendation.

Target latency: < 50ms total (including AI call).
"""

import time
import ipaddress
import hashlib
import random
from datetime import datetime
from typing import Optional


# ── Known malicious IP ranges (simplified — extend with threat intel feed) ───
KNOWN_BAD_PREFIXES = [
    "185.220.",   # Tor exit nodes
    "45.142.",    # common botnet ranges
    "194.165.",
]

# ── Severity thresholds ───────────────────────────────────────────────────────
SEVERITY_HIGH   = 0.7
SEVERITY_MEDIUM = 0.4


class Layer2Scanner:
    """
    Deep packet inspector.
    Returns a full report with severity category and AI recommendation.
    """

    def scan(self, packet: dict, layer1_result: dict) -> dict:
        """
        Perform deep scan on a flagged packet.

        Args:
            packet:        raw packet dict from /process_log
            layer1_result: output from Layer1Filter.check()

        Returns:
            Full scan report dict.
        """
        t_start = time.perf_counter()

        ip_info    = self._parse_ip_header(packet)
        payload    = self._extract_payload(packet)
        data_point = self._build_data_point(packet, ip_info)
        latency    = self._measure_latency(packet)
        score      = self._calculate_risk_score(ip_info, payload, data_point, latency, layer1_result)
        severity   = self._classify_severity(score)
        ai_rec     = self._ai_recommendation(score, severity, ip_info, payload, data_point)

        elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)

        return {
            "scan_id":       f"L2-{hashlib.md5(str(packet).encode()).hexdigest()[:8].upper()}",
            "timestamp":     datetime.utcnow().isoformat() + "Z",
            "elapsed_ms":    elapsed_ms,
            "layer1_result": layer1_result,
            "ip_header":     ip_info,
            "payload":       payload,
            "data_point":    data_point,
            "latency":       latency,
            "risk_score":    round(score, 4),
            "severity":      severity,          # "LOW" | "MEDIUM" | "HIGH"
            "ai_recommendation": ai_rec,
        }

    # ── Private helpers ───────────────────────────────────────────────────────

    def _parse_ip_header(self, packet: dict) -> dict:
        """Extract and classify IP header fields."""
        raw_ip = packet.get("ip_address", "10.0.0.1")
        ttl    = packet.get("ttl", 64)

        try:
            ip_obj = ipaddress.ip_address(raw_ip)
            is_private   = ip_obj.is_private
            is_loopback  = ip_obj.is_loopback
            version      = ip_obj.version
        except ValueError:
            is_private  = False
            is_loopback = False
            version     = 4

        is_known_bad = any(raw_ip.startswith(pfx) for pfx in KNOWN_BAD_PREFIXES)
        ttl_normal   = 30 <= ttl <= 128

        return {
            "source_ip":    raw_ip,
            "version":      f"IPv{version}",
            "ttl":          ttl,
            "ttl_normal":   ttl_normal,
            "is_private":   is_private,
            "is_loopback":  is_loopback,
            "is_known_bad": is_known_bad,
            "protocol":     packet.get("protocol", "TCP"),
            "source_port":  packet.get("source_port", random.randint(1024, 65535)),
            "dest_port":    packet.get("dest_port", 443),
        }

    def _extract_payload(self, packet: dict) -> dict:
        """Analyse payload characteristics."""
        size_in    = packet.get("packet_size_in", packet.get("packet_size", 512))
        size_out   = packet.get("packet_size_out", 0)
        api_calls  = packet.get("num_api_calls", 0)
        memory     = packet.get("memory_used", 0)
        fragments  = packet.get("fragment_count", 0)

        size_ratio = round(size_out / max(size_in, 1), 2)

        return {
            "size_bytes_in":    size_in,
            "size_bytes_out":   size_out,
            "size_ratio":       size_ratio,          # > 5 = potential exfiltration
            "api_calls":        api_calls,
            "memory_used_mb":   memory,
            "fragment_count":   fragments,
            "has_fragments":    fragments > 0,
            "content_type":     packet.get("content_type", "application/json"),
        }

    def _build_data_point(self, packet: dict, ip_info: dict) -> dict:
        """Construct the structured data point for the report."""
        return {
            "function_name":    packet.get("function_name", "unknown"),
            "duration_ms":      packet.get("duration", 0),
            "memory_mb":        packet.get("memory_used", 0),
            "outbound_calls":   packet.get("num_api_calls", 0),
            "unique_dest":      packet.get("unique_destinations", 1),
            "error_count":      packet.get("error_count", 0),
            "source_region":    packet.get("region", "us-east-1"),
            "geo_country":      "Unknown" if not ip_info["is_private"] else "Internal",
        }

    def _measure_latency(self, packet: dict) -> dict:
        """Extract latency metrics."""
        duration = packet.get("duration", 0)
        return {
            "execution_ms":  duration,
            "network_ms":    packet.get("network_latency", round(duration * 0.1, 2)),
            "total_ms":      round(duration * 1.1, 2),
            "is_high":       duration > 2000,
        }

    def _calculate_risk_score(
        self, ip_info, payload, data_point, latency, layer1_result
    ) -> float:
        """Combine signals into a 0–1 risk score."""
        score = 0.0

        # IP signals
        if ip_info["is_known_bad"]:   score += 0.40
        if not ip_info["ttl_normal"]: score += 0.15
        if not ip_info["is_private"]: score += 0.05

        # Payload signals
        if payload["size_ratio"] > 10:  score += 0.25
        elif payload["size_ratio"] > 5: score += 0.15
        if payload["fragment_count"] > 5: score += 0.10
        if payload["api_calls"] > 20:   score += 0.15

        # Latency signals
        if latency["is_high"]:          score += 0.10

        # Layer 1 signals — add weight for each failed check
        failed = [k for k, v in layer1_result.get("checks", {}).items() if not v]
        score += len(failed) * 0.05

        return min(score, 1.0)

    def _classify_severity(self, score: float) -> str:
        if score >= SEVERITY_HIGH:   return "HIGH"
        if score >= SEVERITY_MEDIUM: return "MEDIUM"
        return "LOW"

    def _ai_recommendation(
        self, score: float, severity: str, ip_info: dict, payload: dict, data_point: dict
    ) -> dict:
        """
        Rule-based AI recommendation engine.
        Returns action (BLOCK/PASS/MONITOR) with reasoning.
        Replace with Anthropic API call for richer analysis.
        """
        reasons   = []
        action    = "PASS"
        confidence = round(0.5 + score * 0.5, 2)

        if ip_info["is_known_bad"]:
            reasons.append("Source IP matches known malicious range")
            action = "BLOCK"

        if payload["size_ratio"] > 10:
            reasons.append(f"Data exfiltration pattern detected (out/in ratio: {payload['size_ratio']}x)")
            action = "BLOCK"

        if data_point["outbound_calls"] > 20:
            reasons.append(f"Excessive outbound API calls ({data_point['outbound_calls']})")
            action = "BLOCK" if action != "BLOCK" else "BLOCK"

        if not ip_info["ttl_normal"]:
            reasons.append(f"Abnormal TTL value ({ip_info['ttl']}) — possible IP spoofing")
            if action == "PASS": action = "MONITOR"

        if payload["fragment_count"] > 5:
            reasons.append(f"High fragmentation ({payload['fragment_count']} fragments) — possible evasion")
            if action == "PASS": action = "MONITOR"

        if severity == "LOW" and not reasons:
            reasons.append("Traffic within normal behavioral bounds")
            action = "PASS"

        return {
            "action":     action,        # "BLOCK" | "MONITOR" | "PASS"
            "confidence": confidence,
            "reasoning":  reasons if reasons else ["No significant anomalies detected"],
            "risk_score": round(score, 4),
        }