"""
Packet Analyzer — Cloud Sentinel Layer 2
==========================================
Performs deep analysis of packet-level metrics derived from
AWS Lambda execution metadata.

Covers:
  - Packet size analysis
  - Fragmentation pattern detection
  - Latency breakdown (execution, network, overhead)
  - Protocol analysis
  - Data exfiltration scoring

All in-memory. Zero I/O. Target: < 1ms per call.

Author: Saleem Akthar
"""

import math
import time
from typing import Dict, Tuple


# ============================================================================
# THRESHOLDS
# ============================================================================

# Packet size (bytes)
SIZE_NORMAL_MIN  = 64
SIZE_NORMAL_MAX  = 8192      # 8 KB — normal Lambda request/response
SIZE_LARGE       = 65536     # 64 KB — large but possible
SIZE_SUSPICIOUS  = 1_048_576 # 1 MB — highly suspicious for Lambda

# Latency (ms)
LATENCY_FAST     = 100
LATENCY_NORMAL   = 1000
LATENCY_SLOW     = 3000
LATENCY_CRITICAL = 10000

# Exfiltration ratios
EXFIL_RATIO_LOW  = 2.0
EXFIL_RATIO_MED  = 5.0
EXFIL_RATIO_HIGH = 10.0

# Fragmentation
FRAG_LOW         = 2
FRAG_MEDIUM      = 5
FRAG_HIGH        = 10


# ============================================================================
# PACKET ANALYZER CLASS
# ============================================================================

class PacketAnalyzer:
    """
    Stateless packet analysis engine.
    Accepts a packet dict, returns a structured analysis report.
    """

    def analyze(self, packet: dict) -> dict:
        """
        Main entry point.

        Args:
            packet: dict with Lambda execution metadata fields

        Returns:
            Full packet analysis dict
        """
        t0 = time.perf_counter()

        size         = self._analyze_size(packet)
        fragmentation = self._analyze_fragmentation(packet)
        latency      = self._analyze_latency(packet)
        protocol     = self._analyze_protocol(packet)
        exfiltration = self._analyze_exfiltration(packet, size)

        # Composite packet risk score
        risk_score = self._calculate_packet_risk(
            size, fragmentation, latency, protocol, exfiltration
        )

        elapsed_us = round((time.perf_counter() - t0) * 1_000_000)

        return {
            "elapsed_us":    elapsed_us,
            "size":          size,
            "fragmentation": fragmentation,
            "latency":       latency,
            "protocol":      protocol,
            "exfiltration":  exfiltration,
            "risk_score":    round(risk_score, 4),
        }

    # ── Size Analysis ─────────────────────────────────────────────────────────

    def _analyze_size(self, packet: dict) -> dict:
        """Classify inbound and outbound packet sizes."""
        size_in  = packet.get("packet_size_in",  packet.get("packet_size", 512))
        size_out = packet.get("packet_size_out", 0)
        total    = size_in + size_out

        def classify(s: int) -> str:
            if s < SIZE_NORMAL_MIN:   return "tiny"
            if s <= SIZE_NORMAL_MAX:  return "normal"
            if s <= SIZE_LARGE:       return "large"
            if s <= SIZE_SUSPICIOUS:  return "very_large"
            return "suspicious"

        in_class  = classify(size_in)
        out_class = classify(size_out)

        anomaly_score = 0.0
        flags = []

        if size_in < SIZE_NORMAL_MIN:
            anomaly_score += 0.2
            flags.append(f"Unusually small inbound packet ({size_in} bytes)")

        if size_out > SIZE_SUSPICIOUS:
            anomaly_score += 0.6
            flags.append(f"Extremely large outbound payload ({size_out:,} bytes)")
        elif size_out > SIZE_LARGE:
            anomaly_score += 0.3
            flags.append(f"Large outbound payload ({size_out:,} bytes)")

        if size_in == 0 and size_out > 0:
            anomaly_score += 0.4
            flags.append("Zero inbound bytes with non-zero outbound — suspicious one-way flow")

        return {
            "bytes_in":       size_in,
            "bytes_out":      size_out,
            "total_bytes":    total,
            "class_in":       in_class,
            "class_out":      out_class,
            "flags":          flags,
            "anomaly_score":  round(min(anomaly_score, 1.0), 4),
        }

    # ── Fragmentation Analysis ────────────────────────────────────────────────

    def _analyze_fragmentation(self, packet: dict) -> dict:
        """
        Analyse fragmentation patterns.
        High fragmentation is a common DDoS and evasion technique.
        """
        frag_count   = packet.get("fragment_count", 0)
        api_calls    = packet.get("num_api_calls", 0)
        memory       = packet.get("memory_used", 0)

        # Infer fragmentation from memory spikes (Lambda context)
        # High memory with low API calls often means fragmented data reassembly
        inferred_frags = 0
        if memory > 400 and api_calls < 3:
            inferred_frags = int(memory / 100)

        effective_frags = max(frag_count, inferred_frags)

        flags = []
        anomaly_score = 0.0

        if effective_frags >= FRAG_HIGH:
            anomaly_score = 0.9
            flags.append(f"Critical fragmentation level ({effective_frags} fragments) — likely DDoS or evasion")
        elif effective_frags >= FRAG_MEDIUM:
            anomaly_score = 0.6
            flags.append(f"High fragmentation ({effective_frags} fragments) — possible evasion technique")
        elif effective_frags >= FRAG_LOW:
            anomaly_score = 0.3
            flags.append(f"Moderate fragmentation detected ({effective_frags} fragments)")

        pattern = self._classify_frag_pattern(effective_frags, memory, api_calls)

        return {
            "declared_fragments":  frag_count,
            "inferred_fragments":  inferred_frags,
            "effective_fragments": effective_frags,
            "pattern":             pattern,
            "flags":               flags,
            "anomaly_score":       round(anomaly_score, 4),
        }

    def _classify_frag_pattern(self, frags: int, memory: float, api_calls: int) -> str:
        """Classify the fragmentation pattern into a named category."""
        if frags == 0:                          return "none"
        if frags >= FRAG_HIGH:                  return "ddos_flooding"
        if frags >= FRAG_MEDIUM and memory > 300: return "memory_fragmentation_attack"
        if frags >= FRAG_MEDIUM:                return "evasion_fragmentation"
        if frags >= FRAG_LOW and api_calls > 10:  return "distributed_small_fragments"
        return "minor_fragmentation"

    # ── Latency Analysis ──────────────────────────────────────────────────────

    def _analyze_latency(self, packet: dict) -> dict:
        """
        Break down execution latency into components and classify behaviour.

        Lambda latency model:
          total = cold_start + execution + network_overhead
        """
        duration    = packet.get("duration", 0)
        net_latency = packet.get("network_latency", round(duration * 0.08, 2))
        memory      = packet.get("memory_used", 128)

        # Estimate cold start from memory (higher memory = longer cold start)
        cold_start  = round(max(0, (memory - 128) * 0.5), 2)
        execution   = max(0, duration - cold_start - net_latency)
        overhead    = round(duration * 0.02, 2)

        def classify_latency(d: float) -> str:
            if d <= LATENCY_FAST:     return "fast"
            if d <= LATENCY_NORMAL:   return "normal"
            if d <= LATENCY_SLOW:     return "slow"
            if d <= LATENCY_CRITICAL: return "critical"
            return "extreme"

        classification = classify_latency(duration)

        flags = []
        anomaly_score = 0.0

        if duration > LATENCY_CRITICAL:
            anomaly_score = 0.9
            flags.append(f"Extreme execution time ({duration:,.0f}ms) — crypto mining or infinite loop suspected")
        elif duration > LATENCY_SLOW:
            anomaly_score = 0.6
            flags.append(f"Slow execution ({duration:,.0f}ms) — possible resource exhaustion")
        elif duration < 10 and memory > 256:
            anomaly_score = 0.3
            flags.append("Suspiciously fast execution with high memory allocation")

        # Jitter score — high jitter between net and exec suggests throttling
        if execution > 0:
            jitter = round(abs(net_latency / execution), 4) if execution > 0 else 0
        else:
            jitter = 0.0

        return {
            "total_ms":       duration,
            "execution_ms":   round(execution, 2),
            "network_ms":     round(net_latency, 2),
            "cold_start_ms":  round(cold_start, 2),
            "overhead_ms":    round(overhead, 2),
            "jitter":         jitter,
            "classification": classification,
            "flags":          flags,
            "anomaly_score":  round(anomaly_score, 4),
        }

    # ── Protocol Analysis ─────────────────────────────────────────────────────

    def _analyze_protocol(self, packet: dict) -> dict:
        """
        Analyse protocol usage patterns for AWS Lambda traffic.

        Lambda typically uses HTTPS (TCP/443). Deviations are suspicious.
        """
        protocol   = packet.get("protocol", "HTTPS").upper()
        dest_port  = packet.get("dest_port", 443)
        src_port   = packet.get("source_port", 0)
        api_calls  = packet.get("num_api_calls", 0)

        # Expected protocol for Lambda
        expected_protocols = {"HTTPS", "HTTP", "TCP"}
        is_expected = protocol in expected_protocols

        # Port legitimacy
        well_known_ports = {
            80: "HTTP",  443: "HTTPS", 22: "SSH",
            3306: "MySQL", 5432: "PostgreSQL",
            6379: "Redis", 27017: "MongoDB",
        }
        port_label = well_known_ports.get(dest_port, f"Port-{dest_port}")
        is_unusual_port = dest_port not in well_known_ports and dest_port < 1024

        flags = []
        anomaly_score = 0.0

        if not is_expected:
            anomaly_score += 0.4
            flags.append(f"Unexpected protocol: {protocol} (Lambda should use HTTPS/TCP)")

        if dest_port == 22:
            anomaly_score += 0.5
            flags.append("SSH port (22) access from Lambda — highly suspicious")

        if is_unusual_port:
            anomaly_score += 0.3
            flags.append(f"Unusual destination port: {dest_port}")

        if api_calls > 50:
            anomaly_score += 0.4
            flags.append(f"Excessive API call volume ({api_calls}) — possible C2 communication")

        # Detect port scanning pattern (many calls to different ports)
        if src_port > 0 and src_port < 1024 and protocol != "HTTPS":
            anomaly_score += 0.2
            flags.append(f"Low source port ({src_port}) with non-HTTPS protocol")

        return {
            "protocol":       protocol,
            "dest_port":      dest_port,
            "dest_service":   port_label,
            "source_port":    src_port,
            "is_expected":    is_expected,
            "is_unusual_port": is_unusual_port,
            "api_call_count": api_calls,
            "flags":          flags,
            "anomaly_score":  round(min(anomaly_score, 1.0), 4),
        }

    # ── Data Exfiltration Scoring ─────────────────────────────────────────────

    def _analyze_exfiltration(self, packet: dict, size: dict) -> dict:
        """
        Multi-signal data exfiltration scoring.

        Signals:
          1. Outbound/inbound size ratio
          2. Number of unique destinations
          3. API call rate
          4. Memory usage pattern
          5. Execution pattern vs data volume
        """
        size_in     = size["bytes_in"]
        size_out    = size["bytes_out"]
        api_calls   = packet.get("num_api_calls", 0)
        unique_dest = packet.get("unique_destinations", 1)
        memory      = packet.get("memory_used", 0)
        duration    = packet.get("duration", 0)
        error_count = packet.get("error_count", 0)

        signals = {}
        flags   = []

        # Signal 1: Size ratio
        ratio = size_out / max(size_in, 1)
        if ratio >= EXFIL_RATIO_HIGH:
            signals["size_ratio"] = 1.0
            flags.append(f"Critical data ratio: sending {ratio:.1f}x more data than received")
        elif ratio >= EXFIL_RATIO_MED:
            signals["size_ratio"] = 0.7
            flags.append(f"High outbound ratio ({ratio:.1f}x) — possible exfiltration")
        elif ratio >= EXFIL_RATIO_LOW:
            signals["size_ratio"] = 0.3
            flags.append(f"Elevated outbound ratio ({ratio:.1f}x)")
        else:
            signals["size_ratio"] = 0.0

        # Signal 2: Unique destinations
        if unique_dest > 10:
            signals["unique_destinations"] = 1.0
            flags.append(f"Data sent to {unique_dest} unique destinations")
        elif unique_dest > 5:
            signals["unique_destinations"] = 0.6
            flags.append(f"Multiple destinations ({unique_dest})")
        elif unique_dest > 2:
            signals["unique_destinations"] = 0.3
        else:
            signals["unique_destinations"] = 0.0

        # Signal 3: API call rate
        calls_per_second = api_calls / max(duration / 1000, 0.001)
        if calls_per_second > 50:
            signals["api_rate"] = 1.0
            flags.append(f"Very high API call rate ({calls_per_second:.1f}/s) — bulk data transfer")
        elif calls_per_second > 20:
            signals["api_rate"] = 0.6
        elif api_calls > 15:
            signals["api_rate"] = 0.3
        else:
            signals["api_rate"] = 0.0

        # Signal 4: Memory with high output (data staging)
        if memory > 300 and size_out > SIZE_LARGE:
            signals["memory_staging"] = 0.7
            flags.append("High memory usage with large output — possible data staging in memory")
        else:
            signals["memory_staging"] = 0.0

        # Signal 5: Low error rate with high data volume (clean exfil)
        if error_count == 0 and size_out > SIZE_NORMAL_MAX and api_calls > 10:
            signals["clean_exfil"] = 0.5
            flags.append("Clean execution with high data volume — possible scripted exfiltration")
        else:
            signals["clean_exfil"] = 0.0

        # Weighted composite
        weights = {
            "size_ratio":          0.35,
            "unique_destinations": 0.25,
            "api_rate":            0.20,
            "memory_staging":      0.12,
            "clean_exfil":         0.08,
        }
        exfil_score = sum(signals[k] * weights[k] for k in signals)
        exfil_score = min(exfil_score, 1.0)

        classification = (
            "CRITICAL" if exfil_score >= 0.7 else
            "HIGH"     if exfil_score >= 0.5 else
            "MEDIUM"   if exfil_score >= 0.3 else
            "LOW"
        )

        return {
            "exfiltration_score": round(exfil_score, 4),
            "classification":     classification,
            "size_ratio":         round(ratio, 2),
            "unique_destinations": unique_dest,
            "api_calls_per_sec":  round(calls_per_second, 2),
            "signals":            {k: round(v, 4) for k, v in signals.items()},
            "flags":              flags,
        }

    # ── Composite Risk Score ──────────────────────────────────────────────────

    def _calculate_packet_risk(
        self,
        size: dict,
        fragmentation: dict,
        latency: dict,
        protocol: dict,
        exfiltration: dict,
    ) -> float:
        """
        Weighted composite packet risk score.

        Weights reflect real-world importance for Lambda security:
        exfiltration > latency > fragmentation > protocol > size
        """
        weights = {
            "exfiltration":  0.35,
            "latency":       0.25,
            "fragmentation": 0.20,
            "protocol":      0.12,
            "size":          0.08,
        }

        scores = {
            "exfiltration":  exfiltration["exfiltration_score"],
            "latency":       latency["anomaly_score"],
            "fragmentation": fragmentation["anomaly_score"],
            "protocol":      protocol["anomaly_score"],
            "size":          size["anomaly_score"],
        }

        composite = sum(scores[k] * weights[k] for k in weights)
        return min(composite, 1.0)