"""
Layer 1 Filter — Cloud Sentinel
================================
Confirmation gate that runs AFTER Layer1Scorer.

Role in the pipeline:
    Incoming packet
          ↓
    Layer1Scorer     ← AI scoring, Z-scores, Welford baseline
          ↓ anomaly found OR still learning
    Layer1Filter     ← hard rule confirmation (this file)
          ↓ confirmed suspicious
    Layer2Scanner    ← deep forensic scan
          ↓
    AI Model         ← final ALLOW / INVESTIGATE / BLOCK

Why this order:
    Layer1Scorer catches subtle statistical deviations from baseline.
    Layer1Filter then confirms with hard rules — especially for DDoS
    which the scorer may not catch well during its learning phase
    (100 DDoS packets look statistically similar to each other, so
    the scorer normalises them as baseline — the filter never does).

What Layer1Filter specifically catches:
    1. DDoS          — API call rate above safe threshold (> 50 calls)
    2. IP Spoofing   — private IPs appearing as external sources
    3. Exfiltration  — outbound/inbound ratio above threshold (> 8x)
    4. TTL abuse     — TTL outside valid OS ranges
    5. Port abuse    — suspicious destination ports (SSH from Lambda)
    6. Fragmentation — excessive packet fragments

DDoS-specific design:
    DDoS is the hardest attack for a statistical scorer to catch because:
    - Low duration (20-60ms)  → near-zero Z-score on duration
    - Low memory (40-80MB)    → near-zero Z-score on memory
    - The only anomaly is API call COUNT — which this filter hard-gates.
    api_calls_max = 50 is the definitive DDoS blocker.

Runs in < 1ms. No learning phase. No state. Pure rules.

Author: Backend Team
"""

import ipaddress
import time

# ── Thresholds ────────────────────────────────────────────────────────────────

TTL_MIN              = 30
TTL_MAX              = 128

PACKET_SIZE_MIN      = 20
PACKET_SIZE_MAX      = 65535

DURATION_MAX_MS      = 3000     # SARIMA adjusts this dynamically

API_CALLS_MAX        = 50       # PRIMARY DDoS GATE
                                 # DDoS: 60-150 calls, Normal: 2-15 calls

OUTBOUND_RATIO_MAX   = 8.0      # Data exfiltration gate

FRAGMENT_MAX         = 7        # Fragmentation attack gate

SUSPICIOUS_PORTS     = {
    22,    # SSH   — Lambda should never initiate SSH
    23,    # Telnet
    445,   # SMB
    1433,  # MSSQL direct
    3389,  # RDP
}

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
]


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


class Layer1Filter:
    """
    Hard rule confirmation gate — runs after Layer1Scorer.
    Specifically designed to catch DDoS and attacks the scorer
    cannot reliably catch during its learning phase.
    """

    def __init__(
        self,
        ttl_min:              int   = TTL_MIN,
        ttl_max:              int   = TTL_MAX,
        size_min:             int   = PACKET_SIZE_MIN,
        size_max:             int   = PACKET_SIZE_MAX,
        duration_max_ms:      float = DURATION_MAX_MS,
        api_calls_max:        int   = API_CALLS_MAX,
        outbound_ratio_max:   float = OUTBOUND_RATIO_MAX,
        fragment_max:         int   = FRAGMENT_MAX,
    ):
        self.ttl_min            = ttl_min
        self.ttl_max            = ttl_max
        self.size_min           = size_min
        self.size_max           = size_max
        self.duration_max       = duration_max_ms
        self.api_calls_max      = api_calls_max
        self.outbound_ratio_max = outbound_ratio_max
        self.fragment_max       = fragment_max

    def check(self, packet: dict) -> dict:
        """
        Run all hard rule checks on the packet.

        Returns:
            {
                "pass":       bool  — True = no hard violations
                "reason":     str
                "checks":     dict  — individual check results
                "violations": list  — human-readable failure reasons
                "values":     dict  — actual values checked
                "elapsed_us": int
            }
        """
        t0 = time.perf_counter()

        ttl        = packet.get("ttl", 64)
        size_in    = packet.get("packet_size_in", packet.get("packet_size", 512))
        size_out   = packet.get("packet_size_out", 0)
        duration   = packet.get("duration", 0)
        api_calls  = packet.get("num_api_calls", 0)
        frags      = packet.get("fragment_count", 0)
        dest_port  = packet.get("dest_port", 443)
        ip_address = packet.get("ip_address", "")
        ratio      = size_out / max(size_in, 1)

        checks     = {}
        violations = []

        # Check 1: TTL range
        checks["ttl_valid"] = self.ttl_min <= ttl <= self.ttl_max
        if not checks["ttl_valid"]:
            violations.append(
                f"TTL {ttl} outside valid range ({self.ttl_min}-{self.ttl_max})"
            )

        # Check 2: Packet size
        checks["size_valid"] = self.size_min <= size_in <= self.size_max
        if not checks["size_valid"]:
            violations.append(f"Packet size {size_in}B outside valid range")

        # Check 3: Duration (SARIMA adjusts threshold dynamically)
        checks["duration_ok"] = duration <= self.duration_max
        if not checks["duration_ok"]:
            violations.append(
                f"Duration {duration:.0f}ms exceeds {self.duration_max:.0f}ms"
            )

        # Check 4: API call rate — PRIMARY DDoS GATE
        # DDoS packets have 60-150 calls. Normal Lambda: 2-15 calls.
        # This single threshold definitively blocks all DDoS traffic.
        checks["api_calls_ok"] = api_calls <= self.api_calls_max
        if not checks["api_calls_ok"]:
            violations.append(
                f"API calls {api_calls} exceeds {self.api_calls_max} — DDoS detected"
            )

        # Check 5: Outbound ratio — data exfiltration gate
        checks["ratio_ok"] = ratio <= self.outbound_ratio_max
        if not checks["ratio_ok"]:
            violations.append(
                f"Outbound ratio {ratio:.1f}x exceeds {self.outbound_ratio_max}x — exfiltration"
            )

        # Check 6: Fragmentation attack gate
        checks["fragmentation_ok"] = frags <= self.fragment_max
        if not checks["fragmentation_ok"]:
            violations.append(
                f"Fragment count {frags} exceeds {self.fragment_max} — fragmentation attack"
            )

        # Check 7: Private IP as external source — IP spoofing gate
        if ip_address:
            checks["ip_valid"] = not _is_private_ip(ip_address)
            if not checks["ip_valid"]:
                violations.append(
                    f"Private IP {ip_address} as external source — IP spoofing"
                )
        else:
            checks["ip_valid"] = True

        # Check 8: Suspicious destination port
        checks["port_ok"] = dest_port not in SUSPICIOUS_PORTS
        if not checks["port_ok"]:
            violations.append(
                f"Suspicious port {dest_port} — C2 communication pattern"
            )

        passed     = all(checks.values())
        elapsed_us = round((time.perf_counter() - t0) * 1_000_000)

        if passed:
            reason = "All hard rule checks passed"
        else:
            failed = [k for k, v in checks.items() if not v]
            reason = f"Hard rule violations: {', '.join(failed)}"

        return {
            "pass":       passed,
            "reason":     reason,
            "checks":     checks,
            "violations": violations,
            "values": {
                "ttl":            ttl,
                "size_in":        size_in,
                "size_out":       size_out,
                "duration_ms":    duration,
                "api_calls":      api_calls,
                "outbound_ratio": round(ratio, 2),
                "fragment_count": frags,
                "dest_port":      dest_port,
                "ip_address":     ip_address,
            },
            "elapsed_us": elapsed_us,
        }

    def get_thresholds(self) -> dict:
        return {
            "ttl_min":            self.ttl_min,
            "ttl_max":            self.ttl_max,
            "size_min":           self.size_min,
            "size_max":           self.size_max,
            "duration_max_ms":    self.duration_max,
            "api_calls_max":      self.api_calls_max,
            "outbound_ratio_max": self.outbound_ratio_max,
            "fragment_max":       self.fragment_max,
        }