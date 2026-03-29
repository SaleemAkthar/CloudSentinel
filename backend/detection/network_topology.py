"""
Network Topology Analyzer — Cloud Sentinel Layer 2
====================================================
Analyses routing path, hop count, and transit providers
using TTL simulation ( in-memory).

Covers:
  - Routing path simulation from TTL
  - Hop count validation
  - Transit provider identification
  - Routing anomaly detection

Author: Backend Team
"""

import time
from typing import Dict, List, Optional


# ============================================================================
# TRANSIT PROVIDER DATABASE
# Maps ASN patterns to known transit / backbone providers
# ============================================================================

_TRANSIT_PROVIDERS = {
    # Tier 1 (global backbone — legitimate)
    "AS1":     {"name": "LVLT-1 CenturyLink",  "tier": 1, "risk": "low"},
    "AS174":   {"name": "Cogent",               "tier": 1, "risk": "low"},
    "AS209":   {"name": "CenturyLink",          "tier": 1, "risk": "low"},
    "AS286":   {"name": "KPN Netherlands",      "tier": 1, "risk": "low"},
    "AS701":   {"name": "Verizon",              "tier": 1, "risk": "low"},
    "AS1239":  {"name": "Sprint",               "tier": 1, "risk": "low"},
    "AS1273":  {"name": "Vodafone",             "tier": 1, "risk": "low"},
    "AS2914":  {"name": "NTT America",          "tier": 1, "risk": "low"},
    "AS3257":  {"name": "GTT Communications",   "tier": 1, "risk": "low"},
    "AS3320":  {"name": "Deutsche Telekom",     "tier": 1, "risk": "low"},
    "AS3356":  {"name": "Lumen / Level3",       "tier": 1, "risk": "low"},
    "AS5511":  {"name": "Orange",               "tier": 1, "risk": "low"},
    "AS6453":  {"name": "TATA Communications",  "tier": 1, "risk": "low"},
    "AS6461":  {"name": "Zayo Bandwidth",       "tier": 1, "risk": "low"},
    "AS6762":  {"name": "Telecom Italia",       "tier": 1, "risk": "low"},
    "AS7018":  {"name": "AT&T",                 "tier": 1, "risk": "low"},
    "AS12956": {"name": "Telefonica",           "tier": 1, "risk": "low"},

    # Cloud / CDN (legitimate but scrutinise Lambda-to-Lambda)
    "AS16509": {"name": "Amazon AWS",           "tier": 2, "risk": "low"},
    "AS15169": {"name": "Google Cloud",         "tier": 2, "risk": "low"},
    "AS8075":  {"name": "Microsoft Azure",      "tier": 2, "risk": "low"},
    "AS13335": {"name": "Cloudflare",           "tier": 2, "risk": "low"},
    "AS14061": {"name": "DigitalOcean",         "tier": 2, "risk": "medium"},
    "AS63949": {"name": "Linode / Akamai",      "tier": 2, "risk": "medium"},
    "AS20473": {"name": "Vultr",                "tier": 2, "risk": "medium"},
    "AS24940": {"name": "Hetzner",              "tier": 2, "risk": "medium"},

    # High-risk / bulletproof hosters
    "AS201281": {"name": "Tor Relay",           "tier": 3, "risk": "critical"},
    "AS9009":   {"name": "M247 (Bulletproof)",  "tier": 3, "risk": "high"},
    "AS35624":  {"name": "ALEXANDR-AS",         "tier": 3, "risk": "high"},
    "AS199524": {"name": "G-Core Abuse",        "tier": 3, "risk": "high"},
    "AS53667":  {"name": "FranTech",            "tier": 3, "risk": "high"},
    "AS60781":  {"name": "LeaseWeb Abuse",      "tier": 3, "risk": "high"},
    "AS202425": {"name": "IP Volume",           "tier": 3, "risk": "high"},

    # Regional ISPs (medium trust)
    "AS9329":  {"name": "SLT Sri Lanka",        "tier": 2, "risk": "low"},
    "AS4134":  {"name": "China Telecom",        "tier": 2, "risk": "high"},
    "AS4837":  {"name": "China Unicom",         "tier": 2, "risk": "high"},
    "AS8359":  {"name": "MTS Russia",           "tier": 2, "risk": "high"},
    "AS12389": {"name": "Rostelecom",           "tier": 2, "risk": "high"},
}

# Standard initial TTL values by OS
_OS_TTL_DEFAULTS = {
    64:  "Linux / macOS / Android",
    128: "Windows",
    255: "Cisco IOS / network devices",
    60:  "Solaris / AIX (older)",
    32:  "Windows 95 / NT (legacy)",
}

# Expected hop ranges by geographic region
_REGION_HOP_RANGES = {
    "LK": (5, 12),   # Sri Lanka (local hops)
    "IN": (8, 15),   # India
    "SG": (10, 18),  # Singapore
    "JP": (12, 20),  # Japan
    "CN": (12, 22),  # China
    "AU": (14, 22),  # Australia
    "DE": (15, 22),  # Germany
    "GB": (15, 22),  # UK
    "NL": (15, 22),  # Netherlands
    "US": (15, 25),  # USA
    "BR": (18, 28),  # Brazil
    "RU": (15, 25),  # Russia
    "ZA": (20, 30),  # South Africa
    "PR": (1, 5),    # Private
    "LO": (1, 2),    # Loopback
    "TOR": (15, 30), # Tor (many hops by design)
    "XX": (10, 30),  # Unknown
}

# Simulated hop labels for routing path reconstruction
_HOP_TEMPLATES = {
    "internal": [
        "lambda-internal.aws.com",
        "vpc-router.internal",
        "subnet-gw.internal",
    ],
    "aws_edge": [
        "edge.us-east-1.aws.com",
        "cloudfront-edge.aws.com",
        "api-gw.us-east-1.amazonaws.com",
    ],
    "tier1": [
        "core1.lumen.net",
        "ae-1.r00.nycmny01.us.bb.gin.ntt.net",
        "ae-2.r01.londen01.uk.bb.gin.ntt.net",
        "bundle-ether10.lon.tele2.net",
    ],
    "regional": [
        "ae1.pe1.fra.de.geant.net",
        "singapore-ix.tata.net",
        "sgp-b1-link.telia.net",
        "hkg-ct1.telia.net",
    ],
    "destination": [
        "server.destination.net",
        "host.endpoint.com",
        "target.datacenter.net",
    ],
}


# ============================================================================
# NETWORK TOPOLOGY ANALYZER
# ============================================================================

class NetworkTopologyAnalyzer:
    """
    Simulates and analyses the routing path using TTL and geo data.
    Fully in-memory — no live DNS or traceroute calls.
    """

    def analyze(self, packet: dict, ip_analysis: dict) -> dict:
        """
        Main entry point.

        Args:
            packet:      raw packet dict
            ip_analysis: output from IPAnalyzer.analyze()

        Returns:
            Full topology analysis dict
        """
        t0 = time.perf_counter()

        ttl        = packet.get("ttl", 64)
        geo        = ip_analysis.get("geolocation", {})
        asn_info   = ip_analysis.get("asn", {})

        hop_analysis  = self._analyze_hops(ttl, geo)
        routing_path  = self._simulate_routing_path(ttl, geo, asn_info)
        transit       = self._identify_transit(asn_info, geo)
        anomalies     = self._detect_routing_anomalies(ttl, geo, hop_analysis, transit)

        risk_score = self._calculate_topology_risk(hop_analysis, transit, anomalies)

        elapsed_us = round((time.perf_counter() - t0) * 1_000_000)

        return {
            "elapsed_us":    elapsed_us,
            "hop_analysis":  hop_analysis,
            "routing_path":  routing_path,
            "transit":       transit,
            "anomalies":     anomalies,
            "risk_score":    round(risk_score, 4),
        }

    # ── Hop Count Analysis ────────────────────────────────────────────────────

    def _analyze_hops(self, ttl: int, geo: dict) -> dict:
        """
        Infer hop count from TTL and validate against geographic expectation.

        Formula: hops = initial_TTL - observed_TTL
        """
        country = geo.get("country_code", "US")

        # Find nearest initial TTL
        nearest_initial = min(
            _OS_TTL_DEFAULTS.keys(),
            key=lambda t: abs(t - ttl) if t >= ttl else 9999,
        )
        if nearest_initial < ttl:
            nearest_initial = 64  # fallback

        inferred_hops = nearest_initial - ttl
        os_guess      = _OS_TTL_DEFAULTS.get(nearest_initial, "Unknown OS")

        expected_min, expected_max = _REGION_HOP_RANGES.get(country, (10, 25))

        hop_valid  = expected_min <= inferred_hops <= expected_max
        hop_delta  = 0
        flags      = []

        if not hop_valid:
            hop_delta = inferred_hops - expected_max if inferred_hops > expected_max else expected_min - inferred_hops
            if inferred_hops < expected_min:
                flags.append(
                    f"Hop count ({inferred_hops}) is lower than expected for "
                    f"{geo.get('country_name', country)} ({expected_min}–{expected_max}) "
                    "— possible source IP spoofing or VPN"
                )
            else:
                flags.append(
                    f"Hop count ({inferred_hops}) exceeds expected range for "
                    f"{geo.get('country_name', country)} ({expected_min}–{expected_max}) "
                    "— possible Tor or onion routing"
                )

        return {
            "observed_ttl":     ttl,
            "initial_ttl":      nearest_initial,
            "inferred_hops":    inferred_hops,
            "expected_min":     expected_min,
            "expected_max":     expected_max,
            "hop_count_valid":  hop_valid,
            "hop_delta":        hop_delta,
            "os_fingerprint":   os_guess,
            "flags":            flags,
        }

    # ── Routing Path Simulation ───────────────────────────────────────────────

    def _simulate_routing_path(self, ttl: int, geo: dict, asn_info: dict) -> List[dict]:
        """
        Reconstruct a plausible routing path from TTL and geo data.
        Returns ordered list of simulated hops.
        """
        country  = geo.get("country_code", "US")
        org      = asn_info.get("organisation", "Unknown")

        # Determine path segments based on geography
        path = []
        hop_num = 1

        # Hop 1-2: Lambda internal routing
        for label in _HOP_TEMPLATES["internal"][:2]:
            path.append({
                "hop":     hop_num,
                "host":    label,
                "type":    "internal",
                "latency": f"{hop_num * 0.5:.1f}ms",
                "risk":    "none",
            })
            hop_num += 1

        # Hop 3-4: AWS edge
        for label in _HOP_TEMPLATES["aws_edge"][:2]:
            path.append({
                "hop":     hop_num,
                "host":    label,
                "type":    "aws_edge",
                "latency": f"{hop_num * 1.2:.1f}ms",
                "risk":    "none",
            })
            hop_num += 1

        # Middle hops: Tier 1 or regional backbone
        if country in ("CN", "RU", "KP", "IR"):
            hops = _HOP_TEMPLATES["regional"]
            risk = "high"
        elif country in ("TOR", "XX"):
            hops = _HOP_TEMPLATES["tier1"] + _HOP_TEMPLATES["regional"]
            risk = "critical"
        else:
            hops = _HOP_TEMPLATES["tier1"]
            risk = "low"

        for label in hops[:3]:
            path.append({
                "hop":     hop_num,
                "host":    label,
                "type":    "backbone",
                "latency": f"{hop_num * 2.5:.1f}ms",
                "risk":    risk,
            })
            hop_num += 1

        # Last hop: destination
        path.append({
            "hop":     hop_num,
            "host":    f"{asn_info.get('organisation', 'destination').lower().replace(' ', '-')}.net",
            "type":    "destination",
            "latency": f"{hop_num * 3.0:.1f}ms",
            "risk":    "high" if asn_info.get("is_bad_asn") else "low",
        })

        return path

    # ── Transit Provider Identification ──────────────────────────────────────

    def _identify_transit(self, asn_info: dict, geo: dict) -> dict:
        """Identify and risk-rate the transit provider."""
        asn = asn_info.get("asn", "AS0")
        org = asn_info.get("organisation", "Unknown")

        provider = _TRANSIT_PROVIDERS.get(asn, {
            "name": org,
            "tier": 2,
            "risk": "medium" if geo.get("is_high_risk") else "low",
        })

        flags = []
        if provider["risk"] in ("high", "critical"):
            flags.append(f"Transit provider '{provider['name']}' is rated {provider['risk'].upper()} risk")
        if provider["tier"] == 3:
            flags.append("Bulletproof / high-risk hosting provider in routing path")

        return {
            "asn":          asn,
            "provider_name": provider["name"],
            "tier":         provider["tier"],
            "risk_level":   provider["risk"],
            "flags":        flags,
        }

    # ── Routing Anomaly Detection ─────────────────────────────────────────────

    def _detect_routing_anomalies(
        self, ttl: int, geo: dict, hop_analysis: dict, transit: dict
    ) -> dict:
        """Detect routing anomalies from hop and transit data."""
        anomalies  = []
        risk_score = 0.0

        # Anomaly 1: Hop count outside expected range
        if not hop_analysis["hop_count_valid"]:
            risk_score += 0.3
            anomalies.extend(hop_analysis["flags"])

        # Anomaly 2: High-risk transit
        if transit["risk_level"] in ("high", "critical"):
            risk_score += 0.4
            anomalies.extend(transit["flags"])

        # Anomaly 3: Too few hops for external traffic
        if hop_analysis["inferred_hops"] < 3 and geo.get("country_code") not in ("PR", "LO"):
            risk_score += 0.3
            anomalies.append(
                f"Only {hop_analysis['inferred_hops']} hops for external source — "
                "suggests spoofed or proxied traffic"
            )

        # Anomaly 4: TTL exactly at OS default (no hops at all)
        if ttl in _OS_TTL_DEFAULTS and hop_analysis["inferred_hops"] == 0:
            risk_score += 0.2
            anomalies.append("TTL equals OS default exactly — source may be on same network segment")

        # Anomaly 5: Tor routing detected
        if geo.get("country_code") == "TOR":
            risk_score += 0.5
            anomalies.append("Traffic routed through Tor network — source anonymised")

        return {
            "anomaly_count": len(anomalies),
            "anomalies":     anomalies,
            "risk_score":    round(min(risk_score, 1.0), 4),
        }

    # ── Topology Risk Score ───────────────────────────────────────────────────

    def _calculate_topology_risk(
        self, hop_analysis: dict, transit: dict, anomalies: dict
    ) -> float:
        """Combine topology signals into a single risk score."""
        transit_risk_map = {"low": 0.0, "medium": 0.2, "high": 0.6, "critical": 1.0}

        hop_risk     = 0.4 if not hop_analysis["hop_count_valid"] else 0.0
        transit_risk = transit_risk_map.get(transit["risk_level"], 0.2)
        anomaly_risk = anomalies["risk_score"]

        weights      = {"hop": 0.30, "transit": 0.40, "anomaly": 0.30}
        return min(
            hop_risk * weights["hop"]
            + transit_risk * weights["transit"]
            + anomaly_risk * weights["anomaly"],
            1.0,
        )