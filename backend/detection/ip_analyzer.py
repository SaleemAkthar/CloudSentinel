"""
IP Analyzer — Cloud Sentinel Layer 2
======================================
Performs deep IP analysis entirely in-memory. No external HTTP calls.
All lookups use built-in tables loaded at import time (~0ms per lookup).

Covers:
  - IP validation
  - Geolocation (country, region, lat/lon)
  - ASN / organisation lookup
  - Reverse DNS simulation
  - Reputation scoring with 5+ checks
  - Spoofing detection (5+ checks)
  - Historical IP tracking (in-memory session store)

Author: Backend Team
"""

import ipaddress
import math
import time
import hashlib
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from collections import defaultdict


# ============================================================================
# SECTION 1: BUILT-IN GEO + ASN DATABASE
# Each entry: (cidr, country_code, country_name, region, lat, lon, asn, org)
# Covers major cloud providers, known bad actors, and geographic regions.
# ============================================================================

_IP_RANGES: List[Tuple] = [
    # ── Known Malicious / Tor / Botnet ────────────────────────────────────────
    ("185.220.0.0/16",   "TOR", "Tor Network",        "Tor",        0.0,    0.0,   "AS201281", "Tor Exit Nodes"),
    ("185.107.80.0/22",  "XX",  "Known Malicious",    "Botnet",    51.5,    0.0,   "AS9009",   "M247 Botnet Range"),
    ("45.142.0.0/16",    "XX",  "Known Malicious",    "Botnet",    52.3,   13.4,   "AS35624",  "ALEXANDR-AS Botnet"),
    ("194.165.0.0/16",   "XX",  "Known Malicious",    "Botnet",    55.7,   37.6,   "AS199524", "G-Core Abuse"),
    ("91.108.4.0/22",    "NL",  "Netherlands",        "Amsterdam", 52.3,    4.9,   "AS62041",  "Telegram"),
    ("198.98.0.0/16",    "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS53667",  "FranTech (Bulletproof)"),
    ("80.82.77.0/24",    "NL",  "Netherlands",        "Amsterdam", 52.3,    4.9,   "AS60781",  "LeaseWeb Abuse"),
    ("89.248.160.0/19",  "NL",  "Netherlands",        "Amsterdam", 52.3,    4.9,   "AS202425", "IP Volume Botnet"),

    # ── AWS ───────────────────────────────────────────────────────────────────
    ("3.0.0.0/8",        "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS16509",  "Amazon AWS"),
    ("13.0.0.0/8",       "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS16509",  "Amazon AWS"),
    ("18.0.0.0/8",       "US",  "United States",      "Oregon",    45.5, -122.6,   "AS16509",  "Amazon AWS"),
    ("34.0.0.0/8",       "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS15169",  "Google Cloud"),
    ("35.0.0.0/8",       "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS15169",  "Google Cloud"),
    ("52.0.0.0/8",       "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS16509",  "Amazon AWS"),
    ("54.0.0.0/8",       "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS16509",  "Amazon AWS"),

    # ── Azure ─────────────────────────────────────────────────────────────────
    ("20.0.0.0/8",       "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS8075",   "Microsoft Azure"),
    ("40.0.0.0/8",       "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS8075",   "Microsoft Azure"),

    # ── Cloudflare ────────────────────────────────────────────────────────────
    ("1.1.1.0/24",       "AU",  "Australia",          "Sydney",   -33.8,  151.2,   "AS13335",  "Cloudflare DNS"),
    ("104.16.0.0/12",    "US",  "United States",      "California", 37.4, -122.0,  "AS13335",  "Cloudflare"),

    # ── DigitalOcean ──────────────────────────────────────────────────────────
    ("167.99.0.0/16",    "US",  "United States",      "New York",  40.7,  -74.0,   "AS14061",  "DigitalOcean"),
    ("159.65.0.0/16",    "US",  "United States",      "New York",  40.7,  -74.0,   "AS14061",  "DigitalOcean"),
    ("138.68.0.0/16",    "US",  "United States",      "New York",  40.7,  -74.0,   "AS14061",  "DigitalOcean"),

    # ── Linode / Akamai ───────────────────────────────────────────────────────
    ("45.33.0.0/16",     "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS63949",  "Linode"),
    ("45.56.0.0/16",     "US",  "United States",      "Virginia",  38.9,  -77.0,   "AS63949",  "Linode"),

    # ── Geographic blocks ─────────────────────────────────────────────────────
    ("5.0.0.0/8",        "RU",  "Russia",             "Moscow",    55.7,   37.6,   "AS8359",   "MTS Russia"),
    ("31.0.0.0/8",       "RU",  "Russia",             "Moscow",    55.7,   37.6,   "AS8359",   "MTS Russia"),
    ("37.0.0.0/8",       "DE",  "Germany",            "Frankfurt", 50.1,    8.7,   "AS3320",   "Deutsche Telekom"),
    ("46.0.0.0/8",       "GB",  "United Kingdom",     "London",    51.5,   -0.1,   "AS2856",   "BT"),
    ("58.0.0.0/8",       "CN",  "China",              "Beijing",   39.9,  116.4,   "AS4134",   "China Telecom"),
    ("59.0.0.0/8",       "CN",  "China",              "Beijing",   39.9,  116.4,   "AS4134",   "China Telecom"),
    ("60.0.0.0/8",       "CN",  "China",              "Shanghai",  31.2,  121.5,   "AS4134",   "China Telecom"),
    ("61.0.0.0/8",       "CN",  "China",              "Shanghai",  31.2,  121.5,   "AS4134",   "China Telecom"),
    ("101.0.0.0/8",      "CN",  "China",              "Beijing",   39.9,  116.4,   "AS4837",   "China Unicom"),
    ("103.0.0.0/8",      "IN",  "India",              "Mumbai",    19.1,   72.9,   "AS45609",  "BHARTI Airtel"),
    ("110.0.0.0/8",      "CN",  "China",              "Guangzhou", 23.1,  113.3,   "AS4134",   "China Telecom"),
    ("111.0.0.0/8",      "CN",  "China",              "Guangzhou", 23.1,  113.3,   "AS4134",   "China Telecom"),
    ("112.0.0.0/8",      "CN",  "China",              "Beijing",   39.9,  116.4,   "AS4134",   "China Telecom"),
    ("175.0.0.0/8",      "CN",  "China",              "Beijing",   39.9,  116.4,   "AS4837",   "China Unicom"),
    ("176.0.0.0/8",      "RU",  "Russia",             "Moscow",    55.7,   37.6,   "AS8359",   "MTS Russia"),
    ("178.0.0.0/8",      "RU",  "Russia",             "Moscow",    55.7,   37.6,   "AS12389",  "Rostelecom"),
    ("185.0.0.0/8",      "DE",  "Germany",            "Frankfurt", 50.1,    8.7,   "AS3320",   "Deutsche Telekom"),
    ("188.0.0.0/8",      "DE",  "Germany",            "Frankfurt", 50.1,    8.7,   "AS3320",   "Deutsche Telekom"),
    ("193.0.0.0/8",      "NL",  "Netherlands",        "Amsterdam", 52.3,    4.9,   "AS286",    "KPN Netherlands"),
    ("194.0.0.0/8",      "GB",  "United Kingdom",     "London",    51.5,   -0.1,   "AS2856",   "BT"),
    ("195.0.0.0/8",      "DE",  "Germany",            "Frankfurt", 50.1,    8.7,   "AS3320",   "Deutsche Telekom"),
    ("197.0.0.0/8",      "ZA",  "South Africa",       "Cape Town", -33.9,  18.4,   "AS30844",  "Liquid Telecom"),
    ("200.0.0.0/8",      "BR",  "Brazil",             "Sao Paulo", -23.5, -46.6,   "AS18881",  "Global Village Telecom"),
    ("201.0.0.0/8",      "BR",  "Brazil",             "Sao Paulo", -23.5, -46.6,   "AS18881",  "Global Village Telecom"),
    ("202.0.0.0/8",      "JP",  "Japan",              "Tokyo",     35.7,  139.7,   "AS2516",   "KDDI Japan"),
    ("210.0.0.0/8",      "JP",  "Japan",              "Tokyo",     35.7,  139.7,   "AS2516",   "KDDI Japan"),
    ("211.0.0.0/8",      "KR",  "South Korea",        "Seoul",     37.6,  126.9,   "AS9644",   "SK Telecom"),
    ("218.0.0.0/8",      "CN",  "China",              "Beijing",   39.9,  116.4,   "AS4134",   "China Telecom"),
    ("220.0.0.0/8",      "AU",  "Australia",          "Sydney",   -33.8,  151.2,   "AS1221",   "Telstra"),
    ("221.0.0.0/8",      "KR",  "South Korea",        "Seoul",     37.6,  126.9,   "AS9644",   "SK Telecom"),

    # ── Sri Lanka ─────────────────────────────────────────────────────────────
    ("112.134.0.0/16",   "LK",  "Sri Lanka",          "Colombo",    6.9,   79.9,   "AS9329",   "SLT Sri Lanka"),
    ("117.239.0.0/16",   "LK",  "Sri Lanka",          "Colombo",    6.9,   79.9,   "AS9329",   "SLT Sri Lanka"),
    ("203.143.0.0/16",   "LK",  "Sri Lanka",          "Colombo",    6.9,   79.9",  "AS9329",   "Dialog Sri Lanka"),

    # ── Private / RFC1918 ─────────────────────────────────────────────────────
    ("10.0.0.0/8",       "PR",  "Private Network",    "Internal",   0.0,    0.0,   "AS0",      "RFC1918 Private"),
    ("172.16.0.0/12",    "PR",  "Private Network",    "Internal",   0.0,    0.0,   "AS0",      "RFC1918 Private"),
    ("192.168.0.0/16",   "PR",  "Private Network",    "Internal",   0.0,    0.0,   "AS0",      "RFC1918 Private"),
    ("127.0.0.0/8",      "LO",  "Loopback",           "Localhost",  0.0,    0.0,   "AS0",      "Loopback"),
    ("169.254.0.0/16",   "LL",  "Link-Local",         "Link-Local", 0.0,    0.0,   "AS0",      "Link-Local"),
    ("100.64.0.0/10",    "PR",  "Shared Address",     "Internal",   0.0,    0.0,   "AS0",      "RFC6598 CGN"),
]

# Pre-compile networks for fast lookup
_COMPILED_RANGES = []
for entry in _IP_RANGES:
    try:
        net = ipaddress.ip_network(entry[0], strict=False)
        _COMPILED_RANGES.append((net, entry[1:]))
    except ValueError:
        pass


# ── Known bad ASNs ────────────────────────────────────────────────────────────
_BAD_ASNS = {
    "AS201281", "AS9009", "AS35624", "AS199524",
    "AS53667",  "AS60781", "AS202425",
}

# ── High-risk country codes ───────────────────────────────────────────────────
_HIGH_RISK_COUNTRIES = {"CN", "RU", "KP", "IR", "SY", "CU", "SD", "XX", "TOR"}

# ── Hosting / datacenter ASN prefixes (not inherently bad, but worth flagging) ─
_HOSTING_ORGS = {
    "Amazon AWS", "Google Cloud", "Microsoft Azure",
    "DigitalOcean", "Linode", "Vultr", "Hetzner",
    "OVH", "LeaseWeb", "FranTech",
}

# ── In-memory historical IP store ─────────────────────────────────────────────
# { ip_address: { "first_seen": ts, "last_seen": ts, "hit_count": int,
#                 "countries": set, "flags": list } }
_ip_history: Dict[str, dict] = defaultdict(lambda: {
    "first_seen":  None,
    "last_seen":   None,
    "hit_count":   0,
    "countries":   set(),
    "flags":       [],
    "risk_scores": [],
})


# ============================================================================
# SECTION 2: IP ANALYZER CLASS
# ============================================================================

class IPAnalyzer:
    """
    Full IP analysis engine. Instantiate once, call analyze() per request.
    All methods are pure in-memory — zero I/O after __init__.
    """

    def analyze(self, ip_str: str, ttl: int = 64) -> dict:
        """
        Main entry point. Returns complete IP analysis in < 1ms.

        Args:
            ip_str: IP address string
            ttl:    TTL value from the packet

        Returns:
            Full analysis dict
        """
        t0 = time.perf_counter()

        validation  = self._validate(ip_str)
        if not validation["valid"]:
            return {"valid": False, "ip": ip_str, "error": validation["error"]}

        geo         = self._geolocate(ip_str)
        asn         = self._asn_lookup(ip_str, geo)
        rdns        = self._reverse_dns(ip_str, geo)
        reputation  = self._reputation(ip_str, geo, asn)
        spoofing    = self._spoofing_detection(ip_str, ttl, geo, asn)
        history     = self._update_history(ip_str, geo, reputation["score"])

        elapsed_us = round((time.perf_counter() - t0) * 1_000_000)

        return {
            "ip":           ip_str,
            "valid":        True,
            "elapsed_us":   elapsed_us,
            "validation":   validation,
            "geolocation":  geo,
            "asn":          asn,
            "reverse_dns":  rdns,
            "reputation":   reputation,
            "spoofing":     spoofing,
            "history":      history,
        }

    # ── Validation ────────────────────────────────────────────────────────────

    def _validate(self, ip_str: str) -> dict:
        """Validate IP address format and classify type."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError as e:
            return {"valid": False, "error": str(e)}

        return {
            "valid":        True,
            "version":      f"IPv{ip_obj.version}",
            "is_private":   ip_obj.is_private,
            "is_loopback":  ip_obj.is_loopback,
            "is_multicast": ip_obj.is_multicast,
            "is_reserved":  ip_obj.is_reserved,
            "is_global":    ip_obj.is_global,
            "type":         self._classify_type(ip_obj),
        }

    def _classify_type(self, ip_obj) -> str:
        if ip_obj.is_loopback:  return "loopback"
        if ip_obj.is_private:   return "private"
        if ip_obj.is_multicast: return "multicast"
        if ip_obj.is_reserved:  return "reserved"
        return "public"

    # ── Geolocation ───────────────────────────────────────────────────────────

    def _geolocate(self, ip_str: str) -> dict:
        """Look up geolocation from built-in range table."""
        match = self._find_range(ip_str)
        if match:
            _, country_code, country_name, region, lat, lon, _, _ = match
            return {
                "country_code": country_code,
                "country_name": country_name,
                "region":       region,
                "latitude":     lat,
                "longitude":    lon,
                "is_high_risk": country_code in _HIGH_RISK_COUNTRIES,
            }
        # Default fallback for unrecognised public IPs
        return {
            "country_code": "UN",
            "country_name": "Unknown",
            "region":       "Unknown",
            "latitude":     0.0,
            "longitude":    0.0,
            "is_high_risk": False,
        }

    # ── ASN Lookup ────────────────────────────────────────────────────────────

    def _asn_lookup(self, ip_str: str, geo: dict) -> dict:
        """Return ASN and organisation from built-in table."""
        match = self._find_range(ip_str)
        if match:
            _, _, _, _, _, _, asn, org = match
            return {
                "asn":          asn,
                "organisation": org,
                "is_hosting":   org in _HOSTING_ORGS,
                "is_bad_asn":   asn in _BAD_ASNS,
            }
        return {
            "asn":          "AS0",
            "organisation": "Unknown",
            "is_hosting":   False,
            "is_bad_asn":   False,
        }

    # ── Reverse DNS ───────────────────────────────────────────────────────────

    def _reverse_dns(self, ip_str: str, geo: dict) -> dict:
        """
        Simulate reverse DNS from IP characteristics.
        Real rDNS would require a DNS lookup (adds latency) — we infer instead.
        """
        parts = ip_str.split(".")
        country = geo.get("country_code", "un").lower()
        org     = self._find_range(ip_str)

        if org:
            org_name = org[7].lower().replace(" ", "-").replace("_", "-")
        else:
            org_name  = "unknown-isp"

        # Build a plausible PTR record
        if geo.get("country_code") in ("PR", "LO"):
            ptr = f"internal.local"
        else:
            ptr = f"{parts[-1]}.{parts[-2]}.{org_name}.{country}"

        return {
            "ptr_record":    ptr,
            "has_rdns":      geo.get("country_code") not in ("XX", "TOR"),
            "rdns_mismatch": geo.get("country_code") in _HIGH_RISK_COUNTRIES,
        }

    # ── Reputation ────────────────────────────────────────────────────────────

    def _reputation(self, ip_str: str, geo: dict, asn: dict) -> dict:
        """
        Multi-check reputation scoring. Score 0.0 (clean) → 1.0 (malicious).

        Checks:
          1. Country risk
          2. ASN reputation
          3. Hosting provider flag
          4. Known malicious prefix
          5. Session abuse history
        """
        checks  = {}
        score   = 0.0
        flags   = []

        # Check 1: Country risk
        if geo.get("is_high_risk"):
            checks["country_risk"] = True
            score += 0.25
            flags.append(f"High-risk country: {geo.get('country_name')}")
        else:
            checks["country_risk"] = False

        # Check 2: Bad ASN
        if asn.get("is_bad_asn"):
            checks["bad_asn"] = True
            score += 0.40
            flags.append(f"Known malicious ASN: {asn.get('asn')} ({asn.get('organisation')})")
        else:
            checks["bad_asn"] = False

        # Check 3: Hosting provider (elevated risk if unexpected)
        if asn.get("is_hosting"):
            checks["hosting_provider"] = True
            score += 0.10
            flags.append(f"Traffic from hosting provider: {asn.get('organisation')}")
        else:
            checks["hosting_provider"] = False

        # Check 4: Known malicious prefix
        known_bad = any(
            ip_str.startswith(pfx)
            for pfx in ["185.220.", "45.142.", "194.165.", "198.98.", "89.248."]
        )
        if known_bad:
            checks["known_bad_prefix"] = True
            score += 0.35
            flags.append("IP matches known malicious prefix list")
        else:
            checks["known_bad_prefix"] = False

        # Check 5: Session history abuse
        history = _ip_history.get(ip_str)
        if history and history["hit_count"] > 50:
            checks["session_abuse"] = True
            score += 0.15
            flags.append(f"High request frequency from this IP: {history['hit_count']} hits")
        else:
            checks["session_abuse"] = False

        score = min(score, 1.0)
        label = "MALICIOUS" if score >= 0.7 else "SUSPICIOUS" if score >= 0.4 else "CLEAN"

        return {
            "score":  round(score, 4),
            "label":  label,
            "flags":  flags,
            "checks": checks,
        }

    # ── Spoofing Detection ────────────────────────────────────────────────────

    def _spoofing_detection(self, ip_str: str, ttl: int, geo: dict, asn: dict) -> dict:
        """
        5+ checks for IP spoofing.

        Checks:
          1. TTL plausibility vs expected OS default
          2. TTL vs geographic hop estimate
          3. Private IP appearing as source on public traffic
          4. Reserved / special IP ranges
          5. ASN / country mismatch with TTL fingerprint
          6. Impossible TTL (0 or > 255)
        """
        indicators = []
        checks     = {}

        # Check 1: TTL plausibility (common defaults: 64 Linux, 128 Windows, 255 Cisco)
        expected_ttls = [64, 128, 255]
        min_dist = min(abs(ttl - e) for e in expected_ttls)
        if min_dist > 20:
            checks["ttl_plausibility"] = True
            indicators.append(f"TTL {ttl} is far from any standard OS default (64/128/255)")
        else:
            checks["ttl_plausibility"] = False

        # Check 2: TTL vs geo hop estimate
        geo_hops = self._estimate_geo_hops(geo)
        nearest_default = min(expected_ttls, key=lambda e: abs(ttl - e) if e >= ttl else 999)
        inferred_hops   = nearest_default - ttl
        if abs(inferred_hops - geo_hops) > 15:
            checks["ttl_geo_mismatch"] = True
            indicators.append(
                f"Inferred hops ({inferred_hops}) inconsistent with "
                f"geographic distance estimate ({geo_hops} hops)"
            )
        else:
            checks["ttl_geo_mismatch"] = False

        # Check 3: Private IP on public interface
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private and geo.get("country_code") not in ("PR", "LO"):
                checks["private_on_public"] = True
                indicators.append("Private IP range appearing as public traffic source")
            else:
                checks["private_on_public"] = False
        except ValueError:
            checks["private_on_public"] = False

        # Check 4: Reserved / special ranges
        reserved = geo.get("country_code") in ("LO", "LL")
        if reserved:
            checks["reserved_range"] = True
            indicators.append("IP is in a reserved special-purpose range")
        else:
            checks["reserved_range"] = False

        # Check 5: ASN / country fingerprint mismatch
        if asn.get("is_bad_asn") and not geo.get("is_high_risk"):
            checks["asn_geo_mismatch"] = True
            indicators.append(
                f"Bad ASN ({asn.get('asn')}) from apparently low-risk country"
            )
        else:
            checks["asn_geo_mismatch"] = False

        # Check 6: Impossible TTL
        if ttl <= 0 or ttl > 255:
            checks["impossible_ttl"] = True
            indicators.append(f"TTL value {ttl} is outside valid range (1-255)")
        else:
            checks["impossible_ttl"] = False

        spoofing_score = round(
            sum(1 for v in checks.values() if v) / len(checks), 4
        )
        is_spoofed = spoofing_score >= 0.4

        return {
            "is_likely_spoofed": is_spoofed,
            "spoofing_score":    spoofing_score,
            "indicators":        indicators,
            "checks":            checks,
            "inferred_hops":     max(0, nearest_default - ttl),
            "geo_hop_estimate":  geo_hops,
        }

    def _estimate_geo_hops(self, geo: dict) -> int:
        """Estimate expected hop count based on geographic distance."""
        # Rough hop estimates by region
        region_hops = {
            "LK": 8,  "IN": 10, "SG": 12, "JP": 14, "CN": 15,
            "AU": 16, "DE": 18, "GB": 18, "NL": 18, "FR": 18,
            "US": 20, "CA": 20, "BR": 22, "RU": 20, "ZA": 24,
            "PR": 2,  "LO": 1,
        }
        return region_hops.get(geo.get("country_code", "US"), 20)

    # ── Historical Tracking ───────────────────────────────────────────────────

    def _update_history(self, ip_str: str, geo: dict, risk_score: float) -> dict:
        """Update and return in-memory history for this IP."""
        now = datetime.utcnow().isoformat() + "Z"
        rec = _ip_history[ip_str]

        if rec["first_seen"] is None:
            rec["first_seen"] = now
        rec["last_seen"]  = now
        rec["hit_count"] += 1
        rec["countries"].add(geo.get("country_code", "UN"))
        rec["risk_scores"].append(risk_score)

        # Keep only last 100 scores
        if len(rec["risk_scores"]) > 100:
            rec["risk_scores"] = rec["risk_scores"][-100:]

        avg_risk = sum(rec["risk_scores"]) / len(rec["risk_scores"])

        return {
            "first_seen":   rec["first_seen"],
            "last_seen":    rec["last_seen"],
            "hit_count":    rec["hit_count"],
            "unique_countries": list(rec["countries"]),
            "avg_risk_score":   round(avg_risk, 4),
            "is_repeat_offender": rec["hit_count"] > 10 and avg_risk > 0.5,
        }

    # ── Helper: range lookup ──────────────────────────────────────────────────

    def _find_range(self, ip_str: str):
        """Return the best-matching (most specific) range entry for an IP."""
        try:
            ip_obj = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return None

        best_match  = None
        best_prefix = -1

        for net, data in _COMPILED_RANGES:
            if ip_obj in net:
                pl = net.prefixlen
                if pl > best_prefix:
                    best_prefix = pl
                    best_match  = (str(net),) + data

        return best_match