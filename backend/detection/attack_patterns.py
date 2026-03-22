"""
Attack Pattern Matcher — Cloud Sentinel Layer 2
Matches observed Lambda execution behaviour against known attack signatures.

Patterns (~200 lines each section):
  1. DDoS
  2. IP Spoofing
  3. SQL Injection
  4. Crypto Mining
  5. Data Exfiltration
  6. Memory Attack

Each pattern returns:
  { "matched": bool, "confidence": float, "indicators": list, "details": dict }

All in-memory. No I/O. Target: < 1ms per full match run.

Author: Backend Team
"""

import math
import time
from typing import Dict, List, Tuple



# BASE PATTERN CLASS

class AttackPattern:
    """Base class for all attack patterns."""

    name:        str = "Unknown"
    attack_type: str = "unknown"
    description: str = ""

    def match(self, packet: dict, ip_analysis: dict, packet_analysis: dict) -> dict:
        raise NotImplementedError

    def _result(
        self,
        matched: bool,
        confidence: float,
        indicators: List[str],
        details: dict,
    ) -> dict:
        return {
            "attack_type":  self.attack_type,
            "name":         self.name,
            "matched":      matched,
            "confidence":   round(min(confidence, 1.0), 4),
            "indicators":   indicators,
            "details":      details,
        }


# PATTERN 1: DDoS

class DDoSPattern(AttackPattern):
    """
    Distributed Denial of Service detection.

    Lambda DDoS signals:
      - High API call rate sustained over many invocations
      - Low unique destination count (hitting one target repeatedly)
      - High fragmentation (amplification attacks)
      - Very short execution time with high call volume (ping flood)
      - IP reputation: known botnet or Tor
      - Memory near zero (lightweight flood packets)
    """

    name        = "DDoS Attack"
    attack_type = "ddos"
    description = "Distributed denial-of-service pattern detected in Lambda execution"

    def match(self, packet: dict, ip_analysis: dict, packet_analysis: dict) -> dict:
        indicators = []
        signal_scores = {}

        api_calls   = packet.get("num_api_calls", 0)
        duration    = packet.get("duration", 0)
        unique_dest = packet.get("unique_destinations", 1)
        memory      = packet.get("memory_used", 0)
        frag_count  = packet_analysis.get("fragmentation", {}).get("effective_fragments", 0)
        ip_rep      = ip_analysis.get("reputation", {})
        exfil_score = packet_analysis.get("exfiltration", {}).get("exfiltration_score", 0)

        # Signal 1: High call rate
        calls_per_sec = api_calls / max(duration / 1000, 0.001)
        if calls_per_sec > 100:
            signal_scores["high_call_rate"] = 1.0
            indicators.append(f"Extremely high API call rate: {calls_per_sec:.1f}/s")
        elif calls_per_sec > 50:
            signal_scores["high_call_rate"] = 0.7
            indicators.append(f"High API call rate: {calls_per_sec:.1f}/s")
        elif calls_per_sec > 20:
            signal_scores["high_call_rate"] = 0.4
        else:
            signal_scores["high_call_rate"] = 0.0

        # Signal 2: Single target (low destination diversity)
        if api_calls > 20 and unique_dest == 1:
            signal_scores["single_target"] = 0.8
            indicators.append(f"All {api_calls} API calls targeting a single destination")
        elif unique_dest <= 2 and api_calls > 10:
            signal_scores["single_target"] = 0.5
        else:
            signal_scores["single_target"] = 0.0

        # Signal 3: Amplification via fragmentation
        if frag_count >= 10:
            signal_scores["fragmentation_amp"] = 0.9
            indicators.append(f"High fragment count ({frag_count}) — amplification attack pattern")
        elif frag_count >= 5:
            signal_scores["fragmentation_amp"] = 0.5
        else:
            signal_scores["fragmentation_amp"] = 0.0

        # Signal 4: Short execution + high volume (ping flood simulation)
        if duration < 50 and api_calls > 30:
            signal_scores["ping_flood"] = 0.9
            indicators.append(f"Ping flood pattern: {api_calls} calls in {duration}ms")
        elif duration < 100 and api_calls > 15:
            signal_scores["ping_flood"] = 0.5
        else:
            signal_scores["ping_flood"] = 0.0

        # Signal 5: Botnet IP
        if ip_rep.get("label") == "MALICIOUS":
            signal_scores["botnet_ip"] = 0.8
            indicators.append(f"Source IP flagged as malicious: {ip_rep.get('flags', [])}")
        elif ip_rep.get("label") == "SUSPICIOUS":
            signal_scores["botnet_ip"] = 0.4
        else:
            signal_scores["botnet_ip"] = 0.0

        # Signal 6: Lightweight payload (DDoS uses minimal data)
        size_out = packet.get("packet_size_out", 0)
        if memory < 64 and api_calls > 20 and size_out < 100:
            signal_scores["lightweight_flood"] = 0.7
            indicators.append("Lightweight payload with high call volume — resource exhaustion attempt")
        else:
            signal_scores["lightweight_flood"] = 0.0

        weights = {
            "high_call_rate":    0.30,
            "single_target":     0.20,
            "fragmentation_amp": 0.20,
            "ping_flood":        0.15,
            "botnet_ip":         0.10,
            "lightweight_flood": 0.05,
        }

        confidence = sum(signal_scores.get(k, 0) * w for k, w in weights.items())
        matched    = confidence >= 0.40

        return self._result(matched, confidence, indicators, {
            "calls_per_second":    round(calls_per_sec, 2),
            "unique_destinations": unique_dest,
            "fragment_count":      frag_count,
            "signal_scores":       {k: round(v, 4) for k, v in signal_scores.items()},
        })



# PATTERN 2: IP Spoofing


class SpoofingPattern(AttackPattern):
    """
    IP Spoofing detection.

    Signals:
      - TTL inconsistency with geographic distance
      - Private IP on public interface
      - ASN/country mismatch
      - Impossible TTL values
      - Reverse DNS mismatch
      - Repeated source IP with changing behaviour
    """

    name        = "IP Spoofing"
    attack_type = "ip_spoofing"
    description = "IP spoofing indicators detected in packet header analysis"

    def match(self, packet: dict, ip_analysis: dict, packet_analysis: dict) -> dict:
        indicators = []
        signal_scores = {}

        spoofing    = ip_analysis.get("spoofing", {})
        geo         = ip_analysis.get("geolocation", {})
        asn         = ip_analysis.get("asn", {})
        rdns        = ip_analysis.get("reverse_dns", {})
        history     = ip_analysis.get("history", {})
        ttl         = packet.get("ttl", 64)

        # Signal 1: Use spoofing checks from IPAnalyzer
        spoof_score = spoofing.get("spoofing_score", 0)
        if spoof_score >= 0.6:
            signal_scores["header_spoofing"] = 1.0
            indicators.extend(spoofing.get("indicators", []))
        elif spoof_score >= 0.3:
            signal_scores["header_spoofing"] = 0.6
            indicators.extend(spoofing.get("indicators", []))
        else:
            signal_scores["header_spoofing"] = spoof_score

        # Signal 2: TTL geo mismatch
        if spoofing.get("checks", {}).get("ttl_geo_mismatch"):
            signal_scores["ttl_geo_mismatch"] = 0.8
            indicators.append(
                f"TTL {ttl} inconsistent with source location "
                f"({geo.get('country_name', 'Unknown')})"
            )
        else:
            signal_scores["ttl_geo_mismatch"] = 0.0

        # Signal 3: rDNS mismatch
        if rdns.get("rdns_mismatch"):
            signal_scores["rdns_mismatch"] = 0.6
            indicators.append(f"Reverse DNS mismatch for IP from {geo.get('country_name')}")
        else:
            signal_scores["rdns_mismatch"] = 0.0

        # Signal 4: Repeat offender with changing country
        countries = history.get("unique_countries", [])
        if len(countries) > 3:
            signal_scores["country_hopping"] = 0.7
            indicators.append(
                f"IP appears from {len(countries)} different countries — possible proxy/spoofing"
            )
        else:
            signal_scores["country_hopping"] = 0.0

        # Signal 5: ASN mismatch with geo
        if asn.get("is_bad_asn") and not geo.get("is_high_risk"):
            signal_scores["asn_geo_mismatch"] = 0.5
            indicators.append(f"Bad ASN in seemingly safe country")
        else:
            signal_scores["asn_geo_mismatch"] = 0.0

        weights = {
            "header_spoofing":  0.40,
            "ttl_geo_mismatch": 0.25,
            "rdns_mismatch":    0.15,
            "country_hopping":  0.12,
            "asn_geo_mismatch": 0.08,
        }

        confidence = sum(signal_scores.get(k, 0) * w for k, w in weights.items())
        matched    = confidence >= 0.35

        return self._result(matched, confidence, indicators, {
            "ttl":              ttl,
            "inferred_hops":    spoofing.get("inferred_hops", 0),
            "geo_hop_estimate": spoofing.get("geo_hop_estimate", 0),
            "countries_seen":   countries,
            "signal_scores":    {k: round(v, 4) for k, v in signal_scores.items()},
        })



# PATTERN 3: SQL Injection

class SQLInjectionPattern(AttackPattern):
    """
    SQL Injection detection (behavioural, no raw payload inspection).

    Lambda SQL injection signals:
      - Abnormally high DB query count
      - Query errors spiking (failed injections)
      - Execution time anomalies (time-based blind SQLi)
      - High memory with many DB operations (data dumping)
      - Low API calls but high errors (error-based SQLi)
      - Unusual execution duration pattern
    """

    name        = "SQL Injection"
    attack_type = "sql_injection"
    description = "SQL injection behavioural pattern detected"

    def match(self, packet: dict, ip_analysis: dict, packet_analysis: dict) -> dict:
        indicators = []
        signal_scores = {}

        duration    = packet.get("duration", 0)
        memory      = packet.get("memory_used", 0)
        api_calls   = packet.get("num_api_calls", 0)
        error_count = packet.get("error_count", 0)
        db_queries  = packet.get("db_queries", 0)
        # Infer DB activity from API calls and errors
        inferred_db = db_queries if db_queries > 0 else max(0, api_calls - 2)

        # Signal 1: High DB query count
        if inferred_db > 50:
            signal_scores["high_db_queries"] = 1.0
            indicators.append(f"Extremely high inferred DB query count ({inferred_db})")
        elif inferred_db > 20:
            signal_scores["high_db_queries"] = 0.7
            indicators.append(f"Elevated DB query volume ({inferred_db} queries)")
        elif inferred_db > 10:
            signal_scores["high_db_queries"] = 0.4
        else:
            signal_scores["high_db_queries"] = 0.0

        # Signal 2: Error spike (failed injections hitting DB constraints)
        if error_count > 5 and inferred_db > 5:
            signal_scores["error_spike"] = 0.9
            indicators.append(
                f"High error rate ({error_count} errors) with active DB — "
                "possible error-based SQLi"
            )
        elif error_count > 2:
            signal_scores["error_spike"] = 0.5
            indicators.append(f"Elevated error count ({error_count}) during DB activity")
        else:
            signal_scores["error_spike"] = 0.0

        # Signal 3: Time-based blind SQLi (deliberate slow queries)
        if duration > 5000 and inferred_db > 3:
            signal_scores["time_based_sqli"] = 0.85
            indicators.append(
                f"Long execution ({duration}ms) with DB calls — "
                "consistent with time-based blind SQL injection"
            )
        elif 3000 < duration <= 5000 and inferred_db > 5:
            signal_scores["time_based_sqli"] = 0.5
        else:
            signal_scores["time_based_sqli"] = 0.0

        # Signal 4: High memory + DB queries (data dump)
        if memory > 300 and inferred_db > 15:
            signal_scores["data_dump"] = 0.8
            indicators.append(
                f"High memory ({memory}MB) with many DB queries — "
                "possible database dump attempt"
            )
        elif memory > 200 and inferred_db > 10:
            signal_scores["data_dump"] = 0.5
        else:
            signal_scores["data_dump"] = 0.0

        # Signal 5: Error-based SQLi (low calls, high errors — probing)
        if error_count >= api_calls and api_calls > 0 and api_calls < 10:
            signal_scores["error_based_probe"] = 0.7
            indicators.append(
                f"Error rate equals call rate ({error_count}/{api_calls}) — "
                "consistent with error-based SQLi probing"
            )
        else:
            signal_scores["error_based_probe"] = 0.0

        weights = {
            "high_db_queries":   0.25,
            "error_spike":       0.25,
            "time_based_sqli":   0.25,
            "data_dump":         0.15,
            "error_based_probe": 0.10,
        }

        confidence = sum(signal_scores.get(k, 0) * w for k, w in weights.items())
        matched    = confidence >= 0.35

        return self._result(matched, confidence, indicators, {
            "inferred_db_queries": inferred_db,
            "error_count":         error_count,
            "duration_ms":         duration,
            "memory_mb":           memory,
            "signal_scores":       {k: round(v, 4) for k, v in signal_scores.items()},
        })



# PATTERN 4: Crypto Mining

class CryptoMiningPattern(AttackPattern):
    """
    Crypto mining detection in Lambda functions.

    Signals:
      - Very high execution duration (> 5× baseline)
      - High CPU-bound memory usage
      - Low API call count (mining is CPU, not network intensive)
      - Consistent execution time (mining has stable compute profile)
      - High cost vs output ratio
      - Functions named suspiciously
    """

    name        = "Crypto Mining"
    attack_type = "crypto_mining"
    description = "Unauthorised cryptocurrency mining pattern detected"

    # Expected baseline for normal Lambda
    BASELINE_DURATION = 500   # ms
    BASELINE_MEMORY   = 130   # MB

    def match(self, packet: dict, ip_analysis: dict, packet_analysis: dict) -> dict:
        indicators = []
        signal_scores = {}

        duration      = packet.get("duration", 0)
        memory        = packet.get("memory_used", 0)
        api_calls     = packet.get("num_api_calls", 0)
        error_count   = packet.get("error_count", 0)
        function_name = packet.get("function_name", "").lower()

        # Signal 1: Long duration
        duration_ratio = duration / max(self.BASELINE_DURATION, 1)
        if duration_ratio >= 20:
            signal_scores["high_duration"] = 1.0
            indicators.append(
                f"Execution time {duration}ms is {duration_ratio:.1f}× baseline — "
                "classic crypto mining signature"
            )
        elif duration_ratio >= 10:
            signal_scores["high_duration"] = 0.8
            indicators.append(f"Execution time {duration}ms is {duration_ratio:.1f}× baseline")
        elif duration_ratio >= 5:
            signal_scores["high_duration"] = 0.5
        else:
            signal_scores["high_duration"] = 0.0

        # Signal 2: High memory (mining needs RAM)
        memory_ratio = memory / max(self.BASELINE_MEMORY, 1)
        if memory_ratio >= 4:
            signal_scores["high_memory"] = 0.9
            indicators.append(f"Memory usage {memory}MB is {memory_ratio:.1f}× baseline")
        elif memory_ratio >= 2:
            signal_scores["high_memory"] = 0.6
        else:
            signal_scores["high_memory"] = 0.0

        # Signal 3: Low network activity (mining is CPU, not network)
        if duration > 5000 and api_calls <= 2:
            signal_scores["low_network"] = 0.8
            indicators.append(
                f"Long execution ({duration}ms) with only {api_calls} API calls — "
                "CPU-bound workload consistent with mining"
            )
        elif api_calls == 0 and duration > 3000:
            signal_scores["low_network"] = 0.6
        else:
            signal_scores["low_network"] = 0.0

        # Signal 4: No errors (mining runs cleanly)
        if error_count == 0 and duration > 5000:
            signal_scores["clean_long_exec"] = 0.5
            indicators.append("Error-free long execution — consistent with intentional mining workload")
        else:
            signal_scores["clean_long_exec"] = 0.0

        # Signal 5: Combined duration + memory threshold
        if duration > 8000 and memory > 256:
            signal_scores["combined_threshold"] = 0.9
            indicators.append(
                f"Combined high duration ({duration}ms) + memory ({memory}MB) "
                "exceeds crypto mining threshold"
            )
        elif duration > 5000 and memory > 200:
            signal_scores["combined_threshold"] = 0.6
        else:
            signal_scores["combined_threshold"] = 0.0

        # Signal 6: Suspicious function name
        mining_keywords = ["mine", "hash", "worker", "compute", "cpu", "xmr", "btc", "eth"]
        if any(kw in function_name for kw in mining_keywords):
            signal_scores["suspicious_name"] = 0.6
            indicators.append(f"Function name '{function_name}' contains mining-related keyword")
        else:
            signal_scores["suspicious_name"] = 0.0

        weights = {
            "high_duration":     0.30,
            "high_memory":       0.20,
            "low_network":       0.20,
            "combined_threshold": 0.15,
            "clean_long_exec":   0.10,
            "suspicious_name":   0.05,
        }

        confidence = sum(signal_scores.get(k, 0) * w for k, w in weights.items())
        matched    = confidence >= 0.40

        return self._result(matched, confidence, indicators, {
            "duration_ratio":  round(duration_ratio, 2),
            "memory_ratio":    round(memory_ratio, 2),
            "api_calls":       api_calls,
            "function_name":   function_name,
            "signal_scores":   {k: round(v, 4) for k, v in signal_scores.items()},
        })



# PATTERN 5: Data Exfiltration

class DataExfiltrationPattern(AttackPattern):
    """
    Data exfiltration detection.

    Signals:
      - High outbound/inbound data ratio
      - Many unique destinations
      - High API call volume
      - Clean execution (no errors — planned exfil)
      - High memory with large output (data staged in memory)
      - IP reputation of destination
    """

    name        = "Data Exfiltration"
    attack_type = "data_exfiltration"
    description = "Data exfiltration pattern detected — sensitive data may be leaving the system"

    def match(self, packet: dict, ip_analysis: dict, packet_analysis: dict) -> dict:
        indicators = []
        signal_scores = {}

        exfil   = packet_analysis.get("exfiltration", {})
        size    = packet_analysis.get("size", {})
        ip_rep  = ip_analysis.get("reputation", {})

        exfil_score = exfil.get("exfiltration_score", 0)
        size_ratio  = exfil.get("size_ratio", 0)
        unique_dest = exfil.get("unique_destinations", 1)
        api_calls   = packet.get("num_api_calls", 0)
        error_count = packet.get("error_count", 0)
        memory      = packet.get("memory_used", 0)

        # Signal 1: Use packet analyzer's exfiltration score directly
        if exfil_score >= 0.7:
            signal_scores["packet_exfil_score"] = 1.0
            indicators.append(f"Packet analyzer exfiltration score: {exfil_score:.2f} (critical)")
            indicators.extend(exfil.get("flags", []))
        elif exfil_score >= 0.4:
            signal_scores["packet_exfil_score"] = 0.7
            indicators.extend(exfil.get("flags", []))
        elif exfil_score >= 0.2:
            signal_scores["packet_exfil_score"] = 0.4
        else:
            signal_scores["packet_exfil_score"] = 0.0

        # Signal 2: Multiple destinations
        if unique_dest > 5:
            signal_scores["multi_destination"] = 0.8
            indicators.append(f"Data sent to {unique_dest} unique endpoints")
        elif unique_dest > 2:
            signal_scores["multi_destination"] = 0.4
        else:
            signal_scores["multi_destination"] = 0.0

        # Signal 3: API call volume for bulk transfer
        if api_calls > 25:
            signal_scores["bulk_transfer"] = 0.8
            indicators.append(f"Bulk transfer pattern: {api_calls} API calls")
        elif api_calls > 12:
            signal_scores["bulk_transfer"] = 0.5
        else:
            signal_scores["bulk_transfer"] = 0.0

        # Signal 4: Clean exfil (no errors = scripted, professional)
        if error_count == 0 and api_calls > 10 and size_ratio > 2:
            signal_scores["scripted_exfil"] = 0.7
            indicators.append("Error-free bulk outbound transfer — consistent with scripted exfiltration")
        else:
            signal_scores["scripted_exfil"] = 0.0

        # Signal 5: Sending to known bad IP
        if ip_rep.get("label") in ("MALICIOUS", "SUSPICIOUS") and size_ratio > 1:
            signal_scores["bad_destination"] = 0.9
            indicators.append(f"Data flowing to suspicious IP: {ip_rep.get('flags', [])}")
        else:
            signal_scores["bad_destination"] = 0.0

        weights = {
            "packet_exfil_score": 0.40,
            "multi_destination":  0.20,
            "bulk_transfer":      0.20,
            "scripted_exfil":     0.12,
            "bad_destination":    0.08,
        }

        confidence = sum(signal_scores.get(k, 0) * w for k, w in weights.items())
        matched    = confidence >= 0.35

        return self._result(matched, confidence, indicators, {
            "exfil_score":    exfil_score,
            "size_ratio":     size_ratio,
            "unique_dest":    unique_dest,
            "api_calls":      api_calls,
            "signal_scores":  {k: round(v, 4) for k, v in signal_scores.items()},
        })



# PATTERN 6: Memory Attack

class MemoryAttackPattern(AttackPattern):
    """
    Memory-based attack detection (buffer overflow, memory exhaustion, DoW).

    Signals:
      - Memory usage near or at Lambda limit
      - Memory with low execution time (fast allocation)
      - OOM errors
      - Repeated invocations with escalating memory
      - Memory + high API calls (data injection into memory)
    """

    name        = "Memory Attack"
    attack_type = "memory_attack"
    description = "Memory exhaustion or memory-based attack pattern detected"

    LAMBDA_MEMORY_LIMIT = 512   # MB — default Lambda limit
    WARNING_THRESHOLD   = 0.80  # 80% of limit
    CRITICAL_THRESHOLD  = 0.95  # 95% of limit

    def match(self, packet: dict, ip_analysis: dict, packet_analysis: dict) -> dict:
        indicators = []
        signal_scores = {}

        memory      = packet.get("memory_used", 0)
        duration    = packet.get("duration", 0)
        api_calls   = packet.get("num_api_calls", 0)
        error_count = packet.get("error_count", 0)
        mem_limit   = packet.get("memory_limit", self.LAMBDA_MEMORY_LIMIT)

        mem_ratio = memory / max(mem_limit, 1)

        # Signal 1: Memory near limit
        if mem_ratio >= self.CRITICAL_THRESHOLD:
            signal_scores["memory_near_limit"] = 1.0
            indicators.append(
                f"Memory at {mem_ratio:.1%} of limit ({memory}MB / {mem_limit}MB) — "
                "critical memory exhaustion"
            )
        elif mem_ratio >= self.WARNING_THRESHOLD:
            signal_scores["memory_near_limit"] = 0.7
            indicators.append(
                f"Memory at {mem_ratio:.1%} of limit ({memory}MB) — elevated risk"
            )
        else:
            signal_scores["memory_near_limit"] = max(0, (mem_ratio - 0.5) * 2)

        # Signal 2: Fast memory allocation (< 100ms but high memory = allocation bomb)
        if duration < 100 and memory > 300:
            signal_scores["fast_allocation"] = 0.9
            indicators.append(
                f"Rapid memory allocation: {memory}MB allocated in {duration}ms — "
                "possible allocation bomb"
            )
        elif duration < 200 and memory > 400:
            signal_scores["fast_allocation"] = 0.7
        else:
            signal_scores["fast_allocation"] = 0.0

        # Signal 3: OOM errors (Lambda returns 137 exit code on OOM)
        if error_count > 0 and memory > 400:
            signal_scores["oom_errors"] = 0.8
            indicators.append(
                f"{error_count} errors with high memory usage — "
                "possible out-of-memory condition"
            )
        else:
            signal_scores["oom_errors"] = 0.0

        # Signal 4: Memory + high API calls (data injection)
        if memory > 350 and api_calls > 15:
            signal_scores["memory_injection"] = 0.7
            indicators.append(
                f"High memory ({memory}MB) + {api_calls} API calls — "
                "possible data injection into memory space"
            )
        else:
            signal_scores["memory_injection"] = 0.0

        # Signal 5: Denial of Wallet (DoW) — Lambda billed by memory × duration
        # High memory × long duration = maximum cost attack
        cost_units = (memory / 1024) * (duration / 1000)  # GB-seconds
        if cost_units > 5.0:
            signal_scores["denial_of_wallet"] = 0.9
            indicators.append(
                f"Denial-of-Wallet risk: {cost_units:.2f} GB-seconds per invocation "
                f"({memory}MB × {duration}ms)"
            )
        elif cost_units > 2.0:
            signal_scores["denial_of_wallet"] = 0.6
            indicators.append(f"Elevated compute cost: {cost_units:.2f} GB-seconds")
        else:
            signal_scores["denial_of_wallet"] = 0.0

        weights = {
            "memory_near_limit":  0.30,
            "fast_allocation":    0.25,
            "denial_of_wallet":   0.20,
            "oom_errors":         0.15,
            "memory_injection":   0.10,
        }

        confidence = sum(signal_scores.get(k, 0) * w for k, w in weights.items())
        matched    = confidence >= 0.35

        return self._result(matched, confidence, indicators, {
            "memory_mb":       memory,
            "memory_limit_mb": mem_limit,
            "memory_ratio":    round(mem_ratio, 4),
            "cost_units_gb_s": round(cost_units, 4),
            "error_count":     error_count,
            "signal_scores":   {k: round(v, 4) for k, v in signal_scores.items()},
        })



# PATTERN REGISTRY — Run all patterns

_ALL_PATTERNS: List[AttackPattern] = [
    DDoSPattern(),
    SpoofingPattern(),
    SQLInjectionPattern(),
    CryptoMiningPattern(),
    DataExfiltrationPattern(),
    MemoryAttackPattern(),
]


def match_all_patterns(
    packet: dict,
    ip_analysis: dict,
    packet_analysis: dict,
) -> dict:
    """
    Run all attack patterns and return a combined result.

    Returns:
        {
            "matched_patterns": list of matched pattern results,
            "all_results":      list of all pattern results,
            "top_threat":       highest confidence match,
            "threat_count":     number of matched patterns,
            "elapsed_us":       total time in microseconds,
        }
    """
    t0 = time.perf_counter()

    all_results     = []
    matched_patterns = []

    for pattern in _ALL_PATTERNS:
        result = pattern.match(packet, ip_analysis, packet_analysis)
        all_results.append(result)
        if result["matched"]:
            matched_patterns.append(result)

    # Sort matched by confidence descending
    matched_patterns.sort(key=lambda r: r["confidence"], reverse=True)

    top_threat = matched_patterns[0] if matched_patterns else None

    elapsed_us = round((time.perf_counter() - t0) * 1_000_000)

    return {
        "matched_patterns": matched_patterns,
        "all_results":      all_results,
        "top_threat":       top_threat,
        "threat_count":     len(matched_patterns),
        "elapsed_us":       elapsed_us,
    }
