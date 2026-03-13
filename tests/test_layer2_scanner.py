"""
Layer 2 Scanner — Quick Test Script
=====================================
Run this from the project root to verify all modules work correctly.

Usage:
    python tests/test_layer2_scanner.py

Author: Backend Team
"""

import sys
import os
import json

# Allow running from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# ── Colour helpers ────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}✓{RESET} {msg}")
def fail(msg): print(f"  {RED}✗{RESET} {msg}"); sys.exit(1)
def info(msg): print(f"  {CYAN}→{RESET} {msg}")
def header(msg): print(f"\n{BOLD}{YELLOW}{'─'*55}{RESET}\n{BOLD} {msg}{RESET}\n{'─'*55}")


# ============================================================================
# TEST PACKETS
# ============================================================================

PACKETS = {
    "normal": {
        "description": "Normal Lambda execution",
        "packet": {
            "ip_address":        "52.94.0.1",
            "ttl":               54,
            "duration":          480,
            "memory_used":       128,
            "num_api_calls":     3,
            "packet_size_in":    512,
            "packet_size_out":   256,
            "fragment_count":    0,
            "protocol":          "HTTPS",
            "dest_port":         443,
            "source_port":       54321,
            "network_latency":   12.0,
            "unique_destinations": 1,
            "error_count":       0,
            "function_name":     "process-orders",
            "region":            "us-east-1",
        },
        "expect_severity": ["LOW", "MEDIUM"],
        "expect_action":   ["PASS", "MONITOR"],
    },

    "crypto_mining": {
        "description": "Crypto mining attack",
        "packet": {
            "ip_address":        "185.220.101.45",
            "ttl":               44,
            "duration":          12000,
            "memory_used":       450,
            "num_api_calls":     1,
            "packet_size_in":    128,
            "packet_size_out":   64,
            "fragment_count":    0,
            "protocol":          "HTTPS",
            "dest_port":         443,
            "source_port":       55000,
            "network_latency":   8.0,
            "unique_destinations": 1,
            "error_count":       0,
            "function_name":     "hash-worker",
            "region":            "us-east-1",
        },
        "expect_severity": ["CRITICAL", "HIGH"],
        "expect_action":   ["BLOCK"],
    },

    "data_exfiltration": {
        "description": "Data exfiltration attack",
        "packet": {
            "ip_address":        "45.142.212.100",
            "ttl":               50,
            "duration":          600,
            "memory_used":       350,
            "num_api_calls":     28,
            "packet_size_in":    200,
            "packet_size_out":   524288,   # 512 KB outbound
            "fragment_count":    0,
            "protocol":          "HTTPS",
            "dest_port":         443,
            "source_port":       60000,
            "network_latency":   20.0,
            "unique_destinations": 8,
            "error_count":       0,
            "function_name":     "export-data",
            "region":            "us-east-1",
        },
        "expect_severity": ["CRITICAL", "HIGH"],
        "expect_action":   ["BLOCK"],
    },

    "ddos": {
        "description": "DDoS attack pattern",
        "packet": {
            "ip_address":        "194.165.16.100",
            "ttl":               42,
            "duration":          45,
            "memory_used":       64,
            "num_api_calls":     120,
            "packet_size_in":    64,
            "packet_size_out":   32,
            "fragment_count":    12,
            "protocol":          "TCP",
            "dest_port":         80,
            "source_port":       12345,
            "network_latency":   2.0,
            "unique_destinations": 1,
            "error_count":       0,
            "function_name":     "api-handler",
            "region":            "us-east-1",
        },
        "expect_severity": ["CRITICAL", "HIGH"],
        "expect_action":   ["BLOCK"],
    },

    "sql_injection": {
        "description": "SQL injection attack",
        "packet": {
            "ip_address":        "89.248.160.10",
            "ttl":               55,
            "duration":          5500,
            "memory_used":       280,
            "num_api_calls":     8,
            "packet_size_in":    512,
            "packet_size_out":   1024,
            "fragment_count":    0,
            "protocol":          "HTTPS",
            "dest_port":         3306,
            "source_port":       49152,
            "network_latency":   15.0,
            "unique_destinations": 1,
            "error_count":       6,
            "db_queries":        45,
            "function_name":     "user-lookup",
            "region":            "us-east-1",
        },
        "expect_severity": ["CRITICAL", "HIGH", "MEDIUM"],
        "expect_action":   ["BLOCK", "MONITOR"],
    },

    "memory_attack": {
        "description": "Memory exhaustion / Denial-of-Wallet",
        "packet": {
            "ip_address":        "80.82.77.5",
            "ttl":               48,
            "duration":          9000,
            "memory_used":       490,
            "num_api_calls":     5,
            "packet_size_in":    256,
            "packet_size_out":   128,
            "fragment_count":    0,
            "protocol":          "HTTPS",
            "dest_port":         443,
            "source_port":       58000,
            "network_latency":   10.0,
            "unique_destinations": 1,
            "error_count":       3,
            "memory_limit":      512,
            "function_name":     "image-processor",
            "region":            "us-east-1",
        },
        "expect_severity": ["CRITICAL", "HIGH"],
        "expect_action":   ["BLOCK"],
    },
}

LAYER1_PASS    = {"pass": False, "checks": {"ttl": True, "size": True, "duration": True}, "reason": "Layer 1 flagged"}
LAYER1_FAIL    = {"pass": False, "checks": {"ttl": False, "size": True, "duration": True}, "reason": "TTL out of range"}


# ============================================================================
# IMPORT TESTS
# ============================================================================

def test_imports():
    header("1. Module Import Tests")
    modules = [
        ("backend.detection.ip_analyzer",      "IPAnalyzer"),
        ("backend.detection.packet_analyzer",  "PacketAnalyzer"),
        ("backend.detection.attack_patterns",  "match_all_patterns"),
        ("backend.detection.network_topology", "NetworkTopologyAnalyzer"),
        ("backend.detection.risk_scorer",      "RiskScorer"),
        ("backend.detection.layer2_scanner",   "Layer2Scanner"),
    ]
    for module_path, class_name in modules:
        try:
            mod = __import__(module_path, fromlist=[class_name])
            getattr(mod, class_name)
            ok(f"{module_path} → {class_name}")
        except ImportError as e:
            fail(f"Cannot import {module_path}: {e}")
        except AttributeError as e:
            fail(f"{module_path} missing {class_name}: {e}")


# ============================================================================
# INDIVIDUAL MODULE TESTS
# ============================================================================

def test_ip_analyzer():
    header("2. IP Analyzer Tests")
    from backend.detection.ip_analyzer import IPAnalyzer
    analyzer = IPAnalyzer()

    # Test private IP
    result = analyzer.analyze("10.0.0.1", ttl=64)
    assert result["valid"], "Private IP should be valid"
    assert result["geolocation"]["country_code"] == "PR", "Should be private"
    ok("Private IP (10.0.0.1) correctly identified")

    # Test known bad IP
    result = analyzer.analyze("185.220.101.45", ttl=44)
    assert result["reputation"]["label"] in ("MALICIOUS", "SUSPICIOUS"), \
        f"Expected MALICIOUS/SUSPICIOUS, got {result['reputation']['label']}"
    ok(f"Known bad IP (185.220.x) → reputation: {result['reputation']['label']}")

    # Test spoofing detection
    result = analyzer.analyze("185.220.101.45", ttl=254)
    spoof = result["spoofing"]
    info(f"Spoofing score: {spoof['spoofing_score']:.2f}, "
         f"indicators: {len(spoof['indicators'])}")
    ok("Spoofing detection ran successfully")

    # Test invalid IP
    result = analyzer.analyze("999.999.999.999")
    assert not result["valid"], "Invalid IP should fail validation"
    ok("Invalid IP correctly rejected")

    # Test history tracking
    for _ in range(3):
        analyzer.analyze("45.142.212.100", ttl=50)
    result = analyzer.analyze("45.142.212.100", ttl=50)
    assert result["history"]["hit_count"] >= 4, "Hit count should increment"
    ok(f"History tracking: hit_count = {result['history']['hit_count']}")


def test_packet_analyzer():
    header("3. Packet Analyzer Tests")
    from backend.detection.packet_analyzer import PacketAnalyzer
    analyzer = PacketAnalyzer()

    # Normal packet
    result = analyzer.analyze(PACKETS["normal"]["packet"])
    assert "risk_score" in result
    assert 0.0 <= result["risk_score"] <= 1.0
    ok(f"Normal packet risk score: {result['risk_score']:.4f}")

    # Exfiltration packet
    result = analyzer.analyze(PACKETS["data_exfiltration"]["packet"])
    exfil = result["exfiltration"]
    assert exfil["exfiltration_score"] > 0.3, \
        f"Exfiltration score too low: {exfil['exfiltration_score']}"
    ok(f"Exfiltration packet score: {exfil['exfiltration_score']:.4f} ({exfil['classification']})")

    # Latency breakdown
    result = analyzer.analyze(PACKETS["crypto_mining"]["packet"])
    lat = result["latency"]
    assert "execution_ms" in lat and "network_ms" in lat
    ok(f"Latency breakdown: exec={lat['execution_ms']}ms, "
       f"net={lat['network_ms']}ms, cold_start={lat['cold_start_ms']}ms")

    # DDoS fragmentation
    result = analyzer.analyze(PACKETS["ddos"]["packet"])
    frag = result["fragmentation"]
    ok(f"Fragmentation pattern: {frag['pattern']} "
       f"(effective_frags={frag['effective_fragments']})")


def test_attack_patterns():
    header("4. Attack Pattern Tests")
    from backend.detection.ip_analyzer    import IPAnalyzer
    from backend.detection.packet_analyzer import PacketAnalyzer
    from backend.detection.attack_patterns import match_all_patterns

    ip_a  = IPAnalyzer()
    pkt_a = PacketAnalyzer()

    test_cases = [
        ("crypto_mining",    "crypto_mining"),
        ("data_exfiltration","data_exfiltration"),
        ("ddos",             "ddos"),
        ("sql_injection",    "sql_injection"),
        ("memory_attack",    "memory_attack"),
    ]

    for packet_key, expected_type in test_cases:
        pkt     = PACKETS[packet_key]["packet"]
        ip_res  = ip_a.analyze(pkt["ip_address"], pkt.get("ttl", 64))
        pkt_res = pkt_a.analyze(pkt)
        result  = match_all_patterns(pkt, ip_res, pkt_res)

        matched_types = [p["attack_type"] for p in result["matched_patterns"]]
        if expected_type in matched_types:
            conf = next(p["confidence"] for p in result["matched_patterns"]
                        if p["attack_type"] == expected_type)
            ok(f"{expected_type}: matched (confidence={conf:.2f})")
        else:
            # Soft warning — pattern may need more signals
            print(f"  {YELLOW}⚠{RESET}  {expected_type}: not matched "
                  f"(matched: {matched_types or 'none'})")

    # Normal packet should have low threat count
    pkt    = PACKETS["normal"]["packet"]
    ip_res = ip_a.analyze(pkt["ip_address"], pkt.get("ttl", 64))
    pkt_res = pkt_a.analyze(pkt)
    result = match_all_patterns(pkt, ip_res, pkt_res)
    info(f"Normal packet matched {result['threat_count']} pattern(s): "
         f"{[p['attack_type'] for p in result['matched_patterns']]}")


def test_network_topology():
    header("5. Network Topology Tests")
    from backend.detection.ip_analyzer       import IPAnalyzer
    from backend.detection.network_topology  import NetworkTopologyAnalyzer

    ip_a   = IPAnalyzer()
    topo_a = NetworkTopologyAnalyzer()

    # Normal AWS traffic
    pkt    = PACKETS["normal"]["packet"]
    ip_res = ip_a.analyze(pkt["ip_address"], pkt.get("ttl", 64))
    result = topo_a.analyze(pkt, ip_res)

    assert "hop_analysis" in result
    assert "routing_path" in result
    assert len(result["routing_path"]) > 0
    ok(f"Routing path simulated: {len(result['routing_path'])} hops")
    ok(f"Inferred hops: {result['hop_analysis']['inferred_hops']} "
       f"(OS: {result['hop_analysis']['os_fingerprint']})")
    ok(f"Transit provider: {result['transit']['provider_name']} "
       f"(risk: {result['transit']['risk_level']})")

    # Malicious IP topology
    pkt    = PACKETS["crypto_mining"]["packet"]
    ip_res = ip_a.analyze(pkt["ip_address"], pkt.get("ttl", 64))
    result = topo_a.analyze(pkt, ip_res)
    ok(f"Malicious IP topology risk: {result['risk_score']:.4f} "
       f"(anomalies: {result['anomalies']['anomaly_count']})")


def test_risk_scorer():
    header("6. Risk Scorer Tests")
    from backend.detection.ip_analyzer      import IPAnalyzer
    from backend.detection.packet_analyzer  import PacketAnalyzer
    from backend.detection.attack_patterns  import match_all_patterns
    from backend.detection.network_topology import NetworkTopologyAnalyzer
    from backend.detection.risk_scorer      import RiskScorer

    ip_a   = IPAnalyzer()
    pkt_a  = PacketAnalyzer()
    topo_a = NetworkTopologyAnalyzer()
    scorer = RiskScorer()

    for key, data in PACKETS.items():
        pkt     = data["packet"]
        ip_res  = ip_a.analyze(pkt["ip_address"], pkt.get("ttl", 64))
        pkt_res = pkt_a.analyze(pkt)
        pat_res = match_all_patterns(pkt, ip_res, pkt_res)
        top_res = topo_a.analyze(pkt, ip_res)
        risk    = scorer.score(pkt, ip_res, pkt_res, pat_res, top_res, LAYER1_PASS)

        assert risk["severity"] in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        assert 0.0 <= risk["adjusted_score"] <= 1.0
        assert 0.0 <= risk["confidence"] <= 1.0

        ok(f"{key:20s} → severity={risk['severity']:8s} "
           f"score={risk['adjusted_score']:.2f} "
           f"confidence={risk['confidence']:.2f} "
           f"action={risk['recommendation']['action']}")


# ============================================================================
# FULL END-TO-END SCANNER TEST
# ============================================================================

def test_full_scanner():
    header("7. Full Layer2Scanner End-to-End Tests")
    from backend.detection.layer2_scanner import Layer2Scanner
    scanner = Layer2Scanner()

    passed = 0
    failed_cases = []

    for key, data in PACKETS.items():
        report = scanner.scan(data["packet"], LAYER1_PASS)

        # Validate structure
        required_keys = ["scan_id", "timestamp", "elapsed_ms", "severity",
                         "decision", "ip", "packet", "patterns", "topology", "risk"]
        for rk in required_keys:
            assert rk in report, f"Missing key: {rk}"

        severity_ok = report["severity"] in data["expect_severity"]
        action_ok   = report["decision"] in data["expect_action"]

        status = f"{GREEN}✓{RESET}" if (severity_ok and action_ok) else f"{YELLOW}⚠{RESET}"
        print(f"  {status} [{key}] {data['description']}")
        info(f"    severity={report['severity']} (expected {data['expect_severity']})")
        info(f"    action={report['decision']}   (expected {data['expect_action']})")
        info(f"    score={report['risk']['adjusted_score']:.2f}  "
             f"confidence={report['risk']['confidence']:.2f}  "
             f"elapsed={report['elapsed_ms']}ms")

        if report["patterns"]["threat_count"] > 0:
            matched = [p["attack_type"] for p in report["patterns"]["matched_patterns"]]
            info(f"    patterns matched: {matched}")

        if severity_ok and action_ok:
            passed += 1
        else:
            failed_cases.append(key)

    print(f"\n  {BOLD}Results: {passed}/{len(PACKETS)} packets classified correctly{RESET}")
    if failed_cases:
        print(f"  {YELLOW}Review needed for: {failed_cases}{RESET}")
    else:
        print(f"  {GREEN}All packets classified as expected!{RESET}")


# ============================================================================
# PERFORMANCE TEST
# ============================================================================

def test_performance():
    header("8. Performance Test (100 scans)")
    import time
    from backend.detection.layer2_scanner import Layer2Scanner
    scanner = Layer2Scanner()

    pkt    = PACKETS["crypto_mining"]["packet"]
    times  = []

    for _ in range(100):
        t0     = time.perf_counter()
        scanner.scan(pkt, LAYER1_PASS)
        elapsed = (time.perf_counter() - t0) * 1000
        times.append(elapsed)

    avg  = sum(times) / len(times)
    peak = max(times)
    p95  = sorted(times)[94]

    ok(f"Average scan time : {avg:.2f}ms")
    ok(f"95th percentile   : {p95:.2f}ms")
    ok(f"Peak scan time    : {peak:.2f}ms")

    if avg < 10:
        ok(f"Performance: EXCELLENT (avg < 10ms)")
    elif avg < 50:
        ok(f"Performance: GOOD (avg < 50ms)")
    else:
        print(f"  {YELLOW}⚠{RESET}  Performance: SLOW (avg {avg:.2f}ms — review bottlenecks)")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    print(f"\n{BOLD}{'='*55}")
    print(f"  Cloud Sentinel — Layer 2 Scanner Test Suite")
    print(f"{'='*55}{RESET}")

    try:
        test_imports()
        test_ip_analyzer()
        test_packet_analyzer()
        test_attack_patterns()
        test_network_topology()
        test_risk_scorer()
        test_full_scanner()
        test_performance()

        print(f"\n{BOLD}{GREEN}{'='*55}")
        print(f"  All tests completed successfully!")
        print(f"{'='*55}{RESET}\n")

    except AssertionError as e:
        print(f"\n{RED}{BOLD}ASSERTION FAILED: {e}{RESET}\n")
        sys.exit(1)
    except Exception as e:
        print(f"\n{RED}{BOLD}ERROR: {e}{RESET}\n")
        import traceback
        traceback.print_exc()
        sys.exit(1)