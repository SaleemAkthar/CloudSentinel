"""
simulation/attack_scripts.py
==============================
Attack traffic generators for the Cloud Sentinel dataset simulation.

Each function generates one record that mimics the execution metrics
a real Lambda function would produce under a specific attack pattern.
The values are derived from characteristics documented in CICIDS2017
and adapted to the AWS Lambda execution context.

Six attack types are modelled:
  1. Crypto Mining       — high CPU burn, elevated memory, low API calls
  2. Data Exfiltration   — many rapid DB queries, large outbound payload
  3. SQL Injection       — repeated failed queries, high error count
  4. DDoS                — flood of rapid short requests, high concurrency
  5. Memory Attack       — excessive memory allocation, slow execution
  6. IP Spoofing         — normal execution metrics, suspicious IP metadata

Each function returns a dict with the same schema as normal traffic
so records can be mixed into a single CSV without special handling.

Author: Okitha (LocalStack Simulation — Option 2: direct generation)
"""

import random
from datetime import datetime, timedelta


# ---------------------------------------------------------------------------
# Suspicious IP pools per attack type.
# These ranges are associated with known malicious infrastructure
# (Tor exit nodes, botnet C2 servers, scanning services).
# ---------------------------------------------------------------------------

SUSPICIOUS_IPS = {
    "crypto_mining":      ["5.34.178.52",    "45.155.205.10",  "185.220.101.42"],
    "data_exfiltration":  ["194.165.16.100", "89.248.160.10",  "45.142.212.50"],
    "sql_injection":      ["89.248.160.10",  "185.220.101.33", "5.34.178.99"],
    "ddos":               ["194.165.16.1",   "194.165.16.2",   "194.165.16.3",
                           "194.165.16.4",   "194.165.16.5"],
    "memory_attack":      ["31.13.80.10",    "45.155.205.22",  "185.220.101.55"],
    "ip_spoofing":        ["10.0.0.1",       "172.16.0.100",   "192.168.1.1",
                           "5.34.178.52",    "185.220.101.42"],
}

# Normal internal IP range — used for baseline and spoofing contrast.
NORMAL_IP_PREFIX = "192.168.1."


# ---------------------------------------------------------------------------
# Normal traffic generator
# ---------------------------------------------------------------------------

def generate_normal_record(timestamp: str = None) -> dict:
    """
    Generate one record representing legitimate Lambda execution.

    Values are drawn from ranges observed in well-behaved serverless
    workloads: short duration, low memory, few API calls, no errors.
    These records form the baseline the anomaly detector learns from.
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    # Randomly pick one of four function types to add realistic variation.
    function_profiles = [
        # (function_name, duration_range, memory_range, api_calls_range)
        ("api-handler",    (300,  600),  (80,  140), (1, 3)),
        ("file-processor", (200,  800),  (100, 180), (1, 2)),
        ("db-query",       (100,  400),  (80,  130), (1, 4)),
        ("auth-service",   (50,   200),  (64,  110), (1, 2)),
    ]
    fn, dur_range, mem_range, api_range = random.choice(function_profiles)

    return {
        "timestamp":       timestamp,
        "function_name":   fn,
        "duration":        round(random.uniform(*dur_range), 2),
        "memory_used":     round(random.uniform(*mem_range), 2),
        "num_api_calls":   random.randint(*api_range),
        "error_count":     0,
        "concurrency":     1,
        "ip_address":      NORMAL_IP_PREFIX + str(random.randint(1, 50)),
        "ttl":             random.choice([64, 64, 64, 128]),  # typical OS defaults
        "packet_size_in":  random.randint(256, 1024),
        "packet_size_out": random.randint(128, 512),
        "latency":         round(random.uniform(5, 50), 2),
        "fragment_count":  0,
        "source_port":     random.randint(49152, 65535),
        "status_code":     200,
        "label":           "normal",
        "attack_type":     None,
    }


# ---------------------------------------------------------------------------
# Attack traffic generators
# ---------------------------------------------------------------------------

def generate_crypto_mining_record(timestamp: str = None) -> dict:
    """
    Generate one crypto-mining attack record.

    Crypto mining hijacks Lambda CPU for proof-of-work computation.
    Signature: very high execution duration (simulating multiple
    heavy invocations chained together), elevated memory, and
    low API call count (mining does not need external data).
    TTL is slightly low, consistent with packets routed through
    anonymising infrastructure.
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    # Duration simulates 5–15 chained heavy invocations (800–1500ms each).
    num_loops = random.randint(5, 15)
    total_duration = sum(
        random.uniform(800, 1500) for _ in range(num_loops)
    )

    return {
        "timestamp":       timestamp,
        "function_name":   "api-handler",
        "duration":        round(total_duration, 2),
        "memory_used":     round(random.uniform(350, 480), 2),
        "num_api_calls":   random.randint(1, 3),
        "error_count":     0,
        "concurrency":     1,
        "ip_address":      random.choice(SUSPICIOUS_IPS["crypto_mining"]),
        "ttl":             random.randint(44, 60),
        "packet_size_in":  random.randint(128, 512),
        "packet_size_out": random.randint(64, 256),
        "latency":         round(random.uniform(10, 50), 2),
        "fragment_count":  0,
        "source_port":     random.randint(49152, 65535),
        "status_code":     200,
        "label":           "attack",
        "attack_type":     "crypto_mining",
    }


def generate_data_exfiltration_record(timestamp: str = None) -> dict:
    """
    Generate one data-exfiltration attack record.

    Data exfiltration invokes the DB query function rapidly and
    repeatedly to extract as much data as possible before detection.
    Signature: high API call count, large outbound packet size,
    moderately elevated duration from the volume of queries,
    and clean error count (planned extraction avoids errors).
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    # Each exfiltration burst makes 8–20 rapid complex queries.
    api_calls = random.randint(8, 20)
    total_duration = sum(
        random.uniform(500, 1000) for _ in range(api_calls)
    )

    return {
        "timestamp":       timestamp,
        "function_name":   "db-query",
        "duration":        round(total_duration, 2),
        "memory_used":     round(random.uniform(150, 250), 2),
        "num_api_calls":   api_calls,
        "error_count":     0,
        "concurrency":     random.randint(2, 5),
        "ip_address":      random.choice(SUSPICIOUS_IPS["data_exfiltration"]),
        "ttl":             random.randint(48, 60),
        "packet_size_in":  random.randint(256, 512),
        "packet_size_out": random.randint(5000, 20000),  # large data leaving
        "latency":         round(random.uniform(20, 80), 2),
        "fragment_count":  random.randint(0, 2),
        "source_port":     random.randint(49152, 65535),
        "status_code":     200,
        "label":           "attack",
        "attack_type":     "data_exfiltration",
    }


def generate_sql_injection_record(timestamp: str = None) -> dict:
    """
    Generate one SQL-injection attack record.

    SQL injection bombards the DB query function with malformed inputs
    in an attempt to extract data or bypass authentication.
    Signature: very high error count (most queries fail), many rapid
    attempts, moderate duration from the volume of failed calls.
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    # Most injection attempts fail — 70–90% error rate.
    num_attempts = random.randint(15, 30)
    errors = int(num_attempts * random.uniform(0.7, 0.9))
    total_duration = sum(
        random.uniform(100, 400) for _ in range(num_attempts)
    )

    return {
        "timestamp":       timestamp,
        "function_name":   "db-query",
        "duration":        round(total_duration, 2),
        "memory_used":     round(random.uniform(100, 180), 2),
        "num_api_calls":   num_attempts,
        "error_count":     errors,
        "concurrency":     random.randint(1, 3),
        "ip_address":      random.choice(SUSPICIOUS_IPS["sql_injection"]),
        "ttl":             random.randint(50, 64),
        "packet_size_in":  random.randint(512, 2048),   # large malformed payloads
        "packet_size_out": random.randint(128, 512),
        "latency":         round(random.uniform(15, 60), 2),
        "fragment_count":  random.randint(0, 3),
        "source_port":     random.randint(49152, 65535),
        "status_code":     400,
        "label":           "attack",
        "attack_type":     "sql_injection",
    }


def generate_ddos_record(timestamp: str = None) -> dict:
    """
    Generate one DDoS attack record.

    A DDoS attack floods Lambda with a high volume of short concurrent
    requests to exhaust concurrency limits and increase costs.
    Signature: very high concurrency, many API calls, short individual
    duration (each request is simple), multiple source IPs.
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    return {
        "timestamp":       timestamp,
        "function_name":   "api-handler",
        "duration":        round(random.uniform(50, 300), 2),  # each req is fast
        "memory_used":     round(random.uniform(80, 150), 2),
        "num_api_calls":   random.randint(10, 30),   # flood of calls
        "error_count":     random.randint(0, 5),
        "concurrency":     random.randint(20, 50),   # high concurrent executions
        "ip_address":      random.choice(SUSPICIOUS_IPS["ddos"]),
        "ttl":             random.randint(50, 64),
        "packet_size_in":  random.randint(64, 256),  # small flood packets
        "packet_size_out": random.randint(64, 256),
        "latency":         round(random.uniform(1, 20), 2),
        "fragment_count":  random.randint(0, 5),
        "source_port":     random.randint(1024, 65535),
        "status_code":     200,
        "label":           "attack",
        "attack_type":     "ddos",
    }


def generate_memory_attack_record(timestamp: str = None) -> dict:
    """
    Generate one memory-exhaustion attack record.

    A memory attack forces Lambda to allocate excessive RAM, either to
    degrade performance or exploit buffer overflow vulnerabilities.
    Signature: very high memory consumption, elevated duration from
    the overhead of large allocations, and large inbound payloads.
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    # Simulate file-processor invoked with an unrealistically large file.
    file_size_kb = random.randint(5000, 20000)
    processing_time = min(file_size_kb * 0.005, 5.0) * 1000  # ms, capped at 5s

    return {
        "timestamp":       timestamp,
        "function_name":   "file-processor",
        "duration":        round(processing_time + random.uniform(0, 500), 2),
        "memory_used":     round(random.uniform(400, 512), 2),  # near Lambda limit
        "num_api_calls":   random.randint(1, 3),
        "error_count":     random.randint(0, 2),
        "concurrency":     1,
        "ip_address":      random.choice(SUSPICIOUS_IPS["memory_attack"]),
        "ttl":             random.randint(48, 64),
        "packet_size_in":  random.randint(10000, 65535),  # oversized payload
        "packet_size_out": random.randint(128, 1024),
        "latency":         round(random.uniform(30, 100), 2),
        "fragment_count":  random.randint(3, 10),         # fragmented large packet
        "source_port":     random.randint(49152, 65535),
        "status_code":     200,
        "label":           "attack",
        "attack_type":     "memory_attack",
    }


def generate_ip_spoofing_record(timestamp: str = None) -> dict:
    """
    Generate one IP-spoofing attack record.

    IP spoofing forges the source IP address to bypass rate limiting or
    impersonate trusted internal hosts. Execution metrics look mostly
    normal, but the TTL value is anomalously low (packet has been
    routed many hops through anonymising infrastructure) and the
    source IP alternates between internal-looking and known-bad ranges.
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    return {
        "timestamp":       timestamp,
        "function_name":   "auth-service",
        "duration":        round(random.uniform(50, 300), 2),   # appears normal
        "memory_used":     round(random.uniform(64, 120), 2),   # appears normal
        "num_api_calls":   random.randint(1, 4),
        "error_count":     random.randint(0, 1),
        "concurrency":     1,
        "ip_address":      random.choice(SUSPICIOUS_IPS["ip_spoofing"]),
        "ttl":             random.randint(1, 29),    # abnormally low TTL
        "packet_size_in":  random.randint(256, 1024),
        "packet_size_out": random.randint(128, 512),
        "latency":         round(random.uniform(5, 50), 2),
        "fragment_count":  random.randint(0, 2),
        "source_port":     random.randint(49152, 65535),
        "status_code":     200,
        "label":           "attack",
        "attack_type":     "ip_spoofing",
    }


# ---------------------------------------------------------------------------
# Convenience mapping — used by run_simulation.py to call generators by name
# ---------------------------------------------------------------------------

ATTACK_GENERATORS = {
    "crypto_mining":     generate_crypto_mining_record,
    "data_exfiltration": generate_data_exfiltration_record,
    "sql_injection":     generate_sql_injection_record,
    "ddos":              generate_ddos_record,
    "memory_attack":     generate_memory_attack_record,
    "ip_spoofing":       generate_ip_spoofing_record,
}
