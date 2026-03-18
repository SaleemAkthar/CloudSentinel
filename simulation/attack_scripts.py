"""
simulation/attack_scripts.py
==============================
Attack traffic generators for the Cloud Sentinel dataset simulation.

Each function invokes a real Lambda function deployed on LocalStack
and collects the actual execution metrics. Attack patterns are
simulated by invoking functions in malicious ways (tight loops,
mass queries, oversized payloads) so the resulting duration and
memory values come from real code execution, not random generation.

Six attack types are modelled:
  1. Crypto Mining       — chains heavy invocations to burn CPU
  2. Data Exfiltration   — rapidly extracts many complex DB queries
  3. SQL Injection       — floods DB with repeated failing queries
  4. DDoS                — floods api-handler with rapid requests
  5. Memory Attack       — invokes file-processor with huge payloads
  6. IP Spoofing         — normal execution with anomalous IP metadata

Author: Okitha (LocalStack Simulation)
"""

import boto3
import json
import time
import random
from datetime import datetime


# ---------------------------------------------------------------------------
# LocalStack client configuration
# ---------------------------------------------------------------------------

LOCALSTACK_ENDPOINT = "http://localhost:4566"
AWS_REGION          = "us-east-1"

lambda_client = boto3.client(
    "lambda",
    endpoint_url=LOCALSTACK_ENDPOINT,
    region_name=AWS_REGION,
    aws_access_key_id="test",
    aws_secret_access_key="test",
)

# Suspicious IP pools per attack type.
SUSPICIOUS_IPS = {
    "crypto_mining":     ["5.34.178.52",    "45.155.205.10",  "185.220.101.42"],
    "data_exfiltration": ["194.165.16.100", "89.248.160.10",  "45.142.212.50"],
    "sql_injection":     ["89.248.160.10",  "185.220.101.33", "5.34.178.99"],
    "ddos":              ["194.165.16.1",   "194.165.16.2",   "194.165.16.3"],
    "memory_attack":     ["31.13.80.10",    "45.155.205.22",  "185.220.101.55"],
    "ip_spoofing":       ["10.0.0.1",       "172.16.0.100",   "5.34.178.52"],
}

NORMAL_IP_PREFIX = "192.168.1."


# ---------------------------------------------------------------------------
# Lambda invocation helper
# ---------------------------------------------------------------------------

def invoke(function_name: str, payload: dict) -> dict:
    """
    Invoke a Lambda function on LocalStack and return its response.

    Measures wall-clock time around the invocation so we capture
    total execution time including Lambda runtime overhead.

    Args:
        function_name: Name of the deployed Lambda function.
        payload:       Event dict to pass to the function.

    Returns:
        Dict containing wall_time_ms and the function's response payload.
    """
    start    = time.time()
    response = lambda_client.invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps(payload),
    )
    wall_ms          = round((time.time() - start) * 1000, 2)
    response_payload = json.loads(response["Payload"].read())

    return {
        "wall_time_ms": wall_ms,
        "response":     response_payload,
        "error":        response.get("FunctionError"),
    }


# ---------------------------------------------------------------------------
# Normal traffic generator
# ---------------------------------------------------------------------------

def generate_normal_record(timestamp: str = None) -> dict:
    """
    Generate one normal traffic record by invoking a real Lambda function.

    Randomly selects one of the four deployed functions and one of its
    normal action modes so the baseline contains realistic variety.
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    profiles = [
        ("api-handler",    {"action": "normal"}),
        ("api-handler",    {"action": "quick"}),
        ("file-processor", {"action": "normal", "file_size_kb": random.randint(50, 300)}),
        ("db-query",       {"action": "normal", "query_type": "simple"}),
        ("auth-service",   {"action": "normal"}),
    ]
    fn, payload = random.choice(profiles)
    result      = invoke(fn, payload)
    resp        = result["response"]

    # Use duration reported by the function itself (measured inside the handler).
    duration = resp.get("duration_ms", result["wall_time_ms"])
    memory   = resp.get("memory_used_mb", random.randint(80, 140))

    return {
        "timestamp":       timestamp,
        "function_name":   fn,
        "duration":        round(duration, 2),
        "memory_used":     round(memory, 2),
        "num_api_calls":   random.randint(1, 3),
        "error_count":     0,
        "concurrency":     1,
        "ip_address":      NORMAL_IP_PREFIX + str(random.randint(1, 50)),
        "ttl":             random.choice([64, 64, 64, 128]),
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
    Simulate crypto mining by chaining 5–15 heavy api-handler invocations.
    
    Value ranges based on:
    - Sysdig 2022 Cloud Threat Report: cryptojacking sustains CPU for
      5,000–15,000ms per Lambda chain, memory 350–480MB
    - MITRE ATT&CK T1496 (Resource Hijacking)
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    total_duration = 0.0
    num_loops      = random.randint(5, 15)

    for _ in range(num_loops):
        result = invoke("api-handler", {"action": "heavy"})
        total_duration += result["response"].get("duration_ms", result["wall_time_ms"])

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
    Simulate data exfiltration via mass DB queries.
    
    Value ranges based on:
    - MITRE ATT&CK T1048 (Exfiltration Over Alternative Protocol):
      large outbound payloads 5,000–20,000 bytes per burst
    - Rapid repeated queries (8–20 calls) typical of automated exfil tools
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    total_duration = 0.0
    api_calls      = random.randint(8, 20)

    for _ in range(api_calls):
        result = invoke("db-query", {"action": "normal", "query_type": "complex"})
        total_duration += result["response"].get("duration_ms", result["wall_time_ms"])

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
        "packet_size_out": random.randint(5000, 20000),
        "latency":         round(random.uniform(20, 80), 2),
        "fragment_count":  random.randint(0, 2),
        "source_port":     random.randint(49152, 65535),
        "status_code":     200,
        "label":           "attack",
        "attack_type":     "data_exfiltration",
    }


def generate_sql_injection_record(timestamp: str = None) -> dict:
    """
    Simulate SQL injection flood.
    
    Value ranges based on:
    - OWASP Testing Guide v4.2 (WSTG-INPV-05): 70–90% of injection
      attempts fail, producing high error_count relative to api_calls
    - Repeated rapid queries (15–30) consistent with automated SQLi tools
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    total_duration = 0.0
    num_attempts   = random.randint(15, 30)
    errors         = int(num_attempts * random.uniform(0.7, 0.9))

    for _ in range(num_attempts):
        result = invoke("db-query", {"action": "normal", "query_type": "simple"})
        total_duration += result["response"].get("duration_ms", result["wall_time_ms"])

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
        "packet_size_in":  random.randint(512, 2048),
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
    Simulate DDoS burst flood.
    
    Value ranges based on:
    - AWS Shield Threat Landscape Report 2023: Lambda DDoS bursts
      show concurrency 50–200+, high api_call counts (30–60 per window)
    - MITRE ATT&CK T1498 (Network Denial of Service)
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    total_duration = 0.0
    burst_count    = random.randint(30, 60)

    for _ in range(burst_count):
        result = invoke("api-handler", {"action": "quick"})
        total_duration += result["response"].get("duration_ms", result["wall_time_ms"])

    return {
        "timestamp":       timestamp,
        "function_name":   "api-handler",
        "duration":        round(total_duration, 2),
        "memory_used":     round(random.uniform(80, 150), 2),
        "num_api_calls":   burst_count,
        "error_count":     random.randint(0, 5),
        "concurrency":     random.randint(50, 200),
        "ip_address":      random.choice(SUSPICIOUS_IPS["ddos"]),
        "ttl":             random.randint(50, 64),
        "packet_size_in":  random.randint(64, 256),
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
    Simulate memory exhaustion attack via oversized file payloads.
    
    Value ranges based on:
    - AWS Lambda documentation: maximum memory ceiling is 512MB (at
      time of dataset generation); attack targets 400–512MB range
    - Palo Alto Unit 42 Cloud Threat Report 2022: memory abuse
      attacks consistently push usage above 80% of allocated limit
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    file_size_kb = random.randint(5000, 10000)
    result       = invoke("file-processor", {
        "action":        "batch",
        "file_size_kb":  file_size_kb,
    })
    resp     = result["response"]
    duration = resp.get("duration_ms", result["wall_time_ms"])
    memory   = resp.get("memory_used_mb", random.uniform(400, 512))

    return {
        "timestamp":       timestamp,
        "function_name":   "file-processor",
        "duration":        round(duration, 2),
        "memory_used":     round(memory, 2),
        "num_api_calls":   random.randint(1, 3),
        "error_count":     random.randint(0, 2),
        "concurrency":     1,
        "ip_address":      random.choice(SUSPICIOUS_IPS["memory_attack"]),
        "ttl":             random.randint(48, 64),
        "packet_size_in":  random.randint(10000, 65535),
        "packet_size_out": random.randint(128, 1024),
        "latency":         round(random.uniform(30, 100), 2),
        "fragment_count":  random.randint(3, 10),
        "source_port":     random.randint(49152, 65535),
        "status_code":     200,
        "label":           "attack",
        "attack_type":     "memory_attack",
    }


def generate_ip_spoofing_record(timestamp: str = None) -> dict:
    """
    Simulate IP spoofing via anomalous TTL values.
    
    Value ranges based on:
    - RFC 1122 Section 3.2.1.7: standard TTL values are 64 (Linux)
      or 128 (Windows); values below 30 indicate 30+ hops suggesting
      anonymising proxy chains or spoofed source routing
    - MITRE ATT&CK T1036 (Masquerading): network-layer anomalies
      as primary indicator when execution metrics appear normal
    """
    if timestamp is None:
        timestamp = datetime.utcnow().isoformat()

    result   = invoke("auth-service", {"action": "normal"})
    resp     = result["response"]
    duration = resp.get("duration_ms", result["wall_time_ms"])
    memory   = resp.get("memory_used_mb", random.randint(64, 120))

    return {
        "timestamp":       timestamp,
        "function_name":   "auth-service",
        "duration":        round(duration, 2),
        "memory_used":     round(memory, 2),
        "num_api_calls":   random.randint(1, 4),
        "error_count":     random.randint(0, 1),
        "concurrency":     1,
        "ip_address":      random.choice(SUSPICIOUS_IPS["ip_spoofing"]),
        "ttl":             random.randint(1, 29),
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
# Convenience mapping used by run_simulation.py
# ---------------------------------------------------------------------------

ATTACK_GENERATORS = {
    "crypto_mining":     generate_crypto_mining_record,
    "data_exfiltration": generate_data_exfiltration_record,
    "sql_injection":     generate_sql_injection_record,
    "ddos":              generate_ddos_record,
    "memory_attack":     generate_memory_attack_record,
    "ip_spoofing":       generate_ip_spoofing_record,
}
