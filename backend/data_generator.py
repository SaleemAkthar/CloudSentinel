"""
Cloud Sentinel — Synthetic Log Generator
==========================================
Generates realistic normal and attack traffic for testing the detection pipeline.

Normal traffic variations: standard, quick, heavy, batch, peak, night
Attack types (6): crypto_mining, data_exfiltration, sql_injection,
                  ddos, memory_attack, ip_spoofing
"""

import random
from datetime import datetime, timedelta
import numpy as np
from typing import Dict, List


# ---------------------------------------------------------------------------
# Normal traffic baseline ranges
# ---------------------------------------------------------------------------

NORMAL_RANGES = {
    'duration':       {'mean': 500, 'std': 80, 'min': 300, 'max': 800},
    'memory_used':    {'mean': 130, 'std': 20, 'min': 80, 'max': 200},
    'memory_size':    512,
    'num_api_calls':  {'mean': 3, 'std': 1, 'min': 1, 'max': 6},
    'num_db_calls':   {'mean': 1, 'std': 1, 'min': 0, 'max': 3},
    'num_s3_calls':   {'mean': 1, 'std': 0.5, 'min': 0, 'max': 2},
    'num_http_calls': {'mean': 0, 'std': 0.5, 'min': 0, 'max': 2},
}

FUNCTION_TYPES = [
    'process_payment', 'send_email', 'generate_report',
    'validate_user', 'update_database', 'fetch_data',
]

BUSY_HOURS  = range(9, 18)
NIGHT_HOURS = list(range(0, 6)) + list(range(22, 24))


# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

def clamp(value: float, min_val: float, max_val: float) -> float:
    """Keep value within min/max range."""
    return max(min_val, min(max_val, value))


def generate_realistic_value(config: dict) -> int:
    """Generate a value from a Gaussian distribution, clamped to configured range."""
    value = np.random.normal(config['mean'], config['std'])
    return int(clamp(value, config['min'], config['max']))


def is_busy_time(timestamp: datetime) -> bool:
    return timestamp.hour in BUSY_HOURS


def is_night_time(timestamp: datetime) -> bool:
    return timestamp.hour in NIGHT_HOURS


# ---------------------------------------------------------------------------
# Normal log generation
# ---------------------------------------------------------------------------

def generate_normal_log(timestamp: datetime, variation: str = 'standard') -> Dict:
    """Generate a normal Lambda execution log with realistic variation."""
    duration       = generate_realistic_value(NORMAL_RANGES['duration'])
    memory_used    = generate_realistic_value(NORMAL_RANGES['memory_used'])
    num_db_calls   = generate_realistic_value(NORMAL_RANGES['num_db_calls'])
    num_s3_calls   = generate_realistic_value(NORMAL_RANGES['num_s3_calls'])
    num_http_calls = generate_realistic_value(NORMAL_RANGES['num_http_calls'])

    if variation == 'quick':
        duration     = int(duration * 0.5)
        memory_used  = int(memory_used * 0.8)
        num_db_calls = max(0, num_db_calls - 1)
    elif variation == 'heavy':
        duration     = int(duration * 1.5)
        memory_used  = int(memory_used * 1.3)
        num_db_calls = min(5, num_db_calls + 2)
        num_s3_calls = min(3, num_s3_calls + 1)
    elif variation == 'batch':
        duration     = int(duration * 1.8)
        memory_used  = int(memory_used * 1.4)
        num_db_calls = min(6, num_db_calls + 3)
    elif variation == 'peak':
        if is_busy_time(timestamp):
            duration    = int(duration * 1.2)
            memory_used = int(memory_used * 1.1)
    elif variation == 'night':
        if is_night_time(timestamp):
            duration = int(duration * 0.85)

    total_api_calls = num_db_calls + num_s3_calls + num_http_calls

    api_calls = []
    api_calls.extend(['dynamodb:GetItem'] * num_db_calls)
    api_calls.extend(['s3:GetObject'] * num_s3_calls)
    api_calls.extend(['https:GET'] * num_http_calls)

    return {
        'timestamp':    timestamp.isoformat(),
        'requestId':    f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration':     max(100, duration),
        'memoryUsed':   max(50, memory_used),
        'memorySize':   NORMAL_RANGES['memory_size'],
        'statusCode':   200,
        'apiCalls':     api_calls,
        'errorMessage': None,
        'variation':    variation,
    }


# ---------------------------------------------------------------------------
# Attack generators — one function per attack type
# ---------------------------------------------------------------------------

def generate_crypto_mining_attack(timestamp: datetime) -> Dict:
    """Crypto mining: extreme duration + high memory, minimal API calls."""
    return {
        'timestamp':    timestamp.isoformat(),
        'requestId':    f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration':     int(np.random.uniform(8000, 20000)),
        'memoryUsed':   int(np.random.uniform(400, 500)),
        'memorySize':   NORMAL_RANGES['memory_size'],
        'statusCode':   200,
        'apiCalls':     ['dynamodb:GetItem'],
        'errorMessage': None,
        'attack_type':  'crypto_mining',
    }


def generate_data_exfiltration_attack(timestamp: datetime) -> Dict:
    """Data exfiltration: many uploads, large outbound data."""
    num_s3_uploads = int(np.random.uniform(15, 30))
    num_http_calls = int(np.random.uniform(0, 5))

    api_calls = []
    api_calls.extend(['s3:PutObject'] * num_s3_uploads)
    api_calls.extend(['https:POST'] * num_http_calls)
    api_calls.extend(['dynamodb:GetItem'] * random.randint(1, 3))

    return {
        'timestamp':    timestamp.isoformat(),
        'requestId':    f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration':     int(np.random.uniform(1500, 3000)),
        'memoryUsed':   int(np.random.uniform(150, 250)),
        'memorySize':   NORMAL_RANGES['memory_size'],
        'statusCode':   200,
        'apiCalls':     api_calls,
        'errorMessage': None,
        'attack_type':  'data_exfiltration',
    }


def generate_sql_injection_attack(timestamp: datetime) -> Dict:
    """SQL injection: many failed DB queries, high error rate."""
    num_db_queries = int(np.random.uniform(15, 25))
    has_error = random.random() < 0.8

    error_messages = [
        'Database error: syntax error near SELECT',
        'DynamoDB: ValidationException',
        'Query failed: invalid parameter',
        'Database timeout: too many requests',
        'SQL syntax error: unexpected token',
    ]

    return {
        'timestamp':    timestamp.isoformat(),
        'requestId':    f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration':     int(np.random.uniform(400, 800)),
        'memoryUsed':   int(np.random.uniform(100, 180)),
        'memorySize':   NORMAL_RANGES['memory_size'],
        'statusCode':   500 if has_error else 200,
        'apiCalls':     ['dynamodb:Query'] * num_db_queries,
        'errorMessage': random.choice(error_messages) if has_error else None,
        'attack_type':  'sql_injection',
    }


def generate_memory_leak_attack(timestamp: datetime) -> Dict:
    """Memory attack: memory near Lambda limit, possible OOM errors."""
    memory_used  = int(np.random.uniform(480, 512))
    caused_error = memory_used >= 500

    return {
        'timestamp':    timestamp.isoformat(),
        'requestId':    f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration':     int(np.random.uniform(600, 1200)),
        'memoryUsed':   memory_used,
        'memorySize':   NORMAL_RANGES['memory_size'],
        'statusCode':   500 if caused_error else 200,
        'apiCalls':     ['dynamodb:Query'] * random.randint(1, 3),
        'errorMessage': 'Runtime.OutOfMemory: Memory limit exceeded' if caused_error else None,
        'attack_type':  'memory_attack',
    }


def generate_ddos_attack(timestamp: datetime) -> Dict:
    """DDoS: high repeated API calls, often times out."""
    call_type          = random.choice(['dynamodb:Query', 's3:GetObject', 'https:GET'])
    num_repeated_calls = int(np.random.uniform(30, 60))
    timed_out          = random.random() < 0.3

    return {
        'timestamp':    timestamp.isoformat(),
        'requestId':    f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration':     int(np.random.uniform(5000, 10000)) if not timed_out else 29000,
        'memoryUsed':   int(np.random.uniform(150, 250)),
        'memorySize':   NORMAL_RANGES['memory_size'],
        'statusCode':   504 if timed_out else 200,
        'apiCalls':     [call_type] * num_repeated_calls,
        'errorMessage': 'Task timed out after 29.00 seconds' if timed_out else None,
        'attack_type':  'ddos_loop',
    }


def generate_ip_spoofing_attack(timestamp: datetime) -> Dict:
    """
    IP spoofing: forged source IP, impossible TTL values, packet fragmentation.
    Execution metrics look normal — the IP metadata is what's suspicious.
    """
    spoofed_ips = [
        '10.0.0.1', '172.16.0.100', '192.168.1.1',
        '5.34.178.52', '31.13.80.10', '185.220.101.42', '45.155.205.10',
    ]
    suspicious_ttls = [0, 1, 3, 250, 254, 17, 33]

    duration      = int(np.random.uniform(200, 600))
    memory_used   = int(np.random.uniform(100, 160))
    num_api_calls = random.randint(2, 8)
    fragment_count = random.randint(2, 6)

    api_calls = ['dynamodb:Query'] * min(num_api_calls, 3)
    if num_api_calls > 3:
        api_calls.extend(['s3:GetObject'] * (num_api_calls - 3))

    return {
        'timestamp':      timestamp.isoformat(),
        'requestId':      f'req-{random.randint(100000, 999999):06d}',
        'functionName':   random.choice(FUNCTION_TYPES),
        'duration':       duration,
        'memoryUsed':     memory_used,
        'memorySize':     NORMAL_RANGES['memory_size'],
        'statusCode':     200,
        'apiCalls':       api_calls,
        'errorMessage':   None,
        'attack_type':    'ip_spoofing',
        'ip_address':     random.choice(spoofed_ips),
        'ttl':            random.choice(suspicious_ttls),
        'source_port':    random.randint(1, 1023),
        'fragment_count': fragment_count,
    }


# ---------------------------------------------------------------------------
# Main generator class
# ---------------------------------------------------------------------------

class EnhancedLogGenerator:
    """Generates mixed normal + attack traffic with configurable attack rate."""

    def __init__(self, attack_rate: float = 0.08):
        self.attack_rate   = attack_rate
        self.request_count = 0
        self.start_time    = datetime.now() - timedelta(hours=2)
        self.stats = {
            'total': 0, 'normal': 0, 'attacks': 0, 'attack_types': {},
        }

    def generate_log(self) -> Dict:
        """Generate one log entry (normal or attack based on attack_rate)."""
        self.request_count += 1
        self.stats['total'] += 1

        time_increment = random.randint(100, 1000)
        current_time = self.start_time + timedelta(
            milliseconds=self.request_count * time_increment
        )

        is_attack = random.random() < self.attack_rate

        if is_attack:
            log = self._generate_attack(current_time)
            self.stats['attacks'] += 1
            attack_type = log.get('attack_type', 'unknown')
            self.stats['attack_types'][attack_type] = (
                self.stats['attack_types'].get(attack_type, 0) + 1
            )
        else:
            log = self._generate_normal_with_variation(current_time)
            self.stats['normal'] += 1

        return log

    def _generate_normal_with_variation(self, timestamp: datetime) -> Dict:
        """Pick a variation based on weighted probability."""
        rand = random.random()
        if rand < 0.50:
            variation = 'standard'
        elif rand < 0.70:
            variation = 'quick'
        elif rand < 0.85:
            variation = 'heavy'
        elif rand < 0.95:
            variation = 'batch'
        else:
            variation = 'peak' if is_busy_time(timestamp) else 'night'

        return generate_normal_log(timestamp, variation)

    def _generate_attack(self, timestamp: datetime) -> Dict:
        """
        Generate an attack log — 6 types with weighted probabilities:
            25% Crypto Mining, 25% Data Exfiltration, 20% SQL Injection,
            10% DDoS, 10% Memory Attack, 10% IP Spoofing
        """
        rand = random.random()
        if rand < 0.25:
            return generate_crypto_mining_attack(timestamp)
        elif rand < 0.50:
            return generate_data_exfiltration_attack(timestamp)
        elif rand < 0.70:
            return generate_sql_injection_attack(timestamp)
        elif rand < 0.80:
            return generate_ddos_attack(timestamp)
        elif rand < 0.90:
            return generate_memory_leak_attack(timestamp)
        else:
            return generate_ip_spoofing_attack(timestamp)

    def generate_batch(self, count: int = 100) -> List[Dict]:
        """Generate multiple logs at once."""
        return [self.generate_log() for _ in range(count)]

    def generate_scenario(self, scenario_name: str, count: int = 100) -> List[Dict]:
        """
        Generate a named test scenario:
            normal_day, under_attack, light_attack,
            crypto_wave, data_breach, mixed
        """
        old_rate = self.attack_rate

        if scenario_name == 'normal_day':
            self.attack_rate = 0.0
            logs = self.generate_batch(count)
        elif scenario_name == 'under_attack':
            self.attack_rate = 0.30
            logs = self.generate_batch(count)
        elif scenario_name == 'light_attack':
            self.attack_rate = 0.05
            logs = self.generate_batch(count)
        elif scenario_name == 'crypto_wave':
            logs = []
            for _ in range(count):
                ts = self.start_time + timedelta(seconds=len(logs))
                if random.random() < 0.25:
                    logs.append(generate_crypto_mining_attack(ts))
                else:
                    logs.append(generate_normal_log(ts))
        elif scenario_name == 'data_breach':
            logs = []
            for _ in range(count):
                ts = self.start_time + timedelta(seconds=len(logs))
                if random.random() < 0.20:
                    logs.append(generate_data_exfiltration_attack(ts))
                else:
                    logs.append(generate_normal_log(ts))
        else:
            logs = self.generate_batch(count)

        self.attack_rate = old_rate
        return logs

    def get_statistics(self) -> Dict:
        """Return generation statistics."""
        total = self.stats['total']
        attack_rate = (self.stats['attacks'] / max(total, 1)) * 100
        return {
            'total_generated':   total,
            'normal_logs':       self.stats['normal'],
            'attack_logs':       self.stats['attacks'],
            'actual_attack_rate': f"{attack_rate:.2f}%",
            'attack_breakdown':  self.stats['attack_types'],
        }

    def print_statistics(self):
        """Print a summary of what was generated."""
        stats = self.get_statistics()
        print("=" * 60)
        print("LOG GENERATION STATISTICS")
        print("=" * 60)
        print(f"Total Logs Generated:  {stats['total_generated']}")
        print(f"Normal Logs:           {stats['normal_logs']}")
        print(f"Attack Logs:           {stats['attack_logs']}")
        print(f"Actual Attack Rate:    {stats['actual_attack_rate']}")
        if stats['attack_breakdown']:
            print("\nAttack Type Breakdown:")
            for attack_type, count in sorted(stats['attack_breakdown'].items()):
                print(f"  {attack_type:20s}: {count:3d}")
        print("=" * 60)


# ---------------------------------------------------------------------------
# Backwards-compatible convenience function
# ---------------------------------------------------------------------------

def generate_test_data(num_logs: int = 100, attack_rate: float = 0.08) -> List[Dict]:
    """Generate test logs (drop-in replacement for old code)."""
    generator = EnhancedLogGenerator(attack_rate=attack_rate)
    return generator.generate_batch(num_logs)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("ENHANCED DATA GENERATOR TEST")
    print("=" * 70)

    # Test 1: Mixed traffic
    print("\nTest 1: Mixed Traffic (100 logs, 10% attack rate)")
    print("-" * 70)
    generator = EnhancedLogGenerator(attack_rate=0.10)
    logs = generator.generate_batch(100)

    print("\nFirst 5 logs:")
    for i, log in enumerate(logs[:5]):
        print(f"\nLog {i+1}:")
        print(f"  Type: {'ATTACK' if 'attack_type' in log else 'Normal'}")
        if 'attack_type' in log:
            print(f"  Attack: {log['attack_type']}")
        elif 'variation' in log:
            print(f"  Variation: {log['variation']}")
        print(f"  Duration: {log['duration']}ms")
        print(f"  Memory: {log['memoryUsed']}MB")
        print(f"  API Calls: {len(log['apiCalls'])}")
        if log.get('errorMessage'):
            print(f"  Error: {log['errorMessage']}")

    generator.print_statistics()

    # Test 2: Scenarios
    print("\n" + "=" * 70)
    print("Test 2: Different Scenarios")
    print("-" * 70)
    for scenario in ['normal_day', 'under_attack', 'crypto_wave', 'data_breach']:
        gen = EnhancedLogGenerator()
        logs = gen.generate_scenario(scenario, 50)
        attacks = sum(1 for log in logs if 'attack_type' in log)
        print(f"\n{scenario:15s}: {attacks:2d}/50 attacks ({attacks/50*100:.0f}%)")

    # Test 3: One of each attack type
    print("\n" + "=" * 70)
    print("Test 3: Sample of Each Attack Type")
    print("-" * 70)
    timestamp = datetime.now()
    attack_generators = [
        ('Crypto Mining',      generate_crypto_mining_attack),
        ('Data Exfiltration',  generate_data_exfiltration_attack),
        ('SQL Injection',      generate_sql_injection_attack),
        ('DDoS',               generate_ddos_attack),
        ('Memory Attack',      generate_memory_leak_attack),
        ('IP Spoofing',        generate_ip_spoofing_attack),
    ]
    for name, func in attack_generators:
        log = func(timestamp)
        print(f"\n{name}:")
        print(f"  Duration: {log['duration']}ms")
        print(f"  Memory: {log['memoryUsed']}MB")
        print(f"  Status: {log['statusCode']}")
        print(f"  API Calls: {len(log['apiCalls'])}")
        print(f"  Attack Type: {log['attack_type']}")
        if log.get('errorMessage'):
            print(f"  Error: {log['errorMessage'][:50]}...")
        if log.get('ip_address'):
            print(f"  IP: {log['ip_address']}")
        if log.get('ttl'):
            print(f"  TTL: {log['ttl']}")

    print("\n" + "=" * 70)
    print("ALL TESTS COMPLETE!")
    print("=" * 70)