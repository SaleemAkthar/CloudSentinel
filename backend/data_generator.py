import random
from datetime import datetime, timedelta
import numpy as np
from typing import Dict, List, Optional
from .severity_classifier import SeverityClassifier


# what healthy traffic looks like
NORMAL_RANGES = {
    'duration': {'mean': 500, 'std': 80, 'min': 300, 'max': 800},
    'memory_used': {'mean': 130, 'std': 20, 'min': 80, 'max': 200},
    'memory_size': 512,  # Always 512MB allocated
    'num_api_calls': {'mean': 3, 'std': 1, 'min': 1, 'max': 6},
    'num_db_calls': {'mean': 1, 'std': 1, 'min': 0, 'max': 3},
    'num_s3_calls': {'mean': 1, 'std': 0.5, 'min': 0, 'max': 2},
    'num_http_calls': {'mean': 0, 'std': 0.5, 'min': 0, 'max': 2},
}

# what our serverless app does
FUNCTION_TYPES = [
    'process_payment',
    'send_email',
    'generate_report',
    'validate_user',
    'update_database',
    'fetch_data'
]

# Time-based patterns (when requests happen)
BUSY_HOURS = range(9, 18)  # 9 AM - 6 PM
NIGHT_HOURS = list(range(0, 6)) + list(range(22, 24))  # 10 PM - 6 AM



# Functions to make it easier to code and keep it organized 
def clamp(value: float, min_val: float, max_val: float) -> float:
    """Keep value within min and max range"""
    return max(min_val, min(max_val, value))


def generate_realistic_value(config: dict) -> int:
    """
    Generate realistic value using Gaussian distribution
    Ensures value stays within min/max bounds
    """
    value = np.random.normal(config['mean'], config['std'])
    return int(clamp(value, config['min'], config['max']))


def get_hour_from_timestamp(timestamp: datetime) -> int:
    """Extract hour from timestamp"""
    return timestamp.hour


def is_busy_time(timestamp: datetime) -> bool:
    """Check if timestamp is during busy hours"""
    return get_hour_from_timestamp(timestamp) in BUSY_HOURS


def is_night_time(timestamp: datetime) -> bool:
    """Check if timestamp is during night hours"""
    return get_hour_from_timestamp(timestamp) in NIGHT_HOURS



# NORMAL LOG GENERATION (Different Variations)
def generate_normal_log(timestamp: datetime, variation: str = 'standard') -> Dict:
    # Base values
    duration = generate_realistic_value(NORMAL_RANGES['duration'])
    memory_used = generate_realistic_value(NORMAL_RANGES['memory_used'])
    num_db_calls = generate_realistic_value(NORMAL_RANGES['num_db_calls'])
    num_s3_calls = generate_realistic_value(NORMAL_RANGES['num_s3_calls'])
    num_http_calls = generate_realistic_value(NORMAL_RANGES['num_http_calls'])
    
    # variations of normal 
    if variation == 'quick':
        # Fast operations (cached data, simple queries)
        duration = int(duration * 0.5)  # 50% faster
        memory_used = int(memory_used * 0.8)
        num_db_calls = max(0, num_db_calls - 1)
        
    elif variation == 'heavy': # Legitimate heavy operations (reports, complex queries)
        duration = int(duration * 1.5)  # 50% slower (still normal)
        memory_used = int(memory_used * 1.3)
        num_db_calls = min(5, num_db_calls + 2)
        num_s3_calls = min(3, num_s3_calls + 1)
        
    elif variation == 'batch': # Batch processing (multiple items at once)
        duration = int(duration * 1.8)
        memory_used = int(memory_used * 1.4)
        num_db_calls = min(6, num_db_calls + 3)
        
    elif variation == 'peak': # Peak hour traffic (slight slowdown from load)
        if is_busy_time(timestamp):
            duration = int(duration * 1.2)
            memory_used = int(memory_used * 1.1)
            
    elif variation == 'night': # Night time (faster, less competition)
        if is_night_time(timestamp):
            duration = int(duration * 0.85)
    
    # Total API calls
    total_api_calls = num_db_calls + num_s3_calls + num_http_calls
    
    # Build all API call list
    api_calls = []
    api_calls.extend(['dynamodb:GetItem'] * num_db_calls)
    api_calls.extend(['s3:GetObject'] * num_s3_calls)
    api_calls.extend(['https:GET'] * num_http_calls)
    
    return {
        'timestamp': timestamp.isoformat(),
        'requestId': f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration': max(100, duration),  # Min 100ms
        'memoryUsed': max(50, memory_used),  # Min 50MB
        'memorySize': NORMAL_RANGES['memory_size'],
        'statusCode': 200,
        'apiCalls': api_calls,
        'errorMessage': None,
        'variation': variation
    }



# ANOMALY GENERATION (Different Attack Types)
def generate_crypto_mining_attack(timestamp: datetime) -> Dict:
    return {
        'timestamp': timestamp.isoformat(),
        'requestId': f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration': int(np.random.uniform(8000, 20000)),  # 8-20 seconds!
        'memoryUsed': int(np.random.uniform(400, 500)),   # Near max memory
        'memorySize': NORMAL_RANGES['memory_size'],
        'statusCode': 200,  # Looks successful to hide
        'apiCalls': ['dynamodb:GetItem'],  # Minimal calls to avoid suspicion
        'errorMessage': None,
        'attack_type': 'crypto_mining'
    }


def generate_data_exfiltration_attack(timestamp: datetime) -> Dict:
    num_s3_uploads = int(np.random.uniform(15, 30))  # Excessive uploads
    num_http_calls = int(np.random.uniform(0, 5))    # External transfers
    
    api_calls = []
    api_calls.extend(['s3:PutObject'] * num_s3_uploads)
    api_calls.extend(['https:POST'] * num_http_calls)
    api_calls.extend(['dynamodb:GetItem'] * random.randint(1, 3))  # Reading data
    
    return {
        'timestamp': timestamp.isoformat(),
        'requestId': f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration': int(np.random.uniform(1500, 3000)),   # Bit slower (transferring)
        'memoryUsed': int(np.random.uniform(150, 250)),   # Normal-ish memory
        'memorySize': NORMAL_RANGES['memory_size'],
        'statusCode': 200,
        'apiCalls': api_calls,
        'errorMessage': None,
        'attack_type': 'data_exfiltration'
    }


def generate_sql_injection_attack(timestamp: datetime) -> Dict:
    num_db_queries = int(np.random.uniform(15, 25))  # Many failed attempts
    has_error = random.random() < 0.8  # 80% chance of error
    
    api_calls = ['dynamodb:Query'] * num_db_queries
    
    error_messages = [
        'Database error: syntax error near SELECT',
        'DynamoDB: ValidationException',
        'Query failed: invalid parameter',
        'Database timeout: too many requests',
        'SQL syntax error: unexpected token'
    ]
    
    return {
        'timestamp': timestamp.isoformat(),
        'requestId': f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration': int(np.random.uniform(400, 800)),
        'memoryUsed': int(np.random.uniform(100, 180)),
        'memorySize': NORMAL_RANGES['memory_size'],
        'statusCode': 500 if has_error else 200,
        'apiCalls': api_calls,
        'errorMessage': random.choice(error_messages) if has_error else None,
        'attack_type': 'sql_injection'
    }


# def generate_ssrf_attack(timestamp: datetime) -> Dict:
#     num_http_calls = int(np.random.uniform(6, 15))  # Excessive external calls
#
#     api_calls = ['https:GET'] * num_http_calls
#     api_calls.extend(['dynamodb:GetItem'] * random.randint(0, 2))
#
#     return {
#         'timestamp': timestamp.isoformat(),
#         'requestId': f'req-{random.randint(100000, 999999):06d}',
#         'functionName': random.choice(FUNCTION_TYPES),
#         'duration': int(np.random.uniform(1000, 2000)),
#         'memoryUsed': int(np.random.uniform(120, 180)),
#         'memorySize': NORMAL_RANGES['memory_size'],
#         'statusCode': 200,
#         'apiCalls': api_calls,
#         'errorMessage': None,
#         'attack_type': 'ssrf_attempt'
#     }


def generate_memory_leak_attack(timestamp: datetime) -> Dict:
    """
    MEMORY LEAK / MEMORY BOMB ATTACK
    
    What it is: Attacker causing excessive memory allocation
    
    Characteristics:
    - VERY high memory usage (near or at limit)
    - Normal or slightly high duration
    - May cause out-of-memory errors
    """
    
    memory_used = int(np.random.uniform(480, 512))  # Near maximum!
    caused_error = memory_used >= 500
    
    return {
        'timestamp': timestamp.isoformat(),
        'requestId': f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration': int(np.random.uniform(600, 1200)),
        'memoryUsed': memory_used,
        'memorySize': NORMAL_RANGES['memory_size'],
        'statusCode': 500 if caused_error else 200,
        'apiCalls': ['dynamodb:Query'] * random.randint(1, 3),
        'errorMessage': 'Runtime.OutOfMemory: Memory limit exceeded' if caused_error else None,
        'attack_type': 'memory_attack'
    }


def generate_ddos_attack(timestamp: datetime) -> Dict:
    """
    DDoS / INFINITE LOOP ATTACK
    
    What it is: Function stuck in loop or performing repeated operations
    
    Characteristics:
    - High duration (stuck)
    - MANY repeated API calls
    - Often times out
    """
    
    # Repeated API call pattern
    call_type = random.choice(['dynamodb:Query', 's3:GetObject', 'https:GET'])
    num_repeated_calls = int(np.random.uniform(30, 60))
    
    timed_out = random.random() < 0.3  # 30% chance of timeout
    
    return {
        'timestamp': timestamp.isoformat(),
        'requestId': f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration': int(np.random.uniform(5000, 10000)) if not timed_out else 29000,  # Near timeout
        'memoryUsed': int(np.random.uniform(150, 250)),
        'memorySize': NORMAL_RANGES['memory_size'],
        'statusCode': 504 if timed_out else 200,  # Gateway timeout
        'apiCalls': [call_type] * num_repeated_calls,
        'errorMessage': 'Task timed out after 29.00 seconds' if timed_out else None,
        'attack_type': 'ddos_loop'
    }

    def generate_ip_spoofing_attack(timestamp):
    """
    IP SPOOFING ATTACK
    
    What it is: Attacker disguises their real IP address to bypass security,
    hide identity, or impersonate a trusted source.
    
    Detection signals (used by Layer 2 ip_spoofing pattern):
    - Impossible TTL values (0, 1, 250, 254 — not matching any real OS)
    - Private IP appearing from public internet
    - Low source port (below 1024 — unusual for client traffic)
    - Packet fragmentation (fragments used to evade detection)
    - Otherwise normal-looking request (attacker hides in plain sight)
    
    Characteristics:
    - Normal or slightly elevated duration (not the giveaway)
    - Normal memory usage (not the giveaway)
    - Low-moderate API calls
    - The IP metadata is what's suspicious, not the execution metrics
    
    References:
    - OWASP: IP Spoofing is used in DDoS amplification and session hijacking
    - Layer 2 detection: TTL analysis, geolocation jumps, private IP checks
    """
    
    # Spoofed IP addresses — mix of private IPs that shouldn't come from
    # public internet, and known suspicious ranges
    spoofed_ips = [
        '10.0.0.1',          # Private IP from "public" internet
        '172.16.0.100',      # Private IP from "public" internet
        '192.168.1.1',       # Private IP from "public" internet
        '5.34.178.52',       # Known suspicious range (Russia)
        '31.13.80.10',       # Spoofing a Meta/Facebook IP
        '185.220.101.42',    # Tor exit node range
        '45.155.205.10',     # Known bulletproof hosting
    ]
    
    # Impossible or suspicious TTL values
    # Normal: 64 (Linux), 128 (Windows), 255 (Cisco)
    # Suspicious: 0, 1, 3, 250, 254 — no real OS uses these
    suspicious_ttls = [0, 1, 3, 250, 254, 17, 33]
    
    # Low source ports (below 1024) are suspicious for client traffic
    # Normal clients use ephemeral ports (49152-65535)
    suspicious_source_port = random.randint(1, 1023)
    
    # The execution itself looks fairly normal — spoofing is about
    # the network metadata, not the Lambda behavior
    duration = int(np.random.uniform(200, 600))
    memory_used = int(np.random.uniform(100, 160))
    num_api_calls = random.randint(2, 8)
    
    # Some fragmentation (used to evade packet inspection)
    fragment_count = random.randint(2, 6)
    
    api_calls = ['dynamodb:Query'] * min(num_api_calls, 3)
    if num_api_calls > 3:
        api_calls.extend(['s3:GetObject'] * (num_api_calls - 3))
    
    return {
        'timestamp': timestamp.isoformat(),
        'requestId': f'req-{random.randint(100000, 999999):06d}',
        'functionName': random.choice(FUNCTION_TYPES),
        'duration': duration,
        'memoryUsed': memory_used,
        'memorySize': NORMAL_RANGES['memory_size'],
        'statusCode': 200,
        'apiCalls': api_calls,
        'errorMessage': None,
        'attack_type': 'ip_spoofing',
        # Extra metadata for Layer 2 IP analysis
        'ip_address': random.choice(spoofed_ips),
        'ttl': random.choice(suspicious_ttls),
        'source_port': suspicious_source_port,
        'fragment_count': fragment_count,
    }


# def generate_error_spike_attack(timestamp: datetime) -> Dict:
#     """
#     ERROR SPIKE ATTACK
#
#     What it is: Deliberate triggering of errors to disrupt service
#
#     Characteristics:
#     - Status 400/500 errors
#     - Error messages
#     - Normal duration (fails fast)
#     """
#
#     error_types = [
#         {'code': 400, 'message': 'Bad Request: Missing required parameter'},
#         {'code': 401, 'message': 'Unauthorized: Invalid credentials'},
#         {'code': 403, 'message': 'Forbidden: Access denied'},
#         {'code': 500, 'message': 'Internal Server Error'},
#         {'code': 502, 'message': 'Bad Gateway: Upstream connection failed'},
#     ]
#
#     error = random.choice(error_types)
#
#     return {
#         'timestamp': timestamp.isoformat(),
#         'requestId': f'req-{random.randint(100000, 999999):06d}',
#         'functionName': random.choice(FUNCTION_TYPES),
#         'duration': int(np.random.uniform(200, 500)),  # Fast failures
#         'memoryUsed': int(np.random.uniform(80, 150)),
#         'memorySize': NORMAL_RANGES['memory_size'],
#         'statusCode': error['code'],
#         'apiCalls': ['dynamodb:GetItem'] * random.randint(0, 2),
#         'errorMessage': error['message'],
#         'attack_type': 'error_spike'
#     }


# def generate_suspicious_timing_attack(timestamp: datetime) -> Dict:
#     """
#     SUSPICIOUS TIMING ATTACK
#
#     What it is: Unusual activity during off-hours
#
#     Characteristics:
#     - Happens at night (2-5 AM)
#     - Otherwise normal-looking
#     - But context is suspicious
#     """
#
#     # Make it happen at night
#     night_hour = random.randint(2, 5)
#     suspicious_timestamp = timestamp.replace(hour=night_hour)
#
#     return {
#         'timestamp': suspicious_timestamp.isoformat(),
#         'requestId': f'req-{random.randint(100000, 999999):06d}',
#         'functionName': random.choice(FUNCTION_TYPES),
#         'duration': int(np.random.uniform(400, 800)),
#         'memoryUsed': int(np.random.uniform(120, 180)),
#         'memorySize': NORMAL_RANGES['memory_size'],
#         'statusCode': 200,
#         'apiCalls': ['dynamodb:Query'] * random.randint(2, 5),
#         'errorMessage': None,
#         'attack_type': 'suspicious_timing'
#     }


# MAIN GENERATOR CLASS
class EnhancedLogGenerator:

    def __init__(self, attack_rate: float = 0.08):
        """
        Initialize generator
        
        Args:
            attack_rate: Probability of attack (0.08 = 8% attacks, 92% normal)
        """
        self.attack_rate = attack_rate
        self.request_count = 0
        self.start_time = datetime.now() - timedelta(hours=2)
        
        # Track what we've generated (for statistics)
        self.stats = {
            'total': 0,
            'normal': 0,
            'attacks': 0,
            'attack_types': {}
        }
    
    def generate_log(self) -> Dict:
        """
        Generate next log (normal or attack)
        
        Returns:
            Log dictionary
        """
        self.request_count += 1
        self.stats['total'] += 1
        
        # Calculate timestamp
        time_increment = random.randint(100, 1000)  # 0.1-1 second between requests
        current_time = self.start_time + timedelta(milliseconds=self.request_count * time_increment)
        
        # Decide: Normal or Attack?
        is_attack = random.random() < self.attack_rate
        
        if is_attack:
            # Generate attack
            log = self._generate_attack(current_time)
            self.stats['attacks'] += 1
            attack_type = log.get('attack_type', 'unknown')
            self.stats['attack_types'][attack_type] = self.stats['attack_types'].get(attack_type, 0) + 1
        else:
            # Generate normal log with variation
            log = self._generate_normal_with_variation(current_time)
            self.stats['normal'] += 1
        
        return log
    
    def _generate_normal_with_variation(self, timestamp: datetime) -> Dict:
        """
        Generate normal log with realistic variation
        
        Variations chosen based on probability:
        - 50% standard
        - 20% quick (cached/simple)
        - 15% heavy (reports/complex)
        - 10% batch
        - 5% peak/night adjusted
        """
        
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
    
     def _generate_attack(self, timestamp):
        """
        Generate attack log — 6 attack types matching Layer 2 and frontend
        
        Attack type probabilities:
        - 25% Crypto Mining    (most dangerous, highest duration/memory)
        - 25% Data Exfiltration (high API calls, large outbound — includes SSRF patterns)
        - 20% SQL Injection    (high errors, many DB queries — includes error spike patterns)
        - 10% DDoS             (high concurrency, repeated calls — includes suspicious timing)
        - 10% Memory Attack    (extreme memory usage, near limit)
        - 10% IP Spoofing      (TTL mismatch, impossible travel, private IP from public)
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
        """
        Generate multiple logs at once
        
        Args:
            count: Number of logs to generate
            
        Returns:
            List of log dictionaries
        """
        return [self.generate_log() for _ in range(count)]
    
    def generate_scenario(self, scenario_name: str, count: int = 100) -> List[Dict]:
        """
        Generate specific test scenarios
        
        Scenarios:
        - 'normal_day': Only normal traffic (0% attacks)
        - 'under_attack': High attack rate (30% attacks)
        - 'light_attack': Low attack rate (5% attacks)
        - 'crypto_wave': Mostly crypto mining attacks
        - 'data_breach': Mostly data exfiltration
        - 'mixed': Normal mix (default attack rate)
        """
        
        old_rate = self.attack_rate
        
        if scenario_name == 'normal_day':
            # No attacks - peaceful day
            self.attack_rate = 0.0
            logs = self.generate_batch(count)
            
        elif scenario_name == 'under_attack':
            # Heavy attack - 30% attack rate
            self.attack_rate = 0.30
            logs = self.generate_batch(count)
            
        elif scenario_name == 'light_attack':
            # Light attack - 5% attack rate
            self.attack_rate = 0.05
            logs = self.generate_batch(count)
            
        elif scenario_name == 'crypto_wave':
            # Crypto mining wave
            logs = []
            for _ in range(count):
                if random.random() < 0.25:  # 25% crypto attacks
                    timestamp = self.start_time + timedelta(seconds=len(logs))
                    logs.append(generate_crypto_mining_attack(timestamp))
                else:
                    timestamp = self.start_time + timedelta(seconds=len(logs))
                    logs.append(generate_normal_log(timestamp))
                    
        elif scenario_name == 'data_breach':
            # Data exfiltration attempt
            logs = []
            for _ in range(count):
                if random.random() < 0.20:  # 20% data exfil
                    timestamp = self.start_time + timedelta(seconds=len(logs))
                    logs.append(generate_data_exfiltration_attack(timestamp))
                else:
                    timestamp = self.start_time + timedelta(seconds=len(logs))
                    logs.append(generate_normal_log(timestamp))
        else:
            # Default mixed scenario
            logs = self.generate_batch(count)
        
        # Restore original attack rate
        self.attack_rate = old_rate
        
        return logs
    
    def get_statistics(self) -> Dict:
        """
        Get generation statistics
        
        Returns:
            Statistics dictionary
        """
        if self.stats['total'] == 0:
            attack_rate = 0
        else:
            attack_rate = (self.stats['attacks'] / self.stats['total']) * 100
        
        return {
            'total_generated': self.stats['total'],
            'normal_logs': self.stats['normal'],
            'attack_logs': self.stats['attacks'],
            'actual_attack_rate': f"{attack_rate:.2f}%",
            'attack_breakdown': self.stats['attack_types']
        }
    
    def print_statistics(self):
        """Print nice statistics summary"""
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



# BACKWARDS COMPATIBLE FUNCTION        

def generate_test_data(num_logs: int = 100, attack_rate: float = 0.08) -> List[Dict]:
    """
    Generate test logs (backwards compatible with old code)
    
    Args:
        num_logs: Number of logs to generate
        attack_rate: Probability of attacks (0.08 = 8%)
        
    Returns:
        List of log dictionaries
    """
    generator = EnhancedLogGenerator(attack_rate=attack_rate)
    return generator.generate_batch(num_logs)



# TESTING
if __name__ == "__main__":
    import json
    
    print("=" * 70)
    print("ENHANCED DATA GENERATOR TEST")
    print("=" * 70)
    
    # Test 1: Generate mixed logs
    print("\n Test 1: Mixed Traffic (100 logs, 10% attack rate)")
    print("-" * 70)
    
    generator = EnhancedLogGenerator(attack_rate=0.10)
    logs = generator.generate_batch(100)
    
    # Show first 5 logs
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
        if log['errorMessage']:
            print(f"  Error: {log['errorMessage']}")
    
    generator.print_statistics()
    
    # Test 2: Different scenarios
    print("\n" + "=" * 70)
    print(" Test 2: Different Scenarios")
    print("-" * 70)
    
    scenarios = ['normal_day', 'under_attack', 'crypto_wave', 'data_breach']
    
    for scenario in scenarios:
        gen = EnhancedLogGenerator()
        logs = gen.generate_scenario(scenario, 50)
        
        attacks = sum(1 for log in logs if 'attack_type' in log)
        print(f"\n{scenario:15s}: {attacks:2d}/50 attacks ({attacks/50*100:.0f}%)")
    
    # Test 3: Show one of each attack type
    print("\n" + "=" * 70)
    print("Test 3: Sample of Each Attack Type")
    print("-" * 70)
    
    timestamp = datetime.now()
    
    attack_generators = [
        ('Crypto Mining', generate_crypto_mining_attack),
        ('Data Exfiltration', generate_data_exfiltration_attack),
        ('SQL Injection', generate_sql_injection_attack),
        ('SSRF', generate_ssrf_attack),
        ('Memory Attack', generate_memory_leak_attack),
        ('DDoS/Loop', generate_ddos_attack),
        ('Error Spike', generate_error_spike_attack),
    ]
    
    for name, func in attack_generators:
        log = func(timestamp)
        print(f"\n{name}:")
        print(f"  Duration: {log['duration']}ms")
        print(f"  Memory: {log['memoryUsed']}MB")
        print(f"  Status: {log['statusCode']}")
        print(f"  API Calls: {len(log['apiCalls'])}")
        if log['errorMessage']:
            print(f"  Error: {log['errorMessage'][:50]}...")
    
    print("\n" + "=" * 70)
    print(" ALL TESTS COMPLETE!")
    print("=" * 70)
    