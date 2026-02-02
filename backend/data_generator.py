"""
Sample Log Generator for Testing
Simulates realistic serverless application logs
"""

import random
import json
from datetime import datetime, timedelta
from typing import Dict, List


def generate_normal_log(base_time: datetime) -> Dict:
    """Generate a normal (non-anomalous) log entry."""
    return {
        "timestamp": base_time.isoformat(),
        "function_name": random.choice(["process_payment", "send_email", "generate_report"]),
        "duration": int(random.gauss(200, 30)),  # Mean 200ms, Std 30ms
        "memory_used": int(random.gauss(128, 20)),  # Mean 128MB, Std 20MB
        "num_api_calls": int(random.gauss(3, 1)),  # Mean 3 calls, Std 1
        "status": "success",
        "request_id": f"req_{random.randint(100000, 999999)}"
    }


def generate_anomalous_log(base_time: datetime, anomaly_type: str = "slow") -> Dict:
    """Generate an anomalous log entry."""
    if anomaly_type == "slow":
        # Slow execution
        duration = int(random.gauss(1500, 200))  # Much higher duration
    elif anomaly_type == "memory_spike":
        # High memory usage
        duration = int(random.gauss(200, 30))
        memory_used = int(random.gauss(512, 100))  # Much higher memory
    elif anomaly_type == "many_calls":
        # Excessive API calls (possible DDoS or loop)
        duration = int(random.gauss(300, 50))
        num_api_calls = int(random.gauss(50, 10))  # Many more calls
    else:
        duration = int(random.gauss(200, 30))
    
    log = {
        "timestamp": base_time.isoformat(),
        "function_name": random.choice(["process_payment", "send_email", "generate_report"]),
        "duration": duration,
        "memory_used": memory_used if anomaly_type == "memory_spike" else int(random.gauss(128, 20)),
        "num_api_calls": num_api_calls if anomaly_type == "many_calls" else int(random.gauss(3, 1)),
        "status": "success",
        "request_id": f"req_{random.randint(100000, 999999)}"
    }
    
    return log


def generate_log_stream(num_logs: int = 200, anomaly_rate: float = 0.1) -> List[Dict]:
    """
    Generate a stream of logs.
    
    Args:
        num_logs: Total number of logs to generate
        anomaly_rate: Proportion of logs that should be anomalous (0.0 to 1.0)
    
    Returns:
        List of log dictionaries
    """
    logs = []
    base_time = datetime.now() - timedelta(hours=1)
    
    for i in range(num_logs):
        if random.random() < anomaly_rate:
            log = generate_anomalous_log(base_time, random.choice(["slow", "memory_spike", "many_calls"]))
        else:
            log = generate_normal_log(base_time)
        
        logs.append(log)
        base_time += timedelta(milliseconds=random.randint(100, 500))
    
    return logs


if __name__ == "__main__":
    # Test the generator
    logs = generate_log_stream(num_logs=10, anomaly_rate=0.2)
    for log in logs:
        print(json.dumps(log, indent=2))
