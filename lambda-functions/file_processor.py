"""
Cloud Sentinel Test Lambda — File Processor
Simulates S3 file transformation processing.
"""
import json
import time
import random

def lambda_handler(event, context):
    start = time.time()
    
    action = event.get("action", "normal")
    
    if action == "normal":
        # Simulate file processing
        time.sleep(random.uniform(0.3, 1.5))
        data = [random.random() for _ in range(10000)]
        result = {"status": "ok", "files_processed": random.randint(1, 5)}
    elif action == "large":
        # Large file processing
        time.sleep(random.uniform(2.0, 5.0))
        data = [random.random() for _ in range(500000)]
        result = {"status": "ok", "files_processed": random.randint(10, 50)}
    else:
        time.sleep(random.uniform(0.2, 0.8))
        result = {"status": "ok", "action": action}
    
    elapsed = round((time.time() - start) * 1000, 2)
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            **result,
            "elapsed_ms": elapsed,
            "function": "file-processor"
        })
    }