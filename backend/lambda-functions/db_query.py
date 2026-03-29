"""
Cloud Sentinel Test Lambda — DB Query
Simulates database query processing.
"""
import json
import time
import random

def lambda_handler(event, context):
    start = time.time()
    
    action = event.get("action", "normal")
    
    if action == "normal":
        # Simulate DB query
        time.sleep(random.uniform(0.05, 0.5))
        result = {"status": "ok", "rows_returned": random.randint(1, 100)}
    elif action == "complex":
        # Complex join query
        time.sleep(random.uniform(0.5, 2.0))
        result = {"status": "ok", "rows_returned": random.randint(500, 5000)}
    else:
        time.sleep(random.uniform(0.1, 0.3))
        result = {"status": "ok", "action": action}
    
    elapsed = round((time.time() - start) * 1000, 2)
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            **result,
            "elapsed_ms": elapsed,
            "function": "db-query"
        })
    }