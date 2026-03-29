"""
Cloud Sentinel Test Lambda — API Handler
Simulates a REST API processing function.
"""
import json
import time
import random

def lambda_handler(event, context):
    start = time.time()
    
    # Simulate API processing
    action = event.get("action", "normal")
    
    if action == "normal":
        # Normal API request processing
        time.sleep(random.uniform(0.1, 0.5))
        result = {"status": "ok", "message": "Request processed successfully"}
    elif action == "heavy":
        # Heavy computation
        time.sleep(random.uniform(1.0, 3.0))
        total = sum(i * i for i in range(100000))
        result = {"status": "ok", "computed": total}
    else:
        result = {"status": "ok", "action": action}
    
    elapsed = round((time.time() - start) * 1000, 2)
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            **result,
            "elapsed_ms": elapsed,
            "function": "api-handler"
        })
    }