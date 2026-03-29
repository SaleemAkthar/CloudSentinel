"""
Cloud Sentinel Test Lambda — Auth Service
Simulates authentication token validation.
"""
import json
import time
import random

def lambda_handler(event, context):
    start = time.time()
    
    action = event.get("action", "normal")
    
    if action == "normal":
        # Simulate token validation
        time.sleep(random.uniform(0.02, 0.3))
        result = {"status": "ok", "authenticated": True, "user_id": f"user-{random.randint(1000,9999)}"}
    elif action == "failed":
        # Failed auth attempt
        time.sleep(random.uniform(0.1, 0.5))
        result = {"status": "error", "authenticated": False, "reason": "Invalid token"}
    else:
        time.sleep(random.uniform(0.05, 0.2))
        result = {"status": "ok", "action": action}
    
    elapsed = round((time.time() - start) * 1000, 2)
    
    return {
        "statusCode": 200,
        "body": json.dumps({
            **result,
            "elapsed_ms": elapsed,
            "function": "auth-service"
        })
    }