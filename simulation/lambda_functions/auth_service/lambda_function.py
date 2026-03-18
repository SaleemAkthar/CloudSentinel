"""
simulation/lambda_functions/auth_service/lambda_function.py
============================================================
Simulates an authentication / authorisation Lambda function.

Two execution paths are modelled:
  - normal : JWT token validation — fast and lightweight (50–150ms).
  - login  : Full credential check with password hashing and token
             generation — moderately slower (200–500ms).

Auth functions are expected to be the fastest services in the
system. Any sustained increase in duration or memory beyond
these ranges is a strong indicator of credential-stuffing,
brute-force, or session-hijacking activity.

Author: Okitha (LocalStack Simulation)
"""

import json
import time
import random


def lambda_handler(event, context):
    """
    Entry point for the Auth Service Lambda.

    Reads 'action' from the event to choose between token
    validation and full login, then returns execution duration
    and memory for metric collection.
    """
    start  = time.time()
    action = event.get("action", "normal")

    if action == "normal":
        # Stateless JWT validation — only cryptographic verification,
        # no DB round-trip required.
        time.sleep(random.uniform(0.05, 0.15))
        memory = random.randint(64, 100)
        result = {
            "authenticated": True,
            "user_id":       f"user-{random.randint(1, 1000)}",
        }

    elif action == "login":
        # Full login flow: password hash comparison + token generation.
        # Slightly higher duration and memory are expected here.
        time.sleep(random.uniform(0.2, 0.5))
        memory = random.randint(90, 130)
        result = {
            "authenticated": True,
            "token":         "jwt-" + "x" * 100,
        }

    else:
        # Unrecognised action — deny by default.
        time.sleep(0.1)
        memory = 80
        result = {"authenticated": False}

    elapsed_ms = round((time.time() - start) * 1000, 2)

    return {
        "statusCode":     200,
        "body":           json.dumps(result),
        "duration_ms":    elapsed_ms,
        "memory_used_mb": memory,
    }