"""
simulation/lambda_functions/api_handler/lambda_function.py
===========================================================
Simulates a typical REST API Lambda function.

Three traffic patterns are modelled:
  - normal : standard DB lookup and JSON response (300–600ms)
  - heavy  : report generation with a larger payload (800–1500ms)
  - quick  : cache hit with near-instant response (50–150ms)

The variation across patterns gives the anomaly detector enough
statistical spread to build a meaningful baseline during learning.

Author: Okitha (LocalStack Simulation)
"""

import json
import time
import random


def lambda_handler(event, context):
    """
    Entry point for the API Handler Lambda.

    Reads 'action' from the event to choose which traffic pattern
    to simulate, then returns execution duration and memory so the
    data collector can record realistic metrics.
    """
    start  = time.time()
    action = event.get("action", "normal")

    if action == "normal":
        # Standard request path: DB lookup + response serialisation.
        # Sleep models combined network and query latency.
        time.sleep(random.uniform(0.3, 0.6))
        result = {"status": "ok", "items": list(range(random.randint(1, 10)))}

    elif action == "heavy":
        # Legitimate long-running request (e.g. report generation).
        # High duration here is expected, not anomalous.
        time.sleep(random.uniform(0.8, 1.5))
        result = {"status": "ok", "report": "x" * random.randint(1000, 5000)}

    elif action == "quick":
        # Cache hit — response is pre-computed, almost no processing.
        time.sleep(random.uniform(0.05, 0.15))
        result = {"status": "ok", "cached": True}

    else:
        result = {"status": "unknown_action"}

    elapsed_ms = round((time.time() - start) * 1000, 2)

    return {
        "statusCode":     200,
        "body":           json.dumps(result),
        "duration_ms":    elapsed_ms,
        "memory_used_mb": random.randint(80, 140),
    }