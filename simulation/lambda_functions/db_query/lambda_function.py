"""
simulation/lambda_functions/db_query/lambda_function.py
========================================================
Simulates a DynamoDB / RDS query Lambda function.

Two query complexities are modelled under normal traffic:
  - simple  : single-row lookup, low memory (100–300ms)
  - complex : multi-table join or aggregation (500ms–1s)

Keeping query durations short and memory low reflects the
expected baseline that the anomaly detector learns from.
Sustained deviations from this baseline (e.g. during a
data-exfiltration attack) will be flagged by Layer 1.

Author: Okitha (LocalStack Simulation)
"""

import json
import time
import random


def lambda_handler(event, context):
    """
    Entry point for the DB Query Lambda.

    Reads 'query_type' and 'action' from the event to select
    the appropriate execution path, then returns duration and
    memory for metric collection.
    """
    start      = time.time()
    query_type = event.get("query_type", "simple")
    action     = event.get("action", "normal")

    if action == "normal":
        if query_type == "simple":
            # Fast primary-key lookup — typical read path.
            time.sleep(random.uniform(0.1, 0.3))
            memory = random.randint(80, 120)
            result = {"rows": random.randint(1, 50)}

        elif query_type == "complex":
            # Multi-table join or aggregation query — legitimately slower.
            time.sleep(random.uniform(0.5, 1.0))
            memory = random.randint(120, 180)
            result = {"rows": random.randint(100, 1000)}

        else:
            # Unknown query type — return empty result set quickly.
            time.sleep(0.2)
            memory = 100
            result = {"rows": 0}

    else:
        # Fallback path for unrecognised actions.
        time.sleep(0.3)
        memory = 110
        result = {"rows": 10}

    elapsed_ms = round((time.time() - start) * 1000, 2)

    return {
        "statusCode":     200,
        "body":           json.dumps(result),
        "duration_ms":    elapsed_ms,
        "memory_used_mb": memory,
    }