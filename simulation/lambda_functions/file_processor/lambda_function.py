"""
simulation/lambda_functions/file_processor/lambda_function.py
=============================================================
Simulates an S3 file-processing Lambda function.

Two traffic patterns are modelled:
  - normal : reads, transforms, and writes a single file.
             Duration scales with file_size_kb (5ms per KB, max 2s).
  - batch  : processes multiple files in one invocation (1.5–3s).

Memory consumption is proportional to file size, reflecting
how a real processor would buffer the payload in RAM.

Author: Okitha (LocalStack Simulation)
"""

import json
import time
import random


def lambda_handler(event, context):
    """
    Entry point for the File Processor Lambda.

    Accepts 'file_size_kb' and 'action' from the event.
    Returns duration and memory so the data collector can log
    realistic file-processing metrics.
    """
    start     = time.time()
    file_size = event.get("file_size_kb", 100)
    action    = event.get("action", "normal")

    if action == "normal":
        # Processing time scales linearly with file size (5ms per KB).
        # Capped at 2 seconds to stay within Lambda timeout budgets.
        processing_time = file_size * 0.005
        time.sleep(min(processing_time, 2.0))
        memory = 100 + (file_size * 0.1)   # base + per-KB overhead
        result = {"status": "processed", "output_size": file_size * 0.8}

    elif action == "batch":
        # Multi-file batch job — higher duration and memory are expected.
        time.sleep(random.uniform(1.5, 3.0))
        memory = random.randint(150, 250)
        result = {"status": "batch_complete", "files": random.randint(5, 20)}

    else:
        # Fallback for unrecognised actions.
        time.sleep(0.5)
        memory = 120
        result = {"status": "ok"}

    elapsed_ms = round((time.time() - start) * 1000, 2)

    return {
        "statusCode":     200,
        "body":           json.dumps(result),
        "duration_ms":    elapsed_ms,
        "memory_used_mb": round(memory, 2),
    }