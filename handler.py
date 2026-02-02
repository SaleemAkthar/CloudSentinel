# handler.py

from sentinel import cloud_sentinel_wrapper

def actual_function(event, context):
    # Simulated business logic
    return {
        "message": "Hello from Cloud Sentinel protected Lambda"
    }

def handler(event, context):
    return cloud_sentinel_wrapper(actual_function, event, context)
