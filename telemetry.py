# telemetry.py

import time

class TelemetryCollector:
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.network_calls = 0
        self.errors = 0

    def start(self):
        self.start_time = time.time()

    def stop(self):
        self.end_time = time.time()

    def record_network_call(self):
        self.network_calls += 1

    def record_error(self):
        self.errors += 1

    def get_telemetry(self):
        return {
            "execution_time_ms": (self.end_time - self.start_time) * 1000,
            "network_calls": self.network_calls,
            "errors": self.errors
        }
