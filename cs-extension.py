#!/usr/bin/env python3
"""
Cloud Sentinel — Lambda Extension
====================================
This file runs INSIDE your Lambda functions as a sidecar process.
It receives execution data the moment your function finishes
and sends it to Cloud Sentinel with no CloudWatch delay.

How it works:
─────────────
Normal flow (with CloudWatch — SLOW):
  Lambda finishes → CloudWatch buffers (2-15 seconds) → You find out late

With this extension (FAST):
  Lambda finishes → Extension gets data immediately → Sends to Cloud Sentinel (1-5ms)

The extension runs alongside your Lambda function on the same
machine using AWS Lambda Extensions API on localhost:9001.
No network travel for the data collection part — just internal
process communication which is essentially 0ms.

Author: Cloud Sentinel Backend Team
"""

import json
import os
import http.server
import threading
import urllib.request
import urllib.error
import socket
import sys
import time


# ── Configuration ─────────────────────────────────────────────────────────────
# CS_API_URL is set as an environment variable on your Lambda function
# It must point to your Cloud Sentinel server (ALB URL in AWS)
CS_API_URL = os.environ.get(
    "CS_API_URL",
    "http://localhost:8000/process_log"
)

# AWS fixed URLs — these never change
# Lambda Extensions API — for registering and receiving lifecycle events
LAMBDA_AGENT_BASE_URL = "http://localhost:9001/2020-01-01/extension"

# Lambda Telemetry API — for subscribing to execution reports
TELEMETRY_API_BASE_URL = "http://localhost:9002/2022-07-01/telemetry"

# Port where our listener receives telemetry from Lambda runtime
# Must be different from all other ports in use
TELEMETRY_LISTENER_PORT = 4243

# Extension name — must match the filename when deployed as a layer
EXTENSION_NAME = "cs-extension"


# ── Telemetry Listener ─────────────────────────────────────────────────────────
# This is a tiny web server that runs in a background thread.
# Lambda runtime sends POST requests to it after each function invocation.
# It receives the execution report and forwards it to Cloud Sentinel.

class TelemetryListener(http.server.BaseHTTPRequestHandler):
    """
    Receives execution telemetry from Lambda runtime.

    When your Lambda function finishes, the Lambda runtime sends
    a platform.report event to this listener containing:
    - durationMs        — how long the function ran
    - maxMemoryUsedMB   — peak memory during execution
    - memorySizeMB      — configured memory limit
    - initDurationMs    — cold start time (if any)
    - requestId         — unique ID for this invocation
    - status            — success or error
    """

    def do_POST(self):
        """Handle incoming telemetry from Lambda runtime."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Acknowledge receipt immediately — Lambda runtime waits for this
        self.send_response(200)
        self.end_headers()

        try:
            events = json.loads(body)
            for event in events:
                event_type = event.get("type", "")

                # platform.report = execution summary after function finishes
                # This is the event we care about
                if event_type == "platform.report":
                    self._process_execution_report(event)

                # platform.initReport = cold start information
                elif event_type == "platform.initReport":
                    # Cold starts affect SARIMA baseline
                    # We include initDuration in the main report
                    pass

        except json.JSONDecodeError as e:
            print(f"[CS Extension] JSON parse error: {e}", flush=True)
        except Exception as e:
            print(f"[CS Extension] Error processing event: {e}", flush=True)

    def _process_execution_report(self, event: dict):
        """
        Extract execution metrics from the platform.report event
        and forward them to Cloud Sentinel.
        """
        record  = event.get("record", {})
        metrics = record.get("metrics", {})
        status  = record.get("status", "success")

        # Extract all available metrics
        duration_ms     = metrics.get("durationMs", 0)
        memory_used_mb  = metrics.get("maxMemoryUsedMB", 0)
        memory_size_mb  = metrics.get("memorySizeMB", 512)
        init_duration   = metrics.get("initDurationMs", 0)
        request_id      = record.get("requestId", "unknown")

        # Build payload matching Cloud Sentinel LogRequest model exactly
        # Every field here corresponds to a field in backend/api.py LogRequest
        payload = {
            # Core execution metrics — these drive Layer 1 detection
            "duration":       duration_ms,
            "memory_used":    memory_used_mb,
            "num_api_calls":  0,       # Lambda extension cannot see API calls
                                        # Layer 1 scorer handles this separately

            # Function identification
            "function_name":  os.environ.get(
                                  "AWS_LAMBDA_FUNCTION_NAME", "unknown"
                              ),

            # Network metadata — used by Layer 1 filter and Layer 2 IP analysis
            "ip_address":     self._get_environment_ip(),
            "ttl":            64,       # Default — extension cannot see TTL
            "dest_port":      443,      # Lambda always communicates on 443

            # Error detection — Layer 1 uses this for SQL injection detection
            "error_count":    1 if status == "error" else 0,

            # Packet metadata defaults
            "packet_size_in":  512,
            "packet_size_out": 0,
            "fragment_count":  0,

            # Network latency — cold start time is a useful signal
            # High init duration can indicate code injection
            "network_latency": init_duration,

            # Additional context
            "unique_destinations": 1,
            "region": os.environ.get("AWS_REGION", "us-east-1"),
        }

        # Send to Cloud Sentinel
        self._send_to_cloud_sentinel(payload, request_id)

    def _send_to_cloud_sentinel(self, payload: dict, request_id: str):
        """
        POST the execution data to Cloud Sentinel.
        Uses a 2 second timeout — if Cloud Sentinel is unreachable,
        we give up and move on. This NEVER blocks your Lambda function.
        """
        try:
            start = time.perf_counter()
            data  = json.dumps(payload).encode("utf-8")

            req = urllib.request.Request(
                CS_API_URL,
                data    = data,
                headers = {"Content-Type": "application/json"},
                method  = "POST",
            )

            with urllib.request.urlopen(req, timeout=2) as resp:
                elapsed_ms = (time.perf_counter() - start) * 1000
                result     = json.loads(resp.read())
                decision   = result.get("decision", "UNKNOWN")
                severity   = result.get("severity", "")

                print(
                    f"[CS Extension] [{request_id[:8]}] "
                    f"duration={payload['duration']}ms "
                    f"memory={payload['memory_used']}MB "
                    f"decision={decision} "
                    f"severity={severity} "
                    f"sent_in={elapsed_ms:.1f}ms",
                    flush=True
                )

        except urllib.error.URLError as e:
            # Network error — Cloud Sentinel is unreachable
            # This is not critical — Lambda function continues normally
            print(
                f"[CS Extension] [{request_id[:8]}] "
                f"Network error sending to Cloud Sentinel: {e}",
                flush=True
            )
        except urllib.error.HTTPError as e:
            print(
                f"[CS Extension] [{request_id[:8]}] "
                f"HTTP error from Cloud Sentinel: {e.code} {e.reason}",
                flush=True
            )
        except Exception as e:
            print(
                f"[CS Extension] [{request_id[:8]}] "
                f"Unexpected error: {e}",
                flush=True
            )

    def _get_environment_ip(self) -> str:
        """
        Get the IP address of this Lambda execution environment.
        Each Lambda execution environment has its own IP.
        Used by Layer 2 for IP geolocation and reputation checks.
        """
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "10.0.0.1"

    def log_message(self, format, *args):
        """Suppress default HTTP server access logs — we log our own."""
        pass


# ── Extension Registration ─────────────────────────────────────────────────────

def register_extension() -> str:
    """
    Register this extension with the Lambda Extensions API.

    This tells Lambda runtime:
      - An extension named cs-extension is present
      - It wants to receive INVOKE and SHUTDOWN events
      - Lambda should not freeze the environment until extension responds

    Returns the extension ID assigned by Lambda runtime.
    This ID must be included in all future API calls.
    """
    headers = {
        "Lambda-Extension-Name": EXTENSION_NAME,
        "Content-Type":          "application/json",
    }
    payload = json.dumps({
        "events": ["INVOKE", "SHUTDOWN"]
    }).encode()

    req = urllib.request.Request(
        f"{LAMBDA_AGENT_BASE_URL}/register",
        data    = payload,
        headers = headers,
        method  = "POST",
    )

    with urllib.request.urlopen(req) as resp:
        extension_id = resp.headers.get("Lambda-Extension-Identifier")
        print(
            f"[CS Extension] Registered. ID: {extension_id[:16]}...",
            flush=True
        )
        return extension_id


def subscribe_to_telemetry(extension_id: str):
    """
    Subscribe to Lambda Telemetry API to receive execution reports.

    Key settings explained:
    - maxItems: 1   → send after every single invocation, no batching
    - timeoutMs: 25 → maximum 25ms from function finish to us receiving data
    - types: platform → only execution reports, not function logs

    This gives us data within 25ms of function completion at most.
    In practice it is usually under 5ms.
    """
    headers = {
        "Lambda-Extension-Identifier": extension_id,
        "Content-Type":                "application/json",
    }
    payload = json.dumps({
        "schemaVersion": "2022-07-01",
        "types": [
            "platform"          # platform.report and platform.initReport
        ],
        "buffering": {
            "maxItems":  1,     # send immediately — no waiting for batches
            "maxBytes":  262144,
            "timeoutMs": 25,    # absolute maximum delay in milliseconds
        },
        "destination": {
            "protocol": "HTTP",
            "URI":       f"http://sandbox.localdomain:{TELEMETRY_LISTENER_PORT}",
        },
    }).encode()

    req = urllib.request.Request(
        TELEMETRY_API_BASE_URL,
        data    = payload,
        headers = headers,
        method  = "PUT",
    )

    with urllib.request.urlopen(req) as resp:
        print(
            f"[CS Extension] Subscribed to telemetry. "
            f"Max delay: 25ms. Port: {TELEMETRY_LISTENER_PORT}",
            flush=True
        )


# ── Event Loop ─────────────────────────────────────────────────────────────────

def run_event_loop(extension_id: str):
    """
    Main event loop — keeps the extension alive.

    Lambda runtime sends events here:
    - INVOKE    → a function invocation just happened (telemetry will follow)
    - SHUTDOWN  → Lambda environment is shutting down, clean up and exit

    The GET /event/next call BLOCKS until Lambda runtime has an event.
    This is intentional — it is how extensions work in AWS.
    """
    headers = {"Lambda-Extension-Identifier": extension_id}
    print("[CS Extension] Ready. Waiting for Lambda invocations...", flush=True)

    while True:
        try:
            req = urllib.request.Request(
                f"{LAMBDA_AGENT_BASE_URL}/event/next",
                headers = headers,
                method  = "GET",
            )
            with urllib.request.urlopen(req) as resp:
                event      = json.loads(resp.read())
                event_type = event.get("eventType", "UNKNOWN")

                if event_type == "INVOKE":
                    # Function was invoked — telemetry will arrive at our
                    # listener shortly. Nothing to do here — listener handles it
                    pass

                elif event_type == "SHUTDOWN":
                    shutdown_reason = event.get("shutdownReason", "unknown")
                    print(
                        f"[CS Extension] SHUTDOWN received. "
                        f"Reason: {shutdown_reason}. Exiting.",
                        flush=True
                    )
                    break

        except Exception as e:
            print(f"[CS Extension] Event loop error: {e}", flush=True)
            time.sleep(0.1)  # brief pause before retrying


# ── Main ───────────────────────────────────────────────────────────────────────

def main():
    print(
        f"[CS Extension] Starting Cloud Sentinel Lambda Extension\n"
        f"[CS Extension] Cloud Sentinel API: {CS_API_URL}\n"
        f"[CS Extension] Telemetry port:     {TELEMETRY_LISTENER_PORT}",
        flush=True
    )

    # ── Step 1: Start telemetry listener ─────────────────────────────
    # This web server receives execution reports from Lambda runtime
    # Runs in a background thread so it does not block the event loop
    server = http.server.HTTPServer(
        ("", TELEMETRY_LISTENER_PORT),
        TelemetryListener
    )
    listener_thread = threading.Thread(
        target = server.serve_forever,
        daemon = True,   # daemon=True means thread dies when main exits
        name   = "TelemetryListener"
    )
    listener_thread.start()
    print(
        f"[CS Extension] Telemetry listener started on :{TELEMETRY_LISTENER_PORT}",
        flush=True
    )

    # ── Step 2: Register with Lambda Extensions API ───────────────────
    extension_id = register_extension()

    # ── Step 3: Subscribe to receive telemetry ────────────────────────
    subscribe_to_telemetry(extension_id)

    # ── Step 4: Enter event loop ──────────────────────────────────────
    # This keeps the extension alive between invocations
    run_event_loop(extension_id)

    print("[CS Extension] Exited cleanly.", flush=True)


if __name__ == "__main__":
    main()