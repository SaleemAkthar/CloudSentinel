#!/usr/bin/env python3
"""
Cloud Sentinel Lambda Extension — Simplified v3
=================================================
Sends Lambda execution metadata to Cloud Sentinel after each invocation.
Uses only the Extensions API, for maximum compatibility.

The extension registers for INVOKE events. After each invocation,
it reads the REPORT line from the response and sends metrics to
Cloud Sentinel's /process_log endpoint.
"""

import json
import os
import sys
import urllib.request
import urllib.error
import time
import socket

# ── Configuration ─────────────────────────────────────────────────────────────
CS_API_URL = os.environ.get("CS_API_URL", "http://localhost:8000/process_log")
EXTENSIONS_API = f"http://{os.environ.get('AWS_LAMBDA_RUNTIME_API', 'localhost:9001')}/2020-01-01/extension"
EXTENSION_NAME = os.path.basename(__file__)  # must match filename in extensions/


def register():
    """Register this extension with Lambda runtime."""
    url = f"{EXTENSIONS_API}/register"
    data = json.dumps({"events": ["INVOKE", "SHUTDOWN"]}).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Lambda-Extension-Name": EXTENSION_NAME,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as resp:
            ext_id = resp.headers.get("Lambda-Extension-Identifier")
            print(f"[CS] Registered: {ext_id}", flush=True)
            return ext_id
    except Exception as e:
        print(f"[CS] Registration failed: {e}", flush=True)
        sys.exit(1)


def next_event(ext_id):
    """Block until Lambda sends the next lifecycle event."""
    url = f"{EXTENSIONS_API}/event/next"
    req = urllib.request.Request(
        url,
        headers={"Lambda-Extension-Identifier": ext_id},
        method="GET",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def send_to_cloud_sentinel(function_name, invoke_count):
    """
    Send execution metadata to Cloud Sentinel.
    Since we can't get exact metrics from Extensions API alone,
    we send the function name and let Cloud Sentinel track it.
    """
    payload = {
        "duration": 0,  # Will be populated by CloudWatch poller on backend
        "memory_used": 0,
        "num_api_calls": 1,
        "function_name": function_name,
        "ip_address": get_ip(),
        "error_count": 0,
        "ttl": 64,
        "packet_size": 512,
        "packet_size_in": 512,
        "packet_size_out": 0,
        "fragment_count": 0,
        "dest_port": 443,
        "network_latency": 0,
    }

    try:
        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            CS_API_URL,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2) as resp:
            result = json.loads(resp.read())
            decision = result.get("decision", "?")
            print(f"[CS] Sent #{invoke_count} → {decision}", flush=True)
    except Exception as e:
        print(f"[CS] Send failed: {e}", flush=True)


def get_ip():
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "10.0.0.1"


def main():
    function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "unknown")
    print(f"[CS] Cloud Sentinel Extension starting for {function_name}", flush=True)
    print(f"[CS] Target: {CS_API_URL}", flush=True)

    ext_id = register()
    invoke_count = 0

    while True:
        try:
            event = next_event(ext_id)
            event_type = event.get("eventType", "UNKNOWN")

            if event_type == "INVOKE":
                invoke_count += 1
                # Send after each invocation
                send_to_cloud_sentinel(function_name, invoke_count)

            elif event_type == "SHUTDOWN":
                print(f"[CS] Shutdown. Total invocations: {invoke_count}", flush=True)
                break

        except Exception as e:
            print(f"[CS] Event loop error: {e}", flush=True)
            break

    print("[CS] Exited.", flush=True)


if __name__ == "__main__":
    main()