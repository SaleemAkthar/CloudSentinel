"""
Cloud Sentinel — FastAPI Backend
=================================
Entry point for the anomaly detection API.

Detection pipeline:
    POST /process_log  →  Layer1Scorer  →  SARIMAForecaster  →  AlertStore
    POST /api/scan     →  Layer1Filter  →  Layer2Scanner      →  AlertStore

Run from the project root:
    uvicorn backend.api:app --reload --port 8000

Author: Okitha (API Integration & SARIMA)
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
import datetime
import uuid

from backend.detection.layer1_scorer import Layer1Scorer
from backend.detection.sarima_forecaster import SARIMAForecaster
from backend.storage.in_memory_store import AlertStore
from backend.detection.layer1_filter import Layer1Filter
from backend.detection.layer2_scanner import Layer2Scanner

# Layer2Investigator is optional — the API starts normally without it.
# Endpoints that require it return 503 until Saleem's file is in place.
try:
    from backend.detection.layer2_investigator import Layer2Investigator
    _L2_AVAILABLE = True
except ImportError:
    _L2_AVAILABLE = False

app = FastAPI(title="Cloud Sentinel API", version="2.0")

# Allow the Vite dev server and any local React build to call this API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Module-level singletons
# Each component is instantiated once at startup and reused across requests
# so that state (baselines, trained models, stored alerts) is preserved.
# ---------------------------------------------------------------------------

# SARIMA must be created before Layer1Scorer so it can be passed in.
sarima_forecaster = SARIMAForecaster()

# Layer 1 weighted scorer. Learning window = 100 requests before detection
# begins. SARIMA is wired in here so temporal scores feed into the composite.
detector = Layer1Scorer(learning_window=100)
detector.set_sarima_forecaster(sarima_forecaster)

alert_store    = AlertStore()
layer2         = Layer2Investigator() if _L2_AVAILABLE else None
log_storage    = []  # in-memory audit log shown in the Behaviour Logs page
lambda_metrics = {}  # per-function invocation stats for the Lambda monitor
layer1_filter  = Layer1Filter()
layer2_scanner = Layer2Scanner()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class LogRequest(BaseModel):
    """
    A single Lambda execution event.
    Sent by the frontend simulator or the generate_test_data script.
    """
    duration:      float          # execution time in ms
    memory_used:   float          # memory consumed in MB
    num_api_calls: int            # outbound API calls made during execution
    function_name: str  = "unknown"
    ip_address:    str  = "10.0.0.1"
    error_count:   int  = 0


class PacketRequest(BaseModel):
    """
    A full network packet submission.
    Used by /api/scan which runs the Layer1Filter + Layer2Scanner pipeline.
    """
    duration:             float
    memory_used:          float
    num_api_calls:        int
    function_name:        str   = "unknown"
    ip_address:           str   = "10.0.0.1"
    ttl:                  int   = 64
    packet_size:          int   = 512
    packet_size_in:       int   = 512
    packet_size_out:      int   = 0
    fragment_count:       int   = 0
    protocol:             str   = "TCP"
    source_port:          int   = 0
    dest_port:            int   = 443
    network_latency:      float = 0.0
    unique_destinations:  int   = 1
    error_count:          int   = 0
    region:               str   = "us-east-1"
    content_type:         str   = "application/json"


# ---------------------------------------------------------------------------
# Internal helpers  (prefixed _ — not exposed as endpoints)
# ---------------------------------------------------------------------------

def _build_alert(log_request: LogRequest, detector_result: dict) -> dict:
    """
    Construct a frontend-compatible alert record from a Layer1Scorer result.

    Layer1Scorer already returns anomaly_score in [0.0, 1.0], so no
    rescaling is needed. Internal severity labels (HIGH, MEDIUM) are
    collapsed to WARNING because the frontend only renders three levels.
    """
    normalised_score = round(min(detector_result.get("anomaly_score", 0), 1.0), 2)

    severity_map = {
        "CRITICAL": "CRITICAL",
        "HIGH":     "WARNING",
        "MEDIUM":   "WARNING",
        "LOW":      "INFO",
    }
    frontend_severity = severity_map.get(detector_result.get("severity", "INFO"), "INFO")

    return {
        "id":            f"ALERT-{uuid.uuid4().hex[:6].upper()}",
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
        "function":      log_request.function_name,
        "severity":      frontend_severity,
        "threat_type":   detector_result.get("attack_type", "Unknown"),
        "status":        "OPEN",
        "anomaly_score": normalised_score,
        "confidence":    detector_result.get("confidence", 0),
        "features": {
            "duration_ms":    log_request.duration,
            "memory_used_mb": log_request.memory_used,
            "outbound_calls": int(log_request.num_api_calls),
            "ip_address":     log_request.ip_address,
        },
        "evidence":   detector_result.get("evidence", []),
        "components": detector_result.get("components", {}),
    }


def _build_log_entry(log_request: LogRequest, result: dict) -> dict:
    """
    Build a single audit-log row. Every request is recorded regardless
    of whether it is flagged as an anomaly, giving a complete event trail.
    """
    is_anomaly  = result.get("is_anomaly", False)
    is_critical = is_anomaly and result.get("severity") == "CRITICAL"

    return {
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "function":   log_request.function_name,
        "event":      "Anomaly Detected" if is_anomaly else "Normal Request",
        "user":       "system",
        "ip_address": log_request.ip_address,
        "status":     "blocked" if is_critical else "success",
        "duration":   f"{int(log_request.duration)}ms",
    }


def _update_lambda_metrics(log_request: LogRequest, is_anomaly: bool):
    """
    Maintain a running total of per-function invocation stats.
    Anomalous invocations increment the error counter, which is used
    to calculate the error rate shown on the Lambda monitor page.
    """
    fn = log_request.function_name
    if fn not in lambda_metrics:
        lambda_metrics[fn] = {
            "function_name":  fn,
            "invocations":    0,
            "total_duration": 0.0,
            "total_memory":   0.0,
            "error_count":    0,
        }
    m = lambda_metrics[fn]
    m["invocations"]    += 1
    m["total_duration"] += log_request.duration
    m["total_memory"]   += log_request.memory_used
    if is_anomaly:
        m["error_count"] += 1


# ---------------------------------------------------------------------------
# Core detection endpoint
# ---------------------------------------------------------------------------

@app.post("/process_log")
def process_log(request: LogRequest):
    """
    Main detection pipeline for Lambda execution events.

    Flow:
        1. Build feature dict from the incoming request.
        2. Pass to Layer1Scorer, which runs weighted anomaly scoring.
           SARIMA temporal scoring is handled inside Layer1Scorer via
           the forecaster reference set at startup.
        3. During the learning phase (first 100 requests), data points
           are collected but no anomaly decisions are made.
        4. After learning, if the composite score exceeds the threshold,
           an alert is created and stored.
        5. Every request is appended to the audit log regardless of result.
    """
    features = {
        "duration":        request.duration,
        "memory_used":     request.memory_used,
        "num_api_calls":   request.num_api_calls,
        "error_count":     request.error_count,
        "ip_address":      request.ip_address,
        "timestamp":       datetime.datetime.utcnow().isoformat(),
        # Packet-level fields default to neutral values when not supplied
        # by a basic LogRequest (only populated via /api/scan PacketRequest).
        "concurrency":     1,
        "packet_size_in":  512,
        "packet_size_out": 0,
        "latency":         0.0,
        "fragment_count":  0,
    }

    score, result = detector.process_log(features)

    # During learning, just log the request and feed SARIMA — no alert.
    if result.get("phase") == "learning":
        log_storage.append(_build_log_entry(request, result))
        sarima_forecaster.add_data_point(
            request.duration,
            datetime.datetime.utcnow().isoformat(),
        )
        return result

    # Feed SARIMA independently so it also maintains its own data series.
    sarima_forecaster.add_data_point(
        request.duration,
        datetime.datetime.utcnow().isoformat(),
    )
    temporal_score = sarima_forecaster.detect_temporal_anomaly(request.duration)
    result["temporal_anomaly_score"] = round(temporal_score, 3)

    log_storage.append(_build_log_entry(request, result))
    _update_lambda_metrics(request, is_anomaly=result.get("is_anomaly", False))

    if result.get("is_anomaly"):
        alert_store.add(_build_alert(request, result))

    result["normalised_score"] = round(min(score, 1.0), 2)
    return result


# ---------------------------------------------------------------------------
# Alert endpoints
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
def get_alerts(
    severity: Optional[str] = Query(None, description="CRITICAL | WARNING | INFO"),
    status:   Optional[str] = Query(None, description="OPEN | CLOSED"),
    limit:    int            = Query(100,  description="Maximum number of alerts to return"),
):
    """Return stored alerts. Supports filtering by severity and status."""
    alerts = alert_store.get_all()

    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity.upper()]
    if status:
        alerts = [a for a in alerts if a.get("status") == status.upper()]

    return alerts[:limit]


@app.get("/api/alerts/summary")
def get_alerts_summary():
    """Return alert counts broken down by severity and open/closed state."""
    alerts  = alert_store.get_all()
    summary = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "total": len(alerts)}

    for a in alerts:
        sev = a.get("severity", "INFO")
        if sev in summary:
            summary[sev] += 1

    summary["open"]   = sum(1 for a in alerts if a.get("status") == "OPEN")
    summary["closed"] = sum(1 for a in alerts if a.get("status") == "CLOSED")
    return summary


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    """Fetch a single alert by ID."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


@app.patch("/api/alerts/{alert_id}/close")
def close_alert(alert_id: str):
    """Mark an alert as CLOSED once a analyst has reviewed it."""
    if not alert_store.close(alert_id):
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return {"success": True}


@app.post("/api/alerts/{alert_id}/investigate")
def investigate_alert(alert_id: str):
    """
    Trigger a Layer 2 forensic investigation on a flagged alert.
    Delegates to Layer2Investigator (Saleem) which produces a detailed
    report with matched attack patterns and remediation recommendations.
    Returns 503 if layer2_investigator.py has not been implemented yet.
    """
    if not _L2_AVAILABLE or layer2 is None:
        raise HTTPException(
            status_code=503,
            detail="Layer 2 Investigator is not available yet.",
        )

    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    log_data = {
        "duration":      alert.get("features", {}).get("duration_ms", 0),
        "memory_used":   alert.get("features", {}).get("memory_used_mb", 0),
        "num_api_calls": alert.get("features", {}).get("outbound_calls", 0),
        "ip_address":    alert.get("features", {}).get("ip_address", "10.0.0.1"),
        "function_name": alert.get("function", "unknown"),
        "timestamp":     alert.get("timestamp"),
    }
    alert_metadata = {
        "severity":      alert.get("severity"),
        "attack_type":   alert.get("threat_type"),
        "anomaly_score": alert.get("anomaly_score"),
        "confidence":    alert.get("confidence"),
    }

    return layer2.investigate(
        alert_id=alert_id,
        log_data=log_data,
        alert_metadata=alert_metadata,
    )


# ---------------------------------------------------------------------------
# Audit log endpoint
# ---------------------------------------------------------------------------

@app.get("/api/logs")
def get_logs(limit: int = Query(100, description="Maximum number of log entries to return")):
    """Return the most recent audit log entries for the Behaviour Logs page."""
    return log_storage[-limit:]


# ---------------------------------------------------------------------------
# Lambda monitor endpoints
# ---------------------------------------------------------------------------

@app.get("/api/lambda/overview")
def get_lambda_overview():
    """
    Return aggregate Lambda metrics across all tracked functions.
    Fallback values are shown when no requests have been processed yet,
    so the dashboard cards are never blank on first load.
    """
    all_functions = list(lambda_metrics.values())
    total_inv  = sum(f["invocations"] for f in all_functions)
    avg_dur    = sum(f["total_duration"] for f in all_functions) / max(total_inv, 1)
    total_err  = sum(f["error_count"] for f in all_functions)
    error_rate = round((total_err / max(total_inv, 1)) * 100, 2)

    return {
        "total_invocations": total_inv  or 38484,
        "avg_response_time": round(avg_dur, 1) or 487,
        "error_rate":        error_rate or 1.2,
        "active_functions":  len(all_functions),
        "functions":         all_functions,
    }


@app.get("/api/lambda/functions")
def get_lambda_functions():
    """Return per-function Lambda metrics with computed averages."""
    result = []
    for fn, m in lambda_metrics.items():
        inv = m["invocations"]
        result.append({
            "function_name":   fn,
            "invocations":     inv,
            "avg_duration_ms": round(m["total_duration"] / max(inv, 1), 1),
            "avg_memory_mb":   round(m["total_memory"]   / max(inv, 1), 1),
            "error_count":     m["error_count"],
            "error_rate_pct":  round(m["error_count"] / max(inv, 1) * 100, 2),
        })
    return result


# ---------------------------------------------------------------------------
# Model health endpoint
# ---------------------------------------------------------------------------

@app.get("/api/model/health")
def model_health():
    """
    Return detection model performance metrics for the dashboard health card.

    Accuracy improves as more requests are seen (up to a ceiling of 99.9%).
    Precision decreases as the anomaly rate rises above expected levels.
    These are heuristic estimates suitable for a demo dashboard.
    """
    status        = detector.get_status()
    requests_seen = status.get("requests_processed", 0)
    anomalies     = status.get("anomalies_detected", 0)
    sarima_status = sarima_forecaster.get_status()

    precision = round(max(0, 100 - (anomalies / max(requests_seen, 1)) * 5), 1)
    accuracy  = round(min(99.9, 90 + (min(requests_seen, 500) / 500) * 9.9), 1)

    return {
        "accuracy":        accuracy,
        "precision":       precision,
        "recall":          40.0,
        "trainingActive":  status.get("phase") == "learning",
        "delta":           2.3,
        "sarima_trained":  sarima_status["trained"],
        "sarima_progress": sarima_status["progress_pct"],
    }


# ---------------------------------------------------------------------------
# System status endpoint
# ---------------------------------------------------------------------------

@app.get("/status")
def get_status():
    """
    Health check endpoint.
    Returns the current state of the detector, SARIMA forecaster,
    and whether Layer 2 is available.
    """
    return {
        "status":           "running",
        "detector_stats":   detector.get_status(),
        "sarima_status":    sarima_forecaster.get_status(),
        "layer2_available": _L2_AVAILABLE,
        "timestamp":        datetime.datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# Packet scanning endpoints  (Layer1Filter → Layer2Scanner pipeline)
# ---------------------------------------------------------------------------

@app.post("/api/scan")
def scan_packet(req: PacketRequest):
    """
    Two-stage packet inspection endpoint.

    Stage 1 — Layer1Filter: Checks TTL and packet size against safe thresholds.
    If the packet passes, it is returned immediately with decision PASS.

    Stage 2 — Layer2Scanner: Runs only on packets that failed Stage 1.
    Performs deep inspection (IP analysis, payload scoring, risk classification)
    and returns a full scan report. HIGH and MEDIUM severity results are
    also stored as alerts.
    """
    packet = req.dict()

    l1 = layer1_filter.check(packet)

    if l1["pass"]:
        return {
            "layer":    1,
            "decision": "PASS",
            "layer1":   l1,
            "layer2":   None,
            "severity": "SAFE",
            "message":  "Packet cleared Layer 1 — no further inspection required.",
        }

    l2 = layer2_scanner.scan(packet, l1)

    if l2["severity"] in ("HIGH", "MEDIUM"):
        alert = {
            "id":            l2["scan_id"],
            "timestamp":     l2["timestamp"],
            "function":      req.function_name,
            "severity":      "CRITICAL" if l2["severity"] == "HIGH" else "WARNING",
            "status":        "OPEN",
            "anomaly_score": l2["risk_score"],
            "threat_type":   l2["ai_recommendation"]["action"],
            "confidence":    l2["ai_recommendation"]["confidence"],
            "features": {
                "duration_ms":         req.duration,
                "memory_used_mb":      req.memory_used,
                "outbound_calls":      req.num_api_calls,
                "unique_destinations": req.unique_destinations,
                "error_count":         req.error_count,
                "ip_address":          req.ip_address,
            },
            "layer2_report": l2,
        }
        alert_store.add(alert)

    return {
        "layer":    2,
        "decision": l2["ai_recommendation"]["action"],
        "layer1":   l1,
        "layer2":   l2,
        "severity": l2["severity"],
        "message":  f"Layer 2 scan completed in {l2['elapsed_ms']}ms.",
    }


@app.get("/api/alerts/{alert_id}/packet-report")
def get_packet_report(alert_id: str):
    """
    Retrieve the full Layer 2 packet scan report attached to an alert.
    Only alerts created via /api/scan carry a packet report.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    report = alert.get("layer2_report")
    if not report:
        raise HTTPException(status_code=404, detail="No packet report found for this alert.")

    return report


if __name__ == "__main__":
    uvicorn.run("backend.api:app", host="0.0.0.0", port=8000, reload=True)