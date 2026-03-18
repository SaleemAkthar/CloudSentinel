"""
Cloud Sentinel — FastAPI Backend
=================================
Entry point for the anomaly detection API.

Detection pipeline:
    POST /process_log
        → Layer1Scorer  (AI scoring — runs FIRST)
            ↓
        → Layer1Filter  (hard rule confirmation — runs AFTER scorer)
            ↓ PASS → traffic allowed
            ↓ FAIL → Layer 2 Scanner (deep forensics)
                → AI Model (Isolation Forest + Random Forest ensemble)
                    → Decision: ALLOW / INVESTIGATE / BLOCK

Run from project root:
    uvicorn backend.api:app --reload --port 8000

Author: Okitha (API Integration & SARIMA)
"""

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from collections import deque
import uvicorn
import datetime
import uuid
import os

from backend.detection.sarima_forecaster import SARIMAForecaster
from backend.storage.in_memory_store import AlertStore
from backend.detection.layer2_scanner import Layer2Scanner
from backend.detection.ai_model import EnsembleAnomalyDetector
from backend.detection.pipeline import CloudSentinelPipeline

# Layer2Investigator is optional — API starts without it.
try:
    from backend.detection.layer2_investigator import Layer2Investigator
    _L2_AVAILABLE = True
except ImportError:
    _L2_AVAILABLE = False

app = FastAPI(title="Cloud Sentinel API", version="3.0")

# ---------------------------------------------------------------------------
# CORS configuration (env-based for flexibility)
# ---------------------------------------------------------------------------

CORS_ORIGINS = os.environ.get(
    "CORS_ORIGINS",
    "http://localhost:5173,http://localhost:3000"
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Singletons — created once at startup, shared across all requests
# ---------------------------------------------------------------------------

# SARIMA for temporal anomaly detection
sarima_forecaster = SARIMAForecaster()

# AI Ensemble: Isolation Forest (unsupervised) + Random Forest (supervised)
# Phase 1 (first 200 requests): learns normal baseline
# Phase 2: Isolation Forest scores packets
# Phase 3: Both models vote — BLOCK only when both agree
ai_model = EnsembleAnomalyDetector(learning_window=200)

# Storage
alert_store = AlertStore()
layer2 = Layer2Investigator() if _L2_AVAILABLE else None

# Bounded audit log — keeps last 10,000 entries to prevent memory leaks
LOG_STORAGE_MAX = 10_000
log_storage = deque(maxlen=LOG_STORAGE_MAX)

# Per-function invocation stats for Lambda monitor page
lambda_metrics = {}

# Detection layers
sentinel_pipeline = CloudSentinelPipeline()


# ---------------------------------------------------------------------------
# Request model
# ---------------------------------------------------------------------------

class LogRequest(BaseModel):
    """
    A single Lambda execution event.

    Basic fields are always present. Packet-level fields have safe defaults
    so the pipeline can run Layer 1 Filter checks on every request.
    """
    # Basic fields (always present)
    duration:      float
    memory_used:   float
    num_api_calls: int
    function_name: str  = "unknown"
    ip_address:    str  = "10.0.0.1"
    error_count:   int  = 0

    # Packet-level fields (defaults = normal traffic values)
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
    region:               str   = "us-east-1"
    content_type:         str   = "application/json"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_alert(log_request: LogRequest, decision: str, severity: str,
                 confidence: float, anomaly_score: float, threat_type: str,
                 layer2_report: dict = None, ai_result: dict = None) -> dict:
    """Build a frontend-compatible alert record."""

    # Map backend severity to frontend contract (CRITICAL / WARNING / INFO)
    frontend_severity = severity
    if severity in ("HIGH", "MEDIUM"):
        frontend_severity = "WARNING"
    elif severity == "LOW":
        frontend_severity = "INFO"

    alert = {
        "id":             f"ALERT-{uuid.uuid4().hex[:6].upper()}",
        "timestamp":      datetime.datetime.utcnow().isoformat() + "Z",
        "function":       log_request.function_name,
        "severity":       frontend_severity,
        "status":         "OPEN",
        "anomaly_score":  round(anomaly_score, 3),
        "confidence":     round(confidence, 3),
        "threat_type":    threat_type or "Unknown",
        "decision":       decision,
        "features": {
            "duration_ms":         log_request.duration,
            "memory_used_mb":      log_request.memory_used,
            "outbound_calls":      log_request.num_api_calls,
            "unique_destinations": log_request.unique_destinations,
            "error_count":         log_request.error_count,
            "ip_address":          log_request.ip_address,
            "ttl":                 log_request.ttl,
        },
    }

    if layer2_report:
        alert["layer2_report"] = layer2_report

    if ai_result:
        alert["ai_details"] = {
            "composite_score": ai_result.get("anomaly_score", 0),
            "severity":        ai_result.get("severity"),
            "attack_type":     ai_result.get("attack_type"),
            "components":      ai_result.get("components", {}),
        }

    return alert


def _build_log_entry(log_request: LogRequest, result: dict) -> dict:
    """Build an audit log entry for every processed request."""
    is_anomaly = result.get("is_anomaly", False)
    decision   = result.get("decision", "ALLOW")

    if decision == "BLOCK":
        status = "blocked"
        event  = "Blocked — " + result.get("threat_type", "Anomaly Detected")
    elif decision == "INVESTIGATE":
        status = "flagged"
        event  = "Flagged for Investigation"
    elif is_anomaly:
        status = "flagged"
        event  = "Anomaly Detected"
    else:
        status = "allowed"
        event  = "Normal Traffic"

    return {
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "function":   log_request.function_name,
        "event":      event,
        "user":       "system",
        "ip_address": log_request.ip_address,
        "status":     status,
        "duration":   f"{log_request.duration}ms",
        "decision":   decision,
    }


def _update_lambda_metrics(log_request: LogRequest, is_anomaly: bool):
    """Track per-function invocation stats for the Lambda monitor page."""
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
# CORE DETECTION ENDPOINT
# ---------------------------------------------------------------------------

@app.post("/process_log")
def process_log(request: LogRequest):
    """
    Main detection pipeline for Lambda execution events.

    Flow:
        1. SARIMA        — dynamic thresholds + temporal context
        2. Layer1Scorer  — AI scoring, Z-scores, Welford baseline  (runs FIRST)
        3. Layer1Filter  — hard rule confirmation gate              (runs AFTER scorer)
            PASS → normal traffic allowed
            FAIL → escalate to Layer 2
        4. Layer 2 Scanner — deep forensic analysis
        5. AI Model — ensemble decision (IF + RF)
        6. Create alert if INVESTIGATE or BLOCK
    """

    # Build full packet dict for all detection layers
    packet = {
        "duration":             request.duration,
        "memory_used":          request.memory_used,
        "num_api_calls":        request.num_api_calls,
        "error_count":          request.error_count,
        "ip_address":           request.ip_address,
        "function_name":        request.function_name,
        "timestamp":            datetime.datetime.utcnow().isoformat(),
        "ttl":                  request.ttl,
        "packet_size":          request.packet_size,
        "packet_size_in":       request.packet_size_in,
        "packet_size_out":      request.packet_size_out,
        "fragment_count":       request.fragment_count,
        "protocol":             request.protocol,
        "source_port":          request.source_port,
        "dest_port":            request.dest_port,
        "network_latency":      request.network_latency,
        "unique_destinations":  request.unique_destinations,
        "region":               request.region,
        "content_type":         request.content_type,
        "concurrency":          1,
    }

    # ── Run the unified pipeline ─────────────────────────────────────
    # Internally: SARIMA → Layer1Scorer → Layer1Filter → Layer2 → AI Model
    pipeline_result = sentinel_pipeline.process(packet)

    decision      = pipeline_result["decision"]          # ALLOW / INVESTIGATE / BLOCK
    confidence    = pipeline_result["confidence"]
    severity      = pipeline_result["severity"]
    is_anomaly    = decision in ("INVESTIGATE", "BLOCK")

    # Extract layer details from pipeline stages for the response
    stages        = pipeline_result.get("stages", {})
    l1_result     = stages.get("layer1", {})
    l2_result     = stages.get("layer2", {})
    ai_stage      = stages.get("ai_model", {})
    scorer_result = stages.get("layer1_scorer", {})

    anomaly_score = scorer_result.get("score", 0.0)
    attack_type   = (
        l2_result.get("patterns", {}).get("top_threat", {}).get("name")
        if l2_result else None
    )

    # Early return for clean traffic (pipeline stopped at Layer 1)
    if not is_anomaly:
        result = {
            "decision":   "ALLOW",
            "layer":      1,
            "is_anomaly": False,
            "message":    pipeline_result.get("reason", "Passed Layer 1 — normal traffic"),
            "layer1":     l1_result,
            "ai_model": {
                "phase": scorer_result.get("details", {}).get("phase"),
                "score": anomaly_score,
            },
        }
        log_storage.append(_build_log_entry(request, result))
        _update_lambda_metrics(request, is_anomaly=False)
        return result

    # ── Create alert (only for INVESTIGATE or BLOCK) ─────────────────
    ai_details = ai_stage.get("details", {}) if ai_stage else {}
    alert = _build_alert(
        log_request=request,
        decision=decision,
        severity=severity,
        confidence=confidence,
        anomaly_score=anomaly_score,
        threat_type=attack_type,
        layer2_report=l2_result,
        ai_result=ai_details,
    )
    alert_store.add(alert)

    # ── Log and return ───────────────────────────────────────────────
    risk = l2_result.get("risk", {}) if l2_result else {}
    result = {
        "decision":       decision,
        "is_anomaly":     is_anomaly,
        "anomaly_score":  round(anomaly_score, 3),
        "confidence":     round(confidence, 4),
        "severity":       severity,
        "threat_type":    attack_type if is_anomaly else None,
        "layer":          2,
        "layer1":         l1_result,
        "layer2_summary": {
            "severity":     l2_result.get("severity") if l2_result else None,
            "risk_score":   risk.get("adjusted_score", 0),
            "threat_count": l2_result.get("patterns", {}).get("threat_count", 0) if l2_result else 0,
            "scan_id":      l2_result.get("scan_id") if l2_result else None,
            "elapsed_ms":   l2_result.get("elapsed_ms") if l2_result else None,
        },
        "ai_model": {
            "phase":       ai_details.get("phase"),
            "score":       ai_details.get("anomaly_score", 0),
            "is_anomaly":  ai_details.get("is_anomaly", False),
            "model_votes": ai_details.get("model_votes"),
        },
        "message": (
            f"Layer 2 + AI Model complete. Decision: {decision}."
            if is_anomaly
            else "Layer 2 + AI Model cleared — traffic allowed."
        ),
    }

    log_storage.append(_build_log_entry(request, result))
    _update_lambda_metrics(request, is_anomaly=is_anomaly)

    return result


# ---------------------------------------------------------------------------
# Alert endpoints
# ---------------------------------------------------------------------------

@app.get("/api/alerts")
def get_alerts(
    severity: Optional[str] = Query(None),
    status:   Optional[str] = Query(None),
    limit:    int            = Query(100),
):
    """Return stored alerts with optional filtering."""
    alerts = alert_store.get_all()

    if severity:
        alerts = [a for a in alerts if a.get("severity") == severity]
    if status:
        alerts = [a for a in alerts if a.get("status") == status]

    alerts.sort(key=lambda a: a.get("timestamp", ""), reverse=True)
    return alerts[:limit]


@app.get("/api/alerts/summary")
def get_alerts_summary():
    """Return alert counts grouped by severity."""
    alerts = alert_store.get_all()
    summary = {"CRITICAL": 0, "WARNING": 0, "INFO": 0, "total": len(alerts)}
    summary["open"]   = sum(1 for a in alerts if a.get("status") == "OPEN")
    summary["closed"] = sum(1 for a in alerts if a.get("status") == "CLOSED")
    for a in alerts:
        sev = a.get("severity", "INFO")
        if sev in summary:
            summary[sev] += 1
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
    """Mark an alert as CLOSED."""
    if not alert_store.close(alert_id):
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return {"success": True}


# ---------------------------------------------------------------------------
# User action endpoints — ALLOW and BLOCK
# ---------------------------------------------------------------------------

@app.patch("/api/alerts/{alert_id}/allow")
def allow_alert(alert_id: str):
    """
    Analyst reviewed the alert and determined it's not a threat.
    Marks as ALLOWED + CLOSED. Feeds false-positive outcome to AI model.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    alert["status"]      = "CLOSED"
    alert["resolution"]  = "ALLOWED"
    alert["resolved_by"] = "analyst"
    alert["resolved_at"] = datetime.datetime.utcnow().isoformat() + "Z"

    ai_model.record_outcome(predicted_anomaly=True, true_anomaly=False)

    log_storage.append({
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "function":   alert.get("function", "unknown"),
        "event":      f"Alert {alert_id} — Allowed by analyst",
        "user":       "analyst",
        "ip_address": alert.get("features", {}).get("ip_address", "unknown"),
        "status":     "allowed",
        "duration":   "-",
        "decision":   "ALLOW",
    })

    return {
        "success":    True,
        "alert_id":   alert_id,
        "resolution": "ALLOWED",
        "message":    f"Alert {alert_id} marked as allowed.",
    }


@app.patch("/api/alerts/{alert_id}/block")
def block_alert(alert_id: str):
    """
    Analyst confirmed the alert is a real threat.
    Marks as BLOCKED + CLOSED. Feeds true-positive outcome to AI model.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    alert["status"]      = "CLOSED"
    alert["resolution"]  = "BLOCKED"
    alert["resolved_by"] = "analyst"
    alert["resolved_at"] = datetime.datetime.utcnow().isoformat() + "Z"

    ai_model.record_outcome(predicted_anomaly=True, true_anomaly=True)

    log_storage.append({
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "function":   alert.get("function", "unknown"),
        "event":      f"Alert {alert_id} — Blocked by analyst (IP: {alert.get('features', {}).get('ip_address', 'unknown')})",
        "user":       "analyst",
        "ip_address": alert.get("features", {}).get("ip_address", "unknown"),
        "status":     "blocked",
        "duration":   "-",
        "decision":   "BLOCK",
    })

    return {
        "success":    True,
        "alert_id":   alert_id,
        "resolution": "BLOCKED",
        "message":    f"Alert {alert_id} confirmed as threat. IP blocked.",
    }


# ---------------------------------------------------------------------------
# Investigation endpoint
# ---------------------------------------------------------------------------

@app.post("/api/alerts/{alert_id}/investigate")
def investigate_alert(alert_id: str):
    """
    Trigger Layer 2 forensic investigation on a flagged alert.
    Returns existing report if pipeline already produced one.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    # Return existing Layer 2 report if available
    if alert.get("layer2_report"):
        return {
            "alert_id":   alert_id,
            "source":     "pipeline",
            "report":     alert["layer2_report"],
            "ai_details": alert.get("ai_details"),
            "message":    "Layer 2 report from detection pipeline.",
        }

    # Otherwise run a fresh investigation
    if not _L2_AVAILABLE or layer2 is None:
        raise HTTPException(
            status_code=503,
            detail="Layer 2 Investigator is not available.",
        )

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
def get_logs(limit: int = Query(100)):
    """Return the most recent audit log entries."""
    # deque doesn't support slicing directly — convert to list
    all_logs = list(log_storage)
    return all_logs[-limit:]


# ---------------------------------------------------------------------------
# Lambda monitor endpoints
# ---------------------------------------------------------------------------

@app.get("/api/lambda/overview")
def get_lambda_overview():
    """Return aggregate Lambda metrics across all tracked functions."""
    if not lambda_metrics:
        return {
            "total_invocations":  0,
            "avg_response_time":  0,
            "error_rate":         0,
            "active_functions":   0,
            "functions":          [],
        }

    total_inv = sum(m["invocations"]    for m in lambda_metrics.values())
    total_dur = sum(m["total_duration"] for m in lambda_metrics.values())
    total_err = sum(m["error_count"]    for m in lambda_metrics.values())

    return {
        "total_invocations":  total_inv,
        "avg_response_time":  round(total_dur / max(total_inv, 1), 1),
        "error_rate":         round((total_err / max(total_inv, 1)) * 100, 2),
        "active_functions":   len(lambda_metrics),
        "functions":          list(lambda_metrics.values()),
    }


@app.get("/api/lambda/functions")
def get_lambda_functions():
    """Return per-function Lambda metrics."""
    result = []
    for fn, m in lambda_metrics.items():
        inv = m["invocations"]
        result.append({
            "function_name":   fn,
            "invocations":     inv,
            "avg_duration_ms": round(m["total_duration"] / max(inv, 1), 1),
            "avg_memory_mb":   round(m["total_memory"]   / max(inv, 1), 1),
            "error_count":     m["error_count"],
            "error_rate_pct":  round((m["error_count"] / max(inv, 1)) * 100, 2),
        })
    return result


# ---------------------------------------------------------------------------
# Model health endpoint
# ---------------------------------------------------------------------------

@app.get("/api/model/health")
def get_model_health():
    """Return AI model performance metrics for the dashboard."""
    status        = ai_model.get_status()
    perf          = ai_model.get_performance_metrics()
    sarima_status = sarima_forecaster.get_status()

    return {
        "accuracy":        perf.get("accuracy", 0.0),
        "precision":       perf.get("precision", 0.0),
        "recall":          perf.get("recall", 0.0),
        "f1":              perf.get("f1", 0.0),
        "trainingActive":  status.get("phase") == "learning",
        "delta":           2.3,
        "sarima_trained":  sarima_status["trained"],
        "sarima_progress": sarima_status["progress_pct"],
        "ensemble": {
            "phase":                    status["phase"],
            "isolation_forest_trained": status["isolation_forest_trained"],
            "random_forest_trained":    status["random_forest_trained"],
            "labeled_examples":         status["labeled_examples"],
            "labeled_anomalies":        status["labeled_anomalies"],
        },
    }


# ---------------------------------------------------------------------------
# System status endpoint
# ---------------------------------------------------------------------------

@app.get("/status")
def get_status():
    """Health check endpoint."""
    return {
        "status":           "running",
        "detector_stats":   ai_model.get_status(),
        "sarima_status":    sarima_forecaster.get_status(),
        "layer2_available": _L2_AVAILABLE,
        "pipeline":         "unified",
        "timestamp":        datetime.datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# Packet report endpoint
# ---------------------------------------------------------------------------

@app.get("/api/alerts/{alert_id}/packet-report")
def get_packet_report(alert_id: str):
    """Retrieve the full Layer 2 scan report attached to an alert."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    report = alert.get("layer2_report")
    if not report:
        raise HTTPException(status_code=404, detail="No Layer 2 report found for this alert.")

    return report


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend.api:app", host="0.0.0.0", port=port, reload=True)