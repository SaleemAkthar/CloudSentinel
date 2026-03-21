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
            ↓ FAIL → alert created, Layer 2 NOT run automatically
                → Layer 2 runs ONLY when analyst clicks Investigate
                   POST /api/alerts/{id}/investigate

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
import time
import threading
import boto3

from backend.detection.sarima_forecaster import SARIMAForecaster
from backend.storage.in_memory_store import AlertStore
from backend.detection.ai_model import EnsembleAnomalyDetector
from backend.detection.pipeline import CloudSentinelPipeline
from backend.detection.layer2_scanner import Layer2Scanner
from backend.auth_router import router as auth_router

# Layer2Investigator is optional — API starts without it.
try:
    from backend.detection.layer2_investigator import Layer2Investigator
    _L2_AVAILABLE = True
except ImportError:
    _L2_AVAILABLE = False

app = FastAPI(title="Cloud Sentinel API", version="3.0")

# Mount Auth router
app.include_router(auth_router)

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
from backend.detection.pipeline import _sarima as sarima_forecaster

# AI Ensemble: Isolation Forest (unsupervised) + Random Forest (supervised)
ai_model = EnsembleAnomalyDetector(learning_window=200)

# Layer 2 Scanner singleton — instantiated once, reused per investigate call
_layer2_scanner = Layer2Scanner()

# Storage
alert_store = AlertStore()
layer2 = Layer2Investigator() if _L2_AVAILABLE else None

# Bounded audit log — keeps last 10,000 entries to prevent memory leaks
LOG_STORAGE_MAX = 10_000
log_storage = deque(maxlen=LOG_STORAGE_MAX)

# Per-function invocation stats for Lambda monitor page
lambda_metrics = {}

# Detection pipeline
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

def _build_alert(
    log_request:    LogRequest,
    decision:       str,
    severity:       str,
    confidence:     float,
    anomaly_score:  float,
    threat_type:    str,
    ai_result:      dict = None,
    raw_packet:     dict = None,
    layer1_result:  dict = None,
) -> dict:
    """
    Build a frontend-compatible alert record.

    raw_packet and layer1_result are stored privately (prefixed with _)
    so they are available for on-demand Layer 2 investigation but are
    not sent to the frontend in normal alert listings.
    """

    # Map backend severity to frontend contract (CRITICAL / WARNING / INFO)
    frontend_severity = severity
    if severity in ("HIGH", "MEDIUM"):
        frontend_severity = "WARNING"
    elif severity == "LOW":
        frontend_severity = "INFO"

    alert = {
        "id":            f"ALERT-{uuid.uuid4().hex[:6].upper()}",
        "timestamp":     datetime.datetime.utcnow().isoformat() + "Z",
        "function":      log_request.function_name,
        "severity":      frontend_severity,
        "status":        "OPEN",
        "anomaly_score": round(anomaly_score, 3),
        "confidence":    round(confidence, 3),
        "threat_type":   threat_type or "Unknown",
        "decision":      decision,
        "features": {
            "duration_ms":         log_request.duration,
            "memory_used_mb":      log_request.memory_used,
            "outbound_calls":      log_request.num_api_calls,
            "unique_destinations": log_request.unique_destinations,
            "error_count":         log_request.error_count,
            "ip_address":          log_request.ip_address,
            "ttl":                 log_request.ttl,
        },
        # Layer 2 report — None until analyst triggers investigation
        "layer2_report": None,
    }

    if ai_result:
        alert["ai_details"] = {
            "composite_score": ai_result.get("anomaly_score", 0),
            "severity":        ai_result.get("severity"),
            "attack_type":     ai_result.get("attack_type"),
            "components":      ai_result.get("components", {}),
        }

    # Private fields — stored for on-demand Layer 2, never sent to frontend
    # in normal list/get responses (filtered out in get_alerts)
    alert["_raw_packet"]    = raw_packet
    alert["_layer1_result"] = layer1_result

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


def _strip_private_fields(alert: dict) -> dict:
    """
    Return alert dict without private _ fields.
    Used in list/get endpoints so raw packet data is not exposed.
    """
    return {k: v for k, v in alert.items() if not k.startswith("_")}


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
        2. Layer1Scorer  — AI scoring, Z-scores, Welford baseline
        3. Layer1Filter  — hard rule confirmation gate
            PASS → normal traffic allowed
            FAIL → alert created, returned as INVESTIGATE
                   Layer 2 runs ONLY when analyst clicks Investigate button
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
    # Internally: SARIMA → Layer1Scorer → Layer1Filter
    # Layer 2 is NO LONGER run here — it runs on-demand via /investigate
    pipeline_result = sentinel_pipeline.process(packet)

    # ── Feed SARIMA forecaster ────────────────────────────────────────
    sarima_forecaster.add_data_point(request.duration)
    if (not sarima_forecaster._trained
            and len(sarima_forecaster.training_data) >= sarima_forecaster.MIN_TRAINING_POINTS):
        sarima_forecaster.train()

    decision   = pipeline_result["decision"]       # ALLOW or INVESTIGATE
    confidence = pipeline_result["confidence"]
    severity   = pipeline_result["severity"]
    is_anomaly = decision == "INVESTIGATE"

    # Extract layer details from pipeline stages
    stages        = pipeline_result.get("stages", {})
    l1_result     = stages.get("layer1", {})
    scorer_result = stages.get("layer1_scorer", {})
    ai_details    = scorer_result.get("details", {}) if scorer_result else {}

    anomaly_score = scorer_result.get("score", 0.0)

    # Derive attack type from Layer 1 scorer behavioral analysis
    attack_type = (
        ai_details.get("attack_type")
        if ai_details.get("is_anomaly") else None
    )

    # ── ALLOW: clean traffic ──────────────────────────────────────────
    if not is_anomaly:
        result = {
            "decision":   "ALLOW",
            "layer":      1,
            "is_anomaly": False,
            "message":    pipeline_result.get("reason", "Passed Layer 1 — normal traffic"),
            "layer1":     l1_result,
            "ai_model": {
                "phase": ai_details.get("phase"),
                "score": anomaly_score,
            },
        }
        log_storage.append(_build_log_entry(request, result))
        _update_lambda_metrics(request, is_anomaly=False)
        return result

    # ── INVESTIGATE: flagged by Layer 1, Layer 2 pending ─────────────
    # Create alert. Store raw_packet privately for on-demand Layer 2.
    alert = _build_alert(
        log_request=request,
        decision=decision,
        severity=severity,
        confidence=confidence,
        anomaly_score=anomaly_score,
        threat_type=attack_type,
        ai_result=ai_details,
        raw_packet=pipeline_result.get("raw_packet"),
        layer1_result=l1_result,
    )
    alert_store.add(alert)

    result = {
        "decision":      decision,
        "is_anomaly":    is_anomaly,
        "anomaly_score": round(anomaly_score, 3),
        "confidence":    round(confidence, 4),
        "severity":      severity,
        "threat_type":   attack_type,
        "layer":         1,
        "layer1":        l1_result,
        "layer2_summary": None,  # populated after analyst clicks Investigate
        "ai_model": {
            "phase":      ai_details.get("phase"),
            "score":      ai_details.get("anomaly_score", 0),
            "is_anomaly": ai_details.get("is_anomaly", False),
        },
        "message": (
            "Flagged by Layer 1 — click Investigate in the dashboard "
            "to run deep Layer 2 analysis."
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
    """Return stored alerts with optional filtering. Private fields stripped."""
    alerts = [_strip_private_fields(a) for a in alert_store.get_all()]

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
    """Fetch a single alert by ID. Private fields stripped."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return _strip_private_fields(alert)


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
# ON-DEMAND Layer 2 Investigation endpoint
# ---------------------------------------------------------------------------

@app.post("/api/alerts/{alert_id}/investigate")
def investigate_alert(alert_id: str):
    """
    Trigger Layer 2 forensic investigation on demand.

    This is called when the analyst clicks the 'Investigate' button
    in the Real-Time Alerts page. Layer 2 does NOT run automatically
    during the detection pipeline — it only runs here.

    Layer 2 includes:
      - IP Analysis (geolocation, ASN, reputation, spoofing detection)
      - Packet Analysis (size, fragmentation, latency, exfiltration scoring)
      - Attack Pattern Matching (DDoS, SQLi, crypto mining, exfil, memory, spoofing)
      - Network Topology (routing path, hop count, transit providers)
      - Risk Scoring (composite risk, confidence, severity, recommendations)

    Returns cached report if the alert was already investigated.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    # ── Return cached Layer 2 report if already investigated ─────────
    if alert.get("layer2_report"):
        return {
            "alert_id": alert_id,
            "source":   "cached",
            "report":   alert["layer2_report"],
            "severity": alert.get("severity"),
            "decision": alert.get("decision"),
            "message":  "Returning cached Layer 2 report from previous investigation.",
        }

    # ── Get the stored raw packet ─────────────────────────────────────
    raw_packet = alert.get("_raw_packet")
    if not raw_packet:
        raise HTTPException(
            status_code=422,
            detail=(
                "No packet data stored for this alert. "
                "This can happen if the alert was created before the on-demand "
                "Layer 2 update was deployed, or if the packet data was cleared."
            ),
        )

    # ── Run Layer 2 now ───────────────────────────────────────────────
    layer1_result = alert.get("_layer1_result") or {}

    try:
        l2_result = _layer2_scanner.scan(raw_packet, layer1_result)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"Layer 2 scan failed: {str(exc)}"
        )

    # ── Update alert with Layer 2 results ────────────────────────────
    alert["layer2_report"] = l2_result

    # Update decision from Layer 2 recommendation
    l2_action = l2_result.get("risk", {}).get("recommendation", {}).get("action")
    if l2_action in ("BLOCK", "INVESTIGATE"):
        alert["decision"] = l2_action

    # Update severity from Layer 2 (map to frontend format)
    l2_severity = l2_result.get("severity", "")
    if l2_severity == "CRITICAL":
        alert["severity"] = "CRITICAL"
    elif l2_severity == "HIGH":
        alert["severity"] = "WARNING"
    elif l2_severity == "MEDIUM":
        alert["severity"] = "WARNING"

    # Update threat type from top matched pattern
    top_threat = l2_result.get("patterns", {}).get("top_threat")
    if top_threat:
        alert["threat_type"] = top_threat.get("name", alert.get("threat_type"))

    # ── Feed labeled data to AI ensemble for future improvement ───────
    is_anomaly_l2 = alert.get("decision") in ("BLOCK", "INVESTIGATE")
    attack_type_l2 = (top_threat.get("attack_type", "normal") if top_threat else "normal")
    try:
        ai_model.add_labeled_example(
            raw_packet,
            is_anomaly=is_anomaly_l2,
            attack_type=attack_type_l2,
        )
    except Exception:
        pass  # Don't fail the investigation if AI model update fails

    # ── Log the investigation action ──────────────────────────────────
    log_storage.append({
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "function":   alert.get("function", "unknown"),
        "event":      f"Layer 2 investigation run for {alert_id} — {l2_result.get('severity', 'UNKNOWN')} severity",
        "user":       "analyst",
        "ip_address": alert.get("features", {}).get("ip_address", "unknown"),
        "status":     "flagged" if is_anomaly_l2 else "allowed",
        "duration":   f"{l2_result.get('elapsed_ms', 0)}ms",
        "decision":   alert.get("decision", "INVESTIGATE"),
    })

    return {
        "alert_id": alert_id,
        "source":   "fresh",
        "report":   l2_result,
        "severity": alert.get("severity"),
        "decision": alert.get("decision"),
        "message":  f"Layer 2 investigation completed in {l2_result.get('elapsed_ms', 0)}ms.",
    }


# ---------------------------------------------------------------------------
# Audit log endpoint
# ---------------------------------------------------------------------------

@app.get("/api/logs")
def get_logs(limit: int = Query(100)):
    """Return the most recent audit log entries."""
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
        "layer2_available": True,   # always available — Layer2Scanner imported at top
        "pipeline":         "unified",
        "layer2_mode":      "on-demand",  # Layer 2 only runs when Investigate is clicked
        "timestamp":        datetime.datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# SARIMA status endpoint
# ---------------------------------------------------------------------------

@app.get("/sarima/status")
def get_sarima_status():
    """Detailed SARIMA forecaster status."""
    status     = sarima_forecaster.get_status()
    prediction = sarima_forecaster.predict()

    now  = datetime.datetime.utcnow()
    hour = now.hour

    return {
        "trained":          status["trained"],
        "sarima_available": status["sarima_available"],
        "sarima_fitted":    status["sarima_fitted"],
        "using_fallback":   status["using_fallback"],
        "data_points":      status["data_points"],
        "min_required":     status["min_required"],
        "progress_pct":     status["progress_pct"],
        "current_prediction": {
            "value": prediction["value"],
            "std":   prediction["std"],
        },
        "time_context": {
            "hour":       hour,
            "is_peak":    8 <= hour <= 20,
            "time_window": (
                "night"          if hour < 6  else
                "early_morning"  if hour < 8  else
                "morning_peak"   if hour < 12 else
                "midday_peak"    if hour < 14 else
                "afternoon_peak" if hour < 18 else
                "evening_peak"   if hour < 20 else
                "evening"        if hour < 22 else
                "late_night"
            ),
        },
        "timestamp": now.isoformat() + "Z",
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
        raise HTTPException(
            status_code=404,
            detail=(
                "No Layer 2 report found for this alert. "
                "Click 'Investigate' in the dashboard to run Layer 2 analysis first."
            ),
        )

    return report


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("backend.api:app", host="0.0.0.0", port=port, reload=True)