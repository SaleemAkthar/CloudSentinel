"""
Cloud Sentinel — FastAPI Backend (Unified Pipeline + ML Ensemble)
==================================================================
Entry point for the anomaly detection API.

Detection pipeline (unified flow):
    POST /process_log  →  Layer1Filter (quick gate — TTL, DDoS, spoofing)
                              ↓ PASS → traffic allowed (AI model keeps learning)
                              ↓ FAIL → Layer2Scanner (deep forensics)
                                           ↓
                                       AI Model — ML Ensemble
                                       (Isolation Forest + Random Forest)
                                       BLOCK only when both models agree
                                           ↓
                                       Decision: ALLOW / INVESTIGATE / BLOCK
                                           ↓ if suspicious
                                       Alert → Real-Time Alerts → User → ALLOW or BLOCK

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
import os

from backend.detection.sarima_forecaster import SARIMAForecaster
from backend.storage.in_memory_store import AlertStore
from backend.detection.layer1_filter import Layer1Filter
from backend.detection.layer2_scanner import Layer2Scanner
from backend.detection.ai_model import EnsembleAnomalyDetector

# Layer2Investigator is optional — the API starts normally without it.
# Endpoints that require it return 503 until Saleem's file is in place.
try:
    from backend.detection.layer2_investigator import Layer2Investigator
    _L2_AVAILABLE = True
except ImportError:
    _L2_AVAILABLE = False

app = FastAPI(title="Cloud Sentinel API", version="3.0")

# ---------------------------------------------------------------------------
# Environment-based configuration
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
# Module-level singletons
# ---------------------------------------------------------------------------

# SARIMA for temporal analysis — runs in parallel, feeds temporal scores
sarima_forecaster = SARIMAForecaster()

# The AI Model — real ML ensemble (Isolation Forest + Random Forest).
# Phase 1 (first 200 requests): collects normal traffic, trains Isolation Forest
# Phase 2: Isolation Forest scores every packet
# Phase 3: Once enough labeled data, Random Forest joins → full ensemble
# BLOCK only when both models agree → low false positives
ai_model = EnsembleAnomalyDetector(learning_window=200)

alert_store    = AlertStore()
layer2         = Layer2Investigator() if _L2_AVAILABLE else None
log_storage    = []        # in-memory audit log for the Behaviour Logs page
lambda_metrics = {}        # per-function invocation stats for Lambda monitor
layer1_filter  = Layer1Filter()   # Stage 1: hard rule gate
layer2_scanner = Layer2Scanner()  # Stage 2: deep forensic scan


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class LogRequest(BaseModel):
    """
    A single Lambda execution event.

    Includes both basic fields (always sent) and packet-level fields
    (with sensible defaults) so the unified pipeline can run Layer 1
    Filter checks on every request.
    """
    # Basic fields (always present)
    duration:      float          # execution time in ms
    memory_used:   float          # memory consumed in MB
    num_api_calls: int            # outbound API calls made during execution
    function_name: str  = "unknown"
    ip_address:    str  = "10.0.0.1"
    error_count:   int  = 0

    # Packet-level fields (defaults = normal traffic values)
    # These allow Layer1Filter to run on every request.
    # When sent by generate_test_data with attack patterns,
    # these will carry realistic attack values.
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
    """
    Construct a frontend-compatible alert record from the unified pipeline.
    """
    # Map internal severity to frontend contract (CRITICAL / WARNING / INFO)
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
        "decision":       decision,     # ALLOW / INVESTIGATE / BLOCK
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

    # Attach Layer 2 report if available (for investigation page)
    if layer2_report:
        alert["layer2_report"] = layer2_report

    # Attach AI model details if available
    if ai_result:
        alert["ai_details"] = {
            "composite_score": ai_result.get("anomaly_score", 0),
            "severity":        ai_result.get("severity"),
            "attack_type":     ai_result.get("attack_type"),
            "components":      ai_result.get("components", {}),
        }

    return alert


def _build_log_entry(log_request: LogRequest, result: dict) -> dict:
    """Build an audit log entry for every request."""
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
    """Track per-function invocation stats."""
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
# CORE DETECTION ENDPOINT — Unified Pipeline
# ---------------------------------------------------------------------------

@app.post("/process_log")
def process_log(request: LogRequest):
    """
    Main detection pipeline for Lambda execution events.

    Unified flow:
        1. SARIMA — feed data point for temporal learning
        2. Layer 1 Filter — hard rule gate (TTL, DDoS, spoofing, etc.)
              ↓ PASS → traffic is normal, feed AI model for learning
              ↓ FAIL → escalate to Layer 2
        3. Layer 2 Scanner — deep forensic analysis
              (IP reputation, packet analysis, attack patterns,
               network topology, risk scoring)
        4. AI Model — ML Ensemble (Isolation Forest + Random Forest)
              Combines its own score with Layer 2 risk score.
              BLOCK only when both models agree → low false positives.
        5. If INVESTIGATE or BLOCK → create alert for dashboard
        6. Feed labeled example back to AI model for continuous learning
    """

    # Build the full packet dict for all layers
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
        "concurrency":          1,
    }

    # ── STEP 0: Feed SARIMA (always, for temporal learning) ───────────────
    sarima_forecaster.add_data_point(
        request.duration,
        datetime.datetime.utcnow().isoformat(),
    )

    # ── STEP 1: Layer 1 Filter — hard rule gate ──────────────────────────
    l1_result = layer1_filter.check(packet)

    if l1_result["pass"]:
        # ── NORMAL TRAFFIC — passed all hard rules ───────────────────────
        # Feed the AI model so it keeps learning the normal baseline.
        # During learning phase, this builds the Isolation Forest training set.
        # After learning, normal traffic also acts as labeled "normal" examples.
        ai_result = ai_model.predict(packet)

        # Also feed as labeled normal example for Random Forest training
        ai_model.add_labeled_example(packet, is_anomaly=False, attack_type="normal")

        result = {
            "decision":   "ALLOW",
            "layer":      1,
            "is_anomaly": False,
            "message":    "Passed Layer 1 — normal traffic",
            "layer1":     l1_result,
            "ai_model": {
                "phase":    ai_result.get("phase"),
                "score":    ai_result.get("anomaly_score", 0),
            },
        }
        log_storage.append(_build_log_entry(request, result))
        _update_lambda_metrics(request, is_anomaly=False)
        return result

    # ── STEP 2: Layer 2 Scanner — deep forensic analysis ─────────────────
    # Traffic failed Layer 1, run full deep scan
    l2_result = layer2_scanner.scan(packet, l1_result)

    # ── STEP 3: AI Model — ML Ensemble decision ─────────────────────────
    # Pass Layer 2 risk score so the ensemble can factor it in
    l2_risk = l2_result.get("risk", {}).get("adjusted_score", 0)
    ai_result = ai_model.predict(packet, l2_risk_score=l2_risk)

    decision      = ai_result["decision"]
    anomaly_score = ai_result["anomaly_score"]
    confidence    = ai_result["confidence"]
    attack_type   = ai_result.get("attack_type")
    is_anomaly    = ai_result["is_anomaly"]

    # Get better threat type from Layer 2 patterns if AI model doesn't have one
    if not attack_type:
        top_threat = l2_result.get("patterns", {}).get("top_threat")
        if top_threat:
            attack_type = top_threat.get("name", "Unknown")
        else:
            attack_type = l2_result.get("risk", {}).get(
                "recommendation", {}
            ).get("action", "Unknown")

    # During AI learning phase — fall back to Layer 2 severity for decision
    if ai_result.get("phase") == "learning":
        l2_severity = l2_result.get("severity", "MEDIUM")
        if l2_severity == "CRITICAL":
            decision, confidence = "BLOCK", 0.85
        elif l2_severity == "HIGH":
            decision, confidence = "BLOCK", 0.72
        else:
            decision, confidence = "INVESTIGATE", 0.60
        is_anomaly = decision in ("INVESTIGATE", "BLOCK")

    severity = l2_result.get("severity", "MEDIUM")

    # ── STEP 4: Create alert (only for INVESTIGATE or BLOCK) ─────────────
    if is_anomaly:
        alert = _build_alert(
            log_request=request,
            decision=decision,
            severity=severity,
            confidence=confidence,
            anomaly_score=anomaly_score,
            threat_type=attack_type,
            layer2_report=l2_result,
            ai_result=ai_result,
        )
        alert_store.add(alert)

    # ── STEP 5: Feed labeled example back to AI model ────────────────────
    # This is how the Random Forest accumulates training data.
    # Layer 2's decision acts as the label.
    ai_model.add_labeled_example(
        packet,
        is_anomaly=is_anomaly,
        attack_type=attack_type if is_anomaly else "normal",
    )

    # ── STEP 6: Log everything ───────────────────────────────────────────
    risk = l2_result.get("risk", {})
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
            "severity":      l2_result.get("severity"),
            "risk_score":    risk.get("adjusted_score", 0),
            "threat_count":  l2_result.get("patterns", {}).get("threat_count", 0),
            "scan_id":       l2_result.get("scan_id"),
            "elapsed_ms":    l2_result.get("elapsed_ms"),
        },
        "ai_model": {
            "phase":         ai_result.get("phase"),
            "score":         ai_result.get("anomaly_score", 0),
            "is_anomaly":    ai_result.get("is_anomaly", False),
            "model_votes":   ai_result.get("model_votes"),
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

    # Sort newest first
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
    """Mark an alert as CLOSED once an analyst has reviewed it."""
    if not alert_store.close(alert_id):
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return {"success": True}


# ---------------------------------------------------------------------------
# NEW: User action endpoints — ALLOW and BLOCK
# ---------------------------------------------------------------------------

@app.patch("/api/alerts/{alert_id}/allow")
def allow_alert(alert_id: str):
    """
    User reviewed the alert and determined it is not a threat.
    Marks the alert as ALLOWED and CLOSED.

    This is the "false positive" path — the analyst sees the
    investigation details and decides the traffic is legitimate.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    alert["status"]      = "CLOSED"
    alert["resolution"]  = "ALLOWED"
    alert["resolved_by"] = "analyst"
    alert["resolved_at"] = datetime.datetime.utcnow().isoformat() + "Z"

    # Feed outcome to AI model — this was a false positive
    ai_model.record_outcome(predicted_anomaly=True, true_anomaly=False)

    # Log the user action
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
        "message":    f"Alert {alert_id} marked as allowed. Traffic from this source is permitted.",
    }


@app.patch("/api/alerts/{alert_id}/block")
def block_alert(alert_id: str):
    """
    User reviewed the alert and confirmed it is a threat.
    Marks the alert as BLOCKED and CLOSED.

    This is the "confirmed threat" path — the analyst sees the
    investigation details and decides to block the traffic.
    In production, this would trigger a WAF rule or security group update.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    alert["status"]      = "CLOSED"
    alert["resolution"]  = "BLOCKED"
    alert["resolved_by"] = "analyst"
    alert["resolved_at"] = datetime.datetime.utcnow().isoformat() + "Z"

    # Feed outcome to AI model — this was a true positive (confirmed threat)
    ai_model.record_outcome(predicted_anomaly=True, true_anomaly=True)

    # Log the user action
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
# Investigation endpoint (Layer 2 Investigator)
# ---------------------------------------------------------------------------

@app.post("/api/alerts/{alert_id}/investigate")
def investigate_alert(alert_id: str):
    """
    Trigger a Layer 2 forensic investigation on a flagged alert.

    If the alert already has a Layer 2 report attached (from the
    pipeline), return it directly. Otherwise, delegate to
    Layer2Investigator for a fresh investigation.
    """
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")

    # If the alert already has a Layer 2 report from the pipeline, return it
    if alert.get("layer2_report"):
        return {
            "alert_id":   alert_id,
            "source":     "pipeline",
            "report":     alert["layer2_report"],
            "ai_details": alert.get("ai_details"),
            "message":    "Layer 2 report from detection pipeline.",
        }

    # Otherwise, run a fresh Layer 2 investigation
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
    """Return the most recent audit log entries for the Behaviour Logs page."""
    return log_storage[-limit:]


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

    total_inv   = sum(m["invocations"]    for m in lambda_metrics.values())
    total_dur   = sum(m["total_duration"] for m in lambda_metrics.values())
    total_err   = sum(m["error_count"]    for m in lambda_metrics.values())

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
        "accuracy":        perf.get("accuracy", 90.0),
        "precision":       perf.get("precision", 95.0),
        "recall":          perf.get("recall", 40.0),
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
        "pipeline":         "unified",  # confirms new pipeline is active
        "timestamp":        datetime.datetime.utcnow().isoformat() + "Z",
    }


# ---------------------------------------------------------------------------
# Packet report endpoint (for alerts created via old /api/scan path)
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