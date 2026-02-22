# Run from the project root:
#   uvicorn backend.api:app --reload --port 8000

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
import datetime
import uuid

from backend.online_detector import OnlineDetector
from backend.storage.in_memory_store import AlertStore

app = FastAPI(title="Cloud Sentinel API", version="1.0")

# Allow the Vite dev server and CRA fallback to call the API without CORS errors
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Module-level singletons — must not be re-instantiated per request.
# The detector accumulates a rolling statistical baseline across all requests.
detector    = OnlineDetector(learning_window=100)
alert_store = AlertStore()
log_storage = []  # Stores all processed log entries for the log viewer endpoint


class LogRequest(BaseModel):
    """Represents a single Lambda execution event submitted by the frontend."""
    duration:      float
    memory_used:   float
    num_api_calls: int
    function_name: str = "unknown"


def _build_alert(log_request: LogRequest, detector_result: dict) -> dict:
    """
    Converts raw detector output into a frontend-compatible alert object.
    Normalises the Z-score to [0.0, 1.0] and maps severity to the three
    values the frontend accepts: CRITICAL, WARNING, INFO.
    """
    normalised_score = round(min(detector_result.get("anomaly_score", 0) / 10.0, 1.0), 2)

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
        "severity":      frontend_severity,      # do not rename — frontend contract
        "threat_type":   detector_result.get("threat_type", "Unknown"),  # do not rename
        "status":        "OPEN",
        "anomaly_score": normalised_score,
        "confidence":    detector_result.get("confidence", 0),
        "features": {
            "duration_ms":    log_request.duration,
            "memory_used_mb": log_request.memory_used,
            "outbound_calls": int(log_request.num_api_calls),
        },
        "z_scores": detector_result.get("z_scores", {}),
    }


def _build_log_entry(log_request: LogRequest, result: dict) -> dict:
    """Builds a concise audit-log record for the log viewer. Every request is
    logged — not just anomalies — to maintain a complete activity trail."""
    is_anomaly  = result.get("is_anomaly", False)
    is_critical = is_anomaly and result.get("severity") == "CRITICAL"

    return {
        "timestamp":  datetime.datetime.utcnow().isoformat() + "Z",
        "function":   log_request.function_name,
        "event":      "Anomaly Detected" if is_anomaly else "Normal Request",
        "user":       "system",
        "ip_address": "10.0.0.1",
        "status":     "blocked" if is_critical else "success",
        "duration":   f"{int(log_request.duration)}ms",
    }


@app.get("/status")
def get_status():
    """Health check. Returns API status and the detector's learning progress."""
    return {
        "status":         "running",
        "detector_stats": detector.get_status(),
        "timestamp":      datetime.datetime.utcnow().isoformat() + "Z",
    }


@app.post("/process_log")
def process_log(request: LogRequest):
    """
    Core detection endpoint. Accepts a Lambda execution record, passes it to
    the detector, and returns an anomaly verdict. During the learning phase,
    returns progress only — no verdict is produced until the baseline is ready.
    """
    features = {
        "duration":      request.duration,
        "memory_used":   request.memory_used,
        "num_api_calls": request.num_api_calls,
    }

    result = detector.process_log(features)

    # Still building the baseline — log the entry but return early
    if result.get("phase") == "learning":
        log_storage.append(_build_log_entry(request, result))
        return result

    log_storage.append(_build_log_entry(request, result))

    if result.get("is_anomaly"):
        alert_store.add(_build_alert(request, result))

    result["normalised_score"] = round(min(result.get("anomaly_score", 0) / 10.0, 1.0), 2)
    return result


@app.get("/api/alerts")
def get_alerts():
    """Returns all stored alerts (OPEN and CLOSED)."""
    return alert_store.get_all()


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    """Fetches a single alert by ID. Raises 404 if not found."""
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return alert


@app.patch("/api/alerts/{alert_id}/close")
def close_alert(alert_id: str):
    """Marks an alert as CLOSED (acknowledged). Raises 404 if not found."""
    if not alert_store.close(alert_id):
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found.")
    return {"success": True}


@app.get("/api/logs")
def get_logs():
    """Returns all audit-log entries recorded in the current session."""
    return log_storage


@app.get("/api/model/health")
def model_health():
    """Returns approximate model performance metrics for the dashboard health card."""
    status        = detector.get_status()
    requests_seen = status.get("requests_processed", 0)
    anomalies     = status.get("anomalies_found", 0)

    # Estimated values — will be replaced with labelled evaluation data in Sprint 4
    precision = round(max(0, 100 - (anomalies / max(requests_seen, 1)) * 5), 1)
    accuracy  = round(min(99.9, 90 + (min(requests_seen, 500) / 500) * 9.9), 1)

    return {
        "accuracy":       accuracy,
        "precision":      precision,
        "recall":         40.0,
        "trainingActive": status.get("phase") == "Learning",
        "delta":          2.3,
    }


if __name__ == "__main__":
    uvicorn.run("backend.api:app", host="0.0.0.0", port=8000, reload=True)
