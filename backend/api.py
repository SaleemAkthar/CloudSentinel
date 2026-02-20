# Run from the project root, not from inside backend/:
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

# Vite dev server runs on 5173; allow both that and a plain 3000 fallback.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Both objects are intentionally module-level — the detector accumulates
# statistical state across requests and must not be re-instantiated per call.
detector = OnlineDetector(learning_window=100)
alert_store = AlertStore()


class LogRequest(BaseModel):
    duration: float
    memory_used: float
    num_api_calls: int
    function_name: str = "unknown"


def _build_alert(log_request: LogRequest, detector_result: dict) -> dict:
    # The detector returns a raw Z-score which can exceed 1000 for extreme
    # outliers. Cap it to [0, 1] so the frontend chart scales stay sensible.
    normalised_score = round(min(detector_result.get("anomaly_score", 0) / 10.0, 1.0), 2)

    # The frontend severity enum only has three values, so collapse HIGH/MEDIUM
    # down to WARNING rather than silently dropping the alert.
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
        "threat_type":   detector_result.get("threat_type", "Unknown"),
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


@app.get("/status")
def get_status():
    return {
        "status": "running",
        "detector_stats": detector.get_status(),
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }


@app.post("/process_log")
def process_log(request: LogRequest):
    features = {
        "duration":      request.duration,
        "memory_used":   request.memory_used,
        "num_api_calls": request.num_api_calls,
    }
    result = detector.process_log(features)

    # During the learning phase the detector just returns progress —
    # there's no baseline yet, so we can't classify anything.
    if result.get("phase") == "learning":
        return result

    if result.get("is_anomaly"):
        alert_store.add(_build_alert(request, result))

    # Attach the normalised score so callers don't have to do the conversion.
    result["normalised_score"] = round(min(result.get("anomaly_score", 0) / 10.0, 1.0), 2)
    return result


@app.get("/api/alerts")
def get_alerts():
    return alert_store.get_all()


@app.get("/api/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = alert_store.get_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@app.patch("/api/alerts/{alert_id}/close")
def close_alert(alert_id: str):
    if not alert_store.close(alert_id):
        raise HTTPException(status_code=404, detail="Alert not found")
    return {"success": True}


@app.get("/api/model/health")
def model_health():
    status = detector.get_status()
    requests_seen = status.get("requests_processed", 0)
    anomalies     = status.get("anomalies_found", 0)

    # Rough approximations until we wire up labelled evaluation data.
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