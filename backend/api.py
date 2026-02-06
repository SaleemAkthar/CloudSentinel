from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import datetime

# Initialize the App
app = FastAPI(title="Cloud Sentinel API", version="1.0")

# --- DATA MODELS ---
class LogRequest(BaseModel):
    log_entry: str

# --- ENDPOINTS ---

# 1. Status Endpoint
@app.get("/status")
def get_status():
    return {
        "status": "running",
        "system": "Cloud Sentinel Backend",
        "timestamp": datetime.datetime.now().isoformat()
    }

# 2. Process Log Endpoint (MOCK VERSION)
@app.post("/process_log")
def process_log(request: LogRequest):
    # Mock response for Frontend team
    mock_response = {
        "analysis_timestamp": datetime.datetime.now().isoformat(),
        "anomaly_score": 0.95,
        "is_anomaly": True,
        "severity": "High",
        "threat_type": "Data Exfiltration",
        "details": "Mock analysis: Suspicious data transfer detected."
    }
    return mock_response

# --- RUNNER ---
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)