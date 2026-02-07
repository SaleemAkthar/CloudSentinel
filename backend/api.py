from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uvicorn
import datetime
# Import the actual detector logic
from online_detector import OnlineDetector

# Initialize the App
app = FastAPI(title="Cloud Sentinel API", version="1.0")

# Initialize the Detector as a global object
detector = OnlineDetector()

# --- DATA MODELS ---
class LogRequest(BaseModel):
    duration: float
    memory_used: float
    num_api_calls: int

# --- ENDPOINTS ---

@app.get("/status")
def get_status():
    # Now returns real status from the detector!
    return {
        "status": "running",
        "detector_stats": detector.get_status(),
        "timestamp": datetime.datetime.now().isoformat()
    }

@app.post("/process_log")
def process_log(request: LogRequest):
    # Ensure we are passing the dictionary, not a list
    features = {
        "duration": request.duration,
        "memory_used": request.memory_used,
        "num_api_calls": request.num_api_calls
    }
    
    # This is where it was crashing before
    result = detector.process_log(features) 
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
