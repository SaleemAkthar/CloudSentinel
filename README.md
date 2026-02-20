CloudSentinel
A real-time anomaly detection system for AWS Lambda functions. CloudSentinel monitors serverless execution logs, learns what normal traffic looks like, and raises alerts when function behaviour deviates — catching threats like crypto mining, data exfiltration, and memory exhaustion without requiring labelled training data.
Built as part of an SDGP project.

How it works
The backend runs an online statistical model (Welford's algorithm) that maintains a rolling mean and standard deviation for three features per Lambda invocation: execution duration, memory consumption, and outbound API call count. Once enough baseline traffic has been observed, each new log is scored using a Z-score across all three features. If the max Z-score exceeds a configurable threshold, the log is classified by a rule-based threat classifier and stored as an alert.
Because the baseline updates continuously and only on non-anomalous traffic, the model adapts to gradual shifts in normal behaviour without being poisoned by the anomalies it detects.

Tech stack
LayerTechnologyBackend APIFastAPI, UvicornAnomaly detectionCustom online statistical model (pure Python)FrontendReact, Vite, Tailwind CSSChartsRechartsData validationPydanticTestingPython unittest

Project structure
CloudSentinal/
├── backend/
│   ├── api.py                  # FastAPI app and all HTTP endpoints
│   ├── online_detector.py      # Welford's algorithm + threat classification
│   ├── log_parser.py           # Parses and validates raw log input
│   ├── data_generator.py       # Synthetic log generator for testing
│   ├── severity_classifier.py  # Standalone threat classifier
│   ├── models/                 # Pydantic data models (Alert, Log, Insight)
│   ├── services/               # Business logic layer
│   ├── storage/
│   │   └── in_memory_store.py  # Runtime alert store
│   └── utils/
├── frontend/
│   ├── src/
│   │   ├── pages/              # Dashboard, Alerts, AI Insights, Lambda Monitor, Team
│   │   ├── components/         # Reusable UI components
│   │   └── services/api.js     # Axios wrapper for backend calls
│   └── vite.config.js
└── tests/
    ├── test_online_stats.py    # Core Welford math tests
    ├── test_severity.py        # Threat classification tests
    └── run_all.py              # Master test runner

Getting started
Prerequisites

Python 3.10+
Node.js 18+

Backend
bash# From the project root
pip install fastapi uvicorn pydantic requests numpy

# Start the API server
uvicorn backend.api:app --reload --port 8000
The API will be available at http://localhost:8000. Interactive docs are at http://localhost:8000/docs.

Note: Always run uvicorn from the project root, not from inside backend/. The imports are package-relative and will break otherwise.

Frontend
bashcd frontend
npm install
npm run dev
The frontend will be available at http://localhost:5173 and proxies all /api requests to the backend automatically.

API reference
MethodEndpointDescriptionGET/statusDetector status and learning progressPOST/process_logSubmit a Lambda log for analysisGET/api/alertsRetrieve all stored alertsGET/api/alerts/{id}Retrieve a single alert by IDPATCH/api/alerts/{id}/closeMark an alert as resolvedGET/api/model/healthModel accuracy and training status
Example: submitting a log
bashcurl -X POST http://localhost:8000/process_log \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 450.0,
    "memory_used": 128.0,
    "num_api_calls": 3,
    "function_name": "process_payment"
  }'
Response during learning phase:
json{ "phase": "learning", "progress": 42.0 }
Response after an anomaly is detected:
json{
  "is_anomaly": true,
  "threat_type": "Crypto Mining",
  "severity": "CRITICAL",
  "confidence": 0.95,
  "anomaly_score": 312.4,
  "normalised_score": 1.0
}

Threat types
ThreatTrigger conditionSeverityCrypto MiningDuration Z-score > 4.0 and memory Z-score > 2.0CRITICALData ExfiltrationAPI call count Z-score > 4.0HIGHMemory ExhaustionMemory Z-score > 5.0HIGHAnomalous BehaviourAny Z-score > 3.0 (no specific pattern match)MEDIUM

Running tests
bash# Run all test suites from the project root
python -m tests.run_all

# Run individual suites
python -m tests.test_online_stats   # Core Welford math
python -m tests.test_severity       # Threat classification
Run python -m tests.run_all before every commit. The script exits with a non-zero code on failure so it integrates cleanly with pre-commit hooks or CI.

Team
NameRoleSaleemBackend Lead — anomaly detection model, threat classificationOkithaAPI development and testing infrastructureKithminiFrontend — UI components and alert viewsRushenFrontend — dashboard and data visualisationRaneeshaTesting — integration and statistical validation
