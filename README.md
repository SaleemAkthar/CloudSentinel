# Cloud Sentinel

An AI-powered real-time security monitoring platform for AWS Lambda functions. Cloud Sentinel detects anomalous runtime behaviour — including crypto mining, data exfiltration, SQL injection, and DDoS attacks — by analysing execution logs through a multi-layer detection pipeline and surfacing alerts on a live dashboard.

**Module:** 5COSC021C — Software Development Group Project
**Institution:** Informatics Institute of Technology (IIT) / University of Westminster

---

## How It Works

Every Lambda execution event passes through three detection stages:

1. **Layer 1 — Weighted Anomaly Scorer** builds a statistical baseline from the first 100 requests using Welford's online algorithm, then scores incoming events across four components: feature anomaly, packet anomaly, temporal anomaly (SARIMA), and behavioural anomaly. A composite score above the threshold triggers an alert.

2. **SARIMA Forecaster** runs in parallel with Layer 1, learning the time-series pattern of Lambda durations to detect temporally unusual spikes that statistical z-scoring alone might miss.

3. **Layer 2 — Deep Forensic Scanner** runs only on events that failed Layer 1. It performs IP reputation checks, payload analysis, and risk scoring to produce a detailed investigation report.

---

## Project Structure

```
CloudSentinel/
│
├── backend/
│   ├── api.py                        # FastAPI entry point — all HTTP endpoints
│   ├── generate_test_data.py         # Test data generator (4 phases)
│   ├── data_generator.py             # Synthetic log generation utilities
│   ├── log_parser.py                 # CloudWatch log parsing utilities
│   ├── severity_classifier.py        # Legacy severity labelling (deprecated)
│   ├── requirements.txt              # Python dependencies
│   │
│   ├── detection/
│   │   ├── layer1_scorer.py          # Weighted composite anomaly scorer (Raneesha)
│   │   ├── layer1_filter.py          # Fast TTL + packet size gate
│   │   ├── layer2_investigator.py    # Deep forensic investigation (Saleem)
│   │   ├── layer2_scanner.py         # Packet-level deep scanner
│   │   ├── sarima_forecaster.py      # SARIMA time-series forecaster (Okitha)
│   │   ├── pipeline.py               # Unified detection pipeline
│   │   ├── attack_patterns.py        # Known attack signature patterns
│   │   ├── ip_analyzer.py            # IP reputation and geolocation analysis
│   │   ├── packet_analyzer.py        # Packet header and payload analysis
│   │   ├── risk_scorer.py            # Risk score aggregation
│   │   ├── network_topology.py       # Network graph analysis
│   │   └── online_detector.py        # Legacy statistical detector (deprecated)
│   │
│   ├── models/
│   │   ├── alert.py                  # Alert and AlertDetail Pydantic models
│   │   ├── log.py                    # Log entry model
│   │   ├── insight.py                # AI insight model
│   │   └── weighted_score.py         # Weighted score model
│   │
│   ├── storage/
│   │   └── in_memory_store.py        # In-memory alert store for the session
│   │
│   ├── services/
│   │   ├── alert_service.py          # Alert business logic
│   │   ├── insight_service.py        # AI insight generation
│   │   ├── lambda_service.py         # Lambda metrics aggregation
│   │   └── log_service.py            # Log retrieval and filtering
│   │
│   └── utils/
│       ├── formula.py                # Welford stats, z-scores, anomaly formulas
│       ├── weights.py                # Detection thresholds and component weights
│       ├── helpers.py                # Shared utility functions
│       └── validators.py             # Input validation helpers
│
├── frontend/
│   ├── src/
│   │   ├── components/               # Reusable React UI components
│   │   ├── pages/                    # Dashboard page views
│   │   │   ├── Dashboard.jsx         # Main overview dashboard
│   │   │   ├── RealTimeAlerts.jsx    # Live alert feed
│   │   │   ├── BehaviourLogsPage.jsx # Audit log viewer
│   │   │   ├── AWSLambdaMonitorPage.jsx # Lambda function metrics
│   │   │   ├── AIInsights.jsx        # AI-generated security insights
│   │   │   ├── Investigate.jsx       # Alert investigation page
│   │   │   └── Signup.jsx            # User registration
│   │   ├── services/
│   │   │   └── api.js                # Axios API client
│   │   └── App.jsx                   # Root application component
│   ├── vite.config.js                # Vite config with backend proxy
│   └── package.json
│
├── simulation/
│   ├── deploy.py                     # Deploys Lambda functions to LocalStack
│   └── lambda_functions/
│       ├── api_handler/              # Simulates REST API Lambda
│       ├── file_processor/           # Simulates S3 file processing Lambda
│       ├── db_query/                 # Simulates DynamoDB query Lambda
│       └── auth_service/             # Simulates auth/token validation Lambda
│
├── tests/
│   ├── test_sarima.py                # SARIMA forecaster unit tests (30 tests)
│   ├── test_integration.py           # End-to-end pipeline integration tests
│   ├── test_layer1_scorer.py         # Layer 1 scorer unit tests
│   ├── test_layer2_scanner.py        # Layer 2 scanner unit tests
│   ├── test_formulas.py              # Mathematical formula unit tests
│   ├── simulate_traffic.py           # Traffic simulation script
│   └── run_all.py                    # Master test runner
│
└── docs/
    ├── API_DOCUMENTATION.md          # Full endpoint reference
    ├── FORMULA_SPECIFICATION.md      # Detection formula specification
    └── POSTMAN_GUIDE.md              # Postman collection guide
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- Docker Desktop (for LocalStack simulation)

### 1. Install backend dependencies

```bash
pip install -r backend/requirements.txt
```

### 2. Start the backend

Run from the project root — not from inside the `backend/` folder.

```bash
python -m uvicorn backend.api:app --reload --port 8000
```

Verify the API is running:

```
http://localhost:8000/status
```

### 3. Populate test data (optional)

```bash
python -m backend.generate_test_data
```

### 4. Start the frontend

```bash
cd frontend
npm install
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

> The Vite dev server is configured to proxy `/api`, `/process_log`, and `/status` to `http://localhost:8000`, so the backend must be running before using the frontend.

---

## Running Tests

```bash
# Run all your tests
python -m pytest tests/test_sarima.py tests/test_integration.py -v

# Run a specific test file
python -m pytest tests/test_layer1_scorer.py -v

# Run everything
python -m pytest tests/ -v
```

---

## LocalStack Simulation

The simulation environment generates a realistic dataset by deploying real Lambda functions to LocalStack (a local AWS emulator) and invoking them with normal and attack traffic patterns.

### Prerequisites

```bash
pip install boto3 localstack awscli-local --trusted-host pypi.org --trusted-host files.pythonhosted.org
```

Configure dummy AWS credentials (LocalStack does not validate these):

```bash
aws configure
# Access Key ID: test
# Secret Access Key: test
# Region: us-east-1
# Output format: json
```

### Run the simulation

```bash
# 1. Make sure Docker Desktop is running

# 2. Start LocalStack
localstack start -d

# 3. Verify services are available
localstack status services

# 4. Deploy Lambda functions
python simulation/deploy.py

# 5. Verify deployment
awslocal lambda list-functions
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/process_log` | Submit a Lambda execution event for detection |
| `POST` | `/api/scan` | Submit a full packet for Layer 1 + Layer 2 scanning |
| `GET` | `/api/alerts` | List alerts (filter by severity, status, limit) |
| `GET` | `/api/alerts/summary` | Alert counts by severity |
| `GET` | `/api/alerts/{id}` | Get a single alert |
| `PATCH` | `/api/alerts/{id}/close` | Mark an alert as closed |
| `POST` | `/api/alerts/{id}/investigate` | Trigger Layer 2 forensic investigation |
| `GET` | `/api/logs` | Retrieve audit log entries |
| `GET` | `/api/lambda/overview` | Aggregate Lambda metrics |
| `GET` | `/api/lambda/functions` | Per-function Lambda metrics |
| `GET` | `/api/model/health` | Detection model performance metrics |
| `GET` | `/status` | API health check |

Full documentation: [`docs/API_DOCUMENTATION.md`](docs/API_DOCUMENTATION.md)

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.14, FastAPI, Uvicorn |
| ML / Detection | SARIMA (statsmodels), Welford online statistics, weighted composite scoring |
| Frontend | React 19, Tailwind CSS, Material UI, Recharts, Vite |
| Simulation | LocalStack, boto3, AWS CLI |
| Testing | Pytest |
| Version Control | Git, GitHub |

---

## Team

| Name | Responsibility |
|------|----------------|
| Raneesha | Layer 1 Scorer, mathematical formulas, detection weights |
| Okitha | SARIMA forecaster, API integration, LocalStack simulation |
| Saleem | Layer 2 investigator, attack pattern analysis, network analysis |
