# Cloud Sentinel

An AI-powered real-time security monitoring platform for AWS Lambda functions. Cloud Sentinel detects anomalous runtime behaviour — such as crypto mining and data exfiltration — by analysing execution logs through an online statistical model and surfacing alerts on a live dashboard.

---

## Project Structure

```
CloudSentinel/
│
├── backend/
│   ├── api.py                  # FastAPI application — all HTTP endpoints
│   ├── online_detector.py      # Online statistical anomaly detection engine
│   ├── severity_classifier.py  # Threat labelling and severity scoring
│   ├── data_generator.py       # Synthetic log generation for testing
│   ├── log_parser.py           # CloudWatch log parsing utilities
│   ├── requirements.txt        # Python dependencies
│   │
│   ├── models/                 # Trained ML model artefacts
│   ├── services/               # AWS service integrations (CloudWatch, S3)
│   ├── storage/
│   │   └── in_memory_store.py  # In-memory alert store for the current session
│   └── utils/                  # Shared helper functions
│
├── frontend/
│   ├── src/
│   │   ├── components/         # Reusable React UI components
│   │   ├── pages/              # Dashboard page views
│   │   └── App.jsx             # Root application component
│   ├── public/
│   └── package.json
│
├── tests/
│   ├── test_online_stats.py    # Unit tests for the core statistical math
│   ├── test_severity.py        # Unit tests for threat and severity labelling
│   └── run_all.py              # Master test runner — run before every commit
│
├── docs/                       # Architecture diagrams and project documentation
├── .gitignore
└── README.md
```

---

## Getting Started

### Prerequisites

- Python 3.10+
- Node.js 18+
- AWS account with Lambda, CloudWatch, and S3 access

### Backend

```bash
# Install dependencies
pip install -r backend/requirements.txt

# Start the API server (run from the project root)
uvicorn backend.api:app --reload --port 8000
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

The dashboard will be available at `http://localhost:5173`.

---

## Running Tests

```bash
# Run all tests before committing
python -m tests.run_all

# Run a specific module
python -m pytest tests/test_severity.py -v
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Cloud Platform | AWS Lambda, CloudWatch, CloudTrail, S3 |
| Backend | Python, FastAPI, Scikit-learn |
| Frontend | React, Tailwind CSS, Material-UI |
| ML | Isolation Forest / One-Class SVM (Scikit-learn) |
| Testing | Pytest, Unittest |
| Version Control | Git, GitHub |

---

## Module: 5COSC021C — Software Development Group Project  
**Institution:** Informatics Institute of Technology (IIT) / University of Westminster
