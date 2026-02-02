# Serverless Anomaly Detection System - Implementation Prototype

**Status**: Early Implementation Phase 

This is the initial implementation of an **Online Learning Anomaly Detection System** for AWS Lambda serverless applications. The system learns what "normal" behavior looks like and detects deviations in real-time.

## Project Structure

```
serverless_anomaly_detector/
├── backend/
│   ├── online_detector.py      # Core detection logic (Welford's Algorithm)
│   ├── data_generator.py       # Test data generator
│   └── __init__.py
├── frontend/
│   ├── dashboard.py            # Streamlit dashboard
│   └── __init__.py
├── data/                        # Data storage (future)
├── logs/                        # Log files (future)
└── README.md
```

## What's Implemented

### ✅ Backend (Core Logic)
- **OnlineStats Class**: Implements Welford's Algorithm for efficient mean/variance calculation
- **OnlineDetector Class**: Main detection engine with two phases:
  - **Learning Phase**: Builds baseline statistics from first N requests
  - **Detection Phase**: Identifies anomalies while continuing to learn from normal requests
- **Data Generator**: Creates realistic test logs with normal and anomalous patterns

### ✅ Frontend (Dashboard)
- **Streamlit Dashboard**: Interactive web interface showing:
  - Real-time metrics (total requests, anomalies detected, phase status)
  - Learning progress indicator
  - Live detection results with color-coded alerts
  - Baseline statistics visualization

## Quick Start

### Installation

```bash
# Navigate to project directory
cd serverless_anomaly_detector

# Install dependencies
pip install streamlit pandas
```

### Running the Dashboard

```bash
# From the project root directory
streamlit run frontend/dashboard.py
```

The dashboard will open in your browser at `http://localhost:8501`

### Running Tests

```bash
# Test the backend detector directly
python backend/data_generator.py
```

## How It Works

### Phase 1: Learning (First 50 requests)
The model processes the first 50 requests to establish what "normal" looks like:
- Calculates mean and standard deviation for each feature
- Stores these as the baseline
- No anomaly detection yet

### Phase 2: Detection (After 50 requests)
The model now detects anomalies while continuing to adapt:
- Compares incoming requests to the baseline using Z-scores
- Flags requests that deviate significantly (Z-score > 2.5)
- **Important**: Does NOT learn from anomalies (prevents baseline corruption)
- Continues learning from normal requests (adapts to legitimate changes)

## Key Features

1. **Memory Efficient**: Uses Welford's Algorithm (O(1) space complexity)
2. **Adaptive**: Continues learning from normal behavior even during detection
3. **Robust**: Doesn't learn from anomalies to prevent baseline corruption
4. **Multi-feature**: Analyzes duration, memory usage, and API call counts
5. **Real-time**: Processes logs as they arrive

## Technical Details

### Welford's Algorithm
Enables online calculation of mean and variance without storing all data points:
```
mean = mean + (x - mean) / n
M2 = M2 + (x - mean_old) * (x - mean_new)
variance = M2 / (n - 1)
```

### Anomaly Scoring
Uses multi-feature Z-score approach:
```
z_score = |value - mean| / std_dev
anomaly_score = max(z_scores) / threshold
is_anomaly = anomaly_score > 0.8
```

## Next Steps (Development Roadmap)

- [ ] AWS CloudWatch integration (Boto3)
- [ ] Database persistence (Redis/SQLite)
- [ ] Advanced threat classification
- [ ] Performance optimization for high-volume streams
- [ ] Unit tests and integration tests
- [ ] API endpoints for production deployment
- [ ] Enhanced dashboard with historical trends

## Team Assignments

| Component | Assigned To | Status |
| :--- | :--- | :--- |
| Online Detector Core | Backend Lead | ✅ Complete |
| Data Generator | Backend Team | ✅ Complete |
| Streamlit Dashboard | Frontend Lead | ✅ Complete |
| AWS Integration | Backend Dev 2 | 🔄 In Progress |
| UI/UX Refinement | Frontend Dev 2 | 🔄 In Progress |
| Testing & Documentation | All | 🔄 In Progress |

## References

- Welford, B. P. (1962). "Note on a method for calculating corrected sums of squares and products." Technometrics, 4(3), 419-420.
- Online Machine Learning: https://en.wikipedia.org/wiki/Online_machine_learning
- Streamlit Documentation: https://docs.streamlit.io/

---

**Last Updated**: February 2, 2026  
**Implementation Status**: Early Prototype - Core Logic Complete
