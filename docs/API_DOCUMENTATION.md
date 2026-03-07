# Cloud Sentinel — API Documentation

**Version:** 2.0  
**Base URL:** `http://localhost:8000`  
**Auth:** None (development)

---

## Overview

The Cloud Sentinel API accepts Lambda execution logs, runs them through a two-layer anomaly detection system, and exposes the results to the React frontend.

```
Client → POST /process_log → OnlineDetector (Layer 1)
                            → SARIMAForecaster (temporal)
                            → AlertStore (if anomaly)

Client → POST /api/alerts/{id}/investigate → Layer2Investigator
                                           → Investigation Report
```

---

## Endpoints

### System

#### `GET /status`
Health check. Returns API state, detector progress, and SARIMA status.

**Response**
```json
{
  "status": "running",
  "detector_stats": {
    "requests_processed": 150,
    "anomalies_found": 3,
    "phase": "Detection"
  },
  "sarima_status": {
    "trained": false,
    "data_points": 150,
    "min_required": 200,
    "progress_pct": 75.0,
    "using_fallback": true
  },
  "layer2_available": true,
  "timestamp": "2026-03-06T14:30:00Z"
}
```

---

### Detection

#### `POST /process_log`
Core detection endpoint. Accepts a Lambda execution record, scores it through Layer 1 (statistical) and SARIMA (temporal), and stores an alert if anomalous.

**Request Body**
```json
{
  "duration":      500,
  "memory_used":   130,
  "num_api_calls": 3,
  "function_name": "paymentHandler",
  "ip_address":    "192.168.1.10"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `duration` | float | ✅ | Execution time in milliseconds |
| `memory_used` | float | ✅ | Memory consumed in MB |
| `num_api_calls` | int | ✅ | Number of outbound API calls |
| `function_name` | string | ❌ | Lambda function name (default: `"unknown"`) |
| `ip_address` | string | ❌ | Source IP address (default: `"10.0.0.1"`) |

**Response — Learning Phase**
```json
{
  "phase": "learning",
  "progress": 45.0
}
```

**Response — Detection Phase (Normal)**
```json
{
  "is_anomaly": false,
  "anomaly_score": 0.82,
  "normalised_score": 0.08,
  "temporal_anomaly_score": 0.02,
  "timestamp": "2026-03-06T14:30:00",
  "features": { "duration": 500, "memory_used": 130, "num_api_calls": 3 }
}
```

**Response — Detection Phase (Anomaly)**
```json
{
  "is_anomaly": true,
  "threat_type": "Crypto Mining",
  "severity": "CRITICAL",
  "confidence": 0.95,
  "anomaly_score": 9.4,
  "normalised_score": 0.94,
  "temporal_anomaly_score": 0.87,
  "z_scores": {
    "duration": 9.4,
    "memory_used": 6.2,
    "num_api_calls": -0.3
  },
  "timestamp": "2026-03-06T14:30:00",
  "features": { "duration": 12000, "memory_used": 420, "num_api_calls": 1 }
}
```

---

### Alerts

#### `GET /api/alerts`
Return stored alerts with optional filtering.

**Query Parameters**

| Param | Type | Description |
|---|---|---|
| `severity` | string | Filter: `CRITICAL`, `WARNING`, or `INFO` |
| `status` | string | Filter: `OPEN` or `CLOSED` |
| `limit` | int | Max results (default: 100) |

**Example**
```
GET /api/alerts?severity=CRITICAL&status=OPEN&limit=10
```

**Response**
```json
[
  {
    "id": "ALERT-A1B2C3",
    "timestamp": "2026-03-06T14:30:00Z",
    "function": "paymentHandler",
    "severity": "CRITICAL",
    "threat_type": "Crypto Mining",
    "status": "OPEN",
    "anomaly_score": 0.94,
    "confidence": 0.95,
    "features": {
      "duration_ms": 12000,
      "memory_used_mb": 420,
      "outbound_calls": 1,
      "ip_address": "45.33.32.156"
    },
    "z_scores": { "duration": 9.4, "memory_used": 6.2, "num_api_calls": -0.3 }
  }
]
```

---

#### `GET /api/alerts/summary`
Return alert counts grouped by severity.

**Response**
```json
{
  "CRITICAL": 2,
  "WARNING":  5,
  "INFO":     1,
  "total":    8,
  "open":     6,
  "closed":   2
}
```

---

#### `GET /api/alerts/{alert_id}`
Fetch a single alert by ID.

**Response** — same structure as a single item from `GET /api/alerts`  
**Error** — `404` if alert not found

---

#### `PATCH /api/alerts/{alert_id}/close`
Mark an alert as `CLOSED` (acknowledged by a team member).

**Response**
```json
{ "success": true }
```

**Error** — `404` if alert not found

---

#### `POST /api/alerts/{alert_id}/investigate`
Trigger a Layer 2 deep forensic investigation on an existing alert.

**Response**
```json
{
  "alert_id": "ALERT-A1B2C3",
  "investigation_time": "2026-03-06T14:32:00Z",
  "risk_score": 0.87,
  "risk_level": "CRITICAL",
  "ip_analysis": {
    "address": "45.33.32.156",
    "is_private": false,
    "reputation_score": 0.28,
    "reputation_label": "UNKNOWN",
    "spoofing_detected": false,
    "spoofing_indicators": []
  },
  "packet_analysis": {
    "size_ratio": 0.1,
    "exfiltration_risk": 0.0,
    "fragmentation_risk": 0.0,
    "overall_packet_score": 0.0
  },
  "matched_patterns": [
    {
      "attack_type": "crypto_mining",
      "confidence": 0.95,
      "indicators": [
        "Execution duration > 5× baseline",
        "Memory usage > 2× baseline"
      ],
      "description": "Lambda executed for 12000ms using 420MB — consistent with crypto-mining."
    }
  ],
  "recommendations": [
    {
      "priority": "IMMEDIATE",
      "action": "Block IP 45.33.32.156 at AWS WAF",
      "reason": "Risk score 0.87 — critical threat confirmed"
    },
    {
      "priority": "HIGH",
      "action": "Review Lambda execution role permissions",
      "reason": "Crypto-mining may indicate compromised deployment pipeline"
    }
  ],
  "timeline": [
    { "time": "2026-03-06T14:30:00Z", "event": "Anomalous request detected", "type": "alert" },
    { "time": "2026-03-06T14:32:00Z", "event": "Layer 2 investigation completed", "type": "info" }
  ],
  "summary": "Investigation complete. Severity: CRITICAL. Most likely attack: Crypto Mining (confidence 95%). Overall risk level: CRITICAL."
}
```

**Error** — `404` if alert not found, `503` if Layer 2 not available

---

### Logs

#### `GET /api/logs`
Return audit-log entries (every request, not just anomalies).

**Query Parameters**

| Param | Type | Description |
|---|---|---|
| `limit` | int | Max entries (default: 100) |

**Response**
```json
[
  {
    "timestamp": "2026-03-06T14:30:00Z",
    "function":  "paymentHandler",
    "event":     "Anomaly Detected",
    "user":      "system",
    "ip_address": "45.33.32.156",
    "status":    "blocked",
    "duration":  "12000ms"
  }
]
```

---

### Lambda Monitor

#### `GET /api/lambda/overview`
Return aggregate Lambda metrics across all functions.

**Response**
```json
{
  "total_invocations":  352,
  "avg_response_time":  512.3,
  "error_rate":         2.84,
  "active_functions":   5,
  "functions": [ ... ]
}
```

---

#### `GET /api/lambda/functions`
Return per-function Lambda metrics.

**Response**
```json
[
  {
    "function_name":   "paymentHandler",
    "invocations":     85,
    "avg_duration_ms": 523.1,
    "avg_memory_mb":   132.4,
    "error_count":     3,
    "error_rate_pct":  3.53
  }
]
```

---

### Model Health

#### `GET /api/model/health`
Return AI model performance metrics for the dashboard health card.

**Response**
```json
{
  "accuracy":        94.7,
  "precision":       96.2,
  "recall":          40.0,
  "trainingActive":  false,
  "delta":           2.3,
  "sarima_trained":  true,
  "sarima_progress": 100.0
}
```

---

## Error Format

All errors follow a consistent structure:

```json
{
  "detail": "Alert 'ALERT-XYZ' not found."
}
```

| Code | Meaning |
|---|---|
| `404` | Resource not found |
| `422` | Invalid request body (Pydantic validation) |
| `503` | Service unavailable (e.g. Layer 2 not loaded) |

---

## Frontend Integration Notes

- The Vite dev server at `http://localhost:5173` is already whitelisted in CORS.
- Set `USE_MOCK = false` in `frontend/src/services/api.js` to connect to the live API.
- Add `proxy: { '/api': 'http://localhost:8000' }` to `vite.config.js` to avoid CORS issues in dev.
- The frontend contract requires `severity` to be one of `CRITICAL`, `WARNING`, `INFO` — the API maps backend values accordingly.