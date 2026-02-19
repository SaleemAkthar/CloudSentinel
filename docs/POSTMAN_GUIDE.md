Documentation on the postman Testing for Cloud sentinel API

##Test 1 - Health Check

this was just to check whether the API is running or not

Response : 
{
    "status": "running",
    "detector_stats": {
        "learning_phase": true,
        "requests_seen": 0,
        "anomalies_detected": 0,
        "learning_progress": 0.0,
        "baseline": {
            "duration": {
                "n": 0,
                "mean": 0.0,
                "std": 0.0,
                "variance": 0.0
            },
            "memory_used": {
                "n": 0,
                "mean": 0.0,
                "std": 0.0,
                "variance": 0.0
            },
            "num_api_calls": {
                "n": 0,
                "mean": 0.0,
                "std": 0.0,
                "variance": 0.0
            }
        }
    },
    "timestamp": "2026-02-15T23:09:09.147568"
}

Conclusion - Response is as expected , API is running.

___________________________________________________________________________________

##Test 2 - Process Normal Logs

whether it can process normal logs

Response : 

{
    "phase": "learning",
    "progress": 1.0,
    "message": "Learning: 1/100",
    "timestamp": "2026-02-15T23:12:31.954781",
    "requests_seen": 1,
    "anomalies_detected": 0
}

Conclusion - Response is as expected , API is processing normal logs.

___________________________________________________________________________________

##Test 3 - Process Anomalous Logs

whether it can process anomalous logs (Only Crpto mining , data exfiltration and memory attack for now)

Response after the 100 requests: 

{
    "phase": "detection",
    "is_anomaly": false,
    "anomaly_score": 0.023570226039998265,
    "z_scores": {
        "duration": 0.07071067811868668,
        "memory_used": 0.07071067811999479,
        "num_api_calls": 0.0
    },
    "features": {
        "duration": 500.0,
        "memory_used": 130.0,
        "num_api_calls": 3.0
    },
    "baseline": {
        "duration": {
            "n": 201,
            "mean": 499.7512437810944,
            "std": 3.5267280792930022,
            "variance": 12.437810945273709
        },
        "memory_used": {
            "n": 201,
            "mean": 129.9900497512436,
            "std": 0.1410691231717246,
            "variance": 0.01990049751243921
        },
        "num_api_calls": {
            "n": 201,
            "mean": 3.0,
            "std": 0.0,
            "variance": 0.0
        }
    },
    "message": "Normal (Score: 0.02)",
    "timestamp": "2026-02-16T01:35:07.380167",
    "requests_seen": 204,
    "anomalies_detected": 3
}

Conclusion - Before the 100 logs it showed as learning phase and after the 100 logs it showed as detection phase and detected 3 anomalies.

___________________________________________________________________________________

##Test 4 - Process Anomalous Logs (Crypto Mining)

whether it can process anomalous logs (Crypto Mining)
 
Response : 

{
    "phase": "detection",
    "is_anomaly": true,
    "anomaly_score": 1.0,
    "z_scores": {
        "duration": 2687.0764791869906,
        "memory_used": 2262.8124104749936,
        "num_api_calls": 0.0
    },
    "features": {
        "duration": 10000.0,
        "memory_used": 450.0,
        "num_api_calls": 2.0
    },
    "baseline": {
        "duration": {
            "n": 200,
            "mean": 499.7499999999999,
            "std": 3.535533905932749,
            "variance": 12.500000000000078
        },
        "memory_used": {
            "n": 200,
            "mean": 129.9899999999998,
            "std": 0.14142135623731442,
            "variance": 0.020000000000001388
        },
        "num_api_calls": {
            "n": 200,
            "mean": 3.0,
            "std": 0.0,
            "variance": 0.0
        }
    },
    "message": "ANOMALY DETECTED (Score: 1.00)",
    "timestamp": "2026-02-16T00:46:50.957398",
    "requests_seen": 201,
    "anomalies_detected": 1
}

Conclusion - It detected the anomaly and showed the anomaly score and z-score and features and baseline and message and timestamp and requests_seen and anomalies_detected.


