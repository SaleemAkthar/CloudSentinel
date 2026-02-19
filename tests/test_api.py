import requests

def test_api_integration():
    url = "http://127.0.0.1:8000/process_log"
    
    # Matching your LogRequest model in api.py
    sample_log = {
        "duration": 200.5,
        "memory_used": 128.0,
        "num_api_calls": 3
    }
    
    response = requests.post(url, json=sample_log)
    print(f"Status Code: {response.status_code}")
    
    data = response.json()
    print(f"Current Phase: {data.get('phase', 'unknown')}")

    # Robust checking:
    if data.get('phase') == 'learning':
        print(f"✅ Success: System is in learning mode. Progress: {data.get('progress')}")
    elif 'is_anomaly' in data:
        print(f"✅ Success: System is in detection mode. Anomaly: {data['is_anomaly']}")
    else:
        print("❌ Unexpected Response Format:", data)

if __name__ == "__main__":
    test_api_integration()