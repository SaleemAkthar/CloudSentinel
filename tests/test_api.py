import requests

def test_api_integration():
    url = "http://127.0.0.1:8000/process_log"
    
    # Simulate a normal log
    sample_log = {
        "duration": 200,
        "memory_used": 128,
        "num_api_calls": 3
    }
    
    response = requests.post(url, json=sample_log)
    data = response.json()
    
    print(f"Status Code: {response.status_code}")
    print(f"Is Anomaly: {data['is_anomaly']}")
    print(f"Phase: {data['phase']}")

if __name__ == "__main__":
    test_api_integration()