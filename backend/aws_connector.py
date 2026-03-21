import boto3
import time
from datetime import datetime

# Import your entire Layer 1 & 2 Detection Engine
from backend.log_parser import parse_log
from backend.detection.pipeline import CloudSentinelPipeline

# Initialize the AWS CloudWatch Logs client
# It will automatically find the credentials you set in the Command Prompt
logs_client = boto3.client('logs')

# CHANGE THIS to your actual Lambda function's name
LOG_GROUP_NAME = '/aws/lambda/cloud-sentinel-test'

def continuous_aws_monitoring():
    # Initialize the complete Detection Pipeline (Layer 1 + 2 + AI)
    print("Initializing Cloud Sentinel AI Pipeline...")
    pipeline = CloudSentinelPipeline()
    print(f"Starting continuous CloudWatch monitoring for: {LOG_GROUP_NAME}")
    print("Press Ctrl+C to stop.\n")
    print("=" * 70)
    
    # Start looking from 1 minute ago to catch recent activity
    last_seen_time = int((time.time() - 60) * 1000)
    
    try:
        while True:
            try:
                # Fetch ALL logs (removed filterPattern='REPORT' so we can see app logs)
                response = logs_client.filter_log_events(
                    logGroupName=LOG_GROUP_NAME,
                    startTime=last_seen_time + 1
                )
                
                events = response.get('events', [])
                
                if events:
                    # We will group logs by RequestId to combine the REPORT line 
                    # with the custom application log line.
                    requests_data = {}
                    
                    for event in events:
                        if event['timestamp'] > last_seen_time:
                            last_seen_time = event['timestamp']
                            
                        raw_msg = event['message'].strip()
                        
                        # 1. Look for the Custom JSON Metadata log you will print from your Lambda
                        if 'SENTINEL_METADATA:' in raw_msg:
                            try:
                                json_str = raw_msg.split('SENTINEL_METADATA:')[1].strip()
                                import json
                                metadata = json.loads(json_str)
                                req_id = metadata.get('requestId', 'unknown')
                                
                                if req_id not in requests_data:
                                    requests_data[req_id] = {}
                                    
                                requests_data[req_id]['api_calls'] = metadata.get('api_calls', [])
                                requests_data[req_id]['error_count'] = metadata.get('error_count', 0)
                                requests_data[req_id]['concurrency'] = metadata.get('concurrency', 1)
                            except:
                                pass
                                
                        # 2. Look for the AWS REPORT line for the official Duration & Memory
                        elif raw_msg.startswith('REPORT RequestId:'):
                            try:
                                req_id = raw_msg.split('RequestId: ')[1].split('\t')[0]
                                duration = float(raw_msg.split('Duration: ')[1].split(' ms')[0])
                                memory = int(raw_msg.split('Max Memory Used: ')[1].split(' MB')[0])
                                
                                if req_id not in requests_data:
                                    requests_data[req_id] = {}
                                    
                                requests_data[req_id]['duration'] = duration
                                requests_data[req_id]['memory'] = memory
                                requests_data[req_id]['timestamp'] = event['timestamp']
                            except:
                                pass

                    # 3. Now process the requests where we found the REPORT metrics
                    current_log_count = 0
                    for req_id, data in requests_data.items():
                        if 'duration' in data and 'memory' in data:
                            current_log_count += 1
                            try:
                                # Build the final format for Layer 1 Scorer
                                log_data_dict = {
                                    "timestamp": datetime.fromtimestamp(data['timestamp']/1000.0).isoformat(),
                                    "requestId": req_id,
                                    "functionName": LOG_GROUP_NAME.split('/')[-1],
                                    "duration": data['duration'],
                                    "memoryUsed": data['memory'],
                                    "memorySize": 512,
                                    "apiCalls": data.get('api_calls', []),     # Extracted!
                                    "error_count": data.get('error_count', 0), # Extracted!
                                    "concurrency": data.get('concurrency', 1), # Extracted!
                                    "statusCode": 500 if data.get('error_count', 0) > 0 else 200,
                                    "ip_address": "8.8.8.8"
                                }
                                
                                # Run Pipeline!
                                parsed_log = parse_log(log_data_dict)
                                decision, details, metrics = pipeline.process(parsed_log)
                                
                                score = details.get('anomaly_score', 0.0)
                                attack = details.get('attack_type', 'none')
                                
                                if decision == 'ALLOW':
                                    status = f"🟢 [ALLOW  ] Score: {score:.2f} | Normal Traffic"
                                elif decision == 'INVESTIGATE':
                                    status = f"🟡 [INVEST ] Score: {score:.2f} | Anomaly: {attack}"
                                else:
                                    status = f"🔴 [BLOCK  ] Score: {score:.2f} | ATTACK: {attack}"
                                    
                                print(f"{status} (Dur: {data['duration']}ms, Mem: {data['memory']}MB, APIs: {len(log_data_dict['apiCalls'])}, Errors: {log_data_dict['error_count']})")
                                
                            except Exception as parse_err:
                                print(f"Failed to process Request {req_id}: {parse_err}")
                                
                    if current_log_count > 0:
                        print("-" * 50)
                            
                # Sleep for 10 seconds before asking AWS again
                time.sleep(10)
                
            except logs_client.exceptions.ResourceNotFoundException:
                print(f"\n❌ Error: Log Group '{LOG_GROUP_NAME}' not found in AWS.")
                print("Stopping monitor. Please check the name and region.")
                break
            except Exception as e:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Warning: AWS fetch failed: {e}")
                time.sleep(10) # Sleep and try again on transient errors
                
    except KeyboardInterrupt:
        print("\n\n⏹️ Monitoring stopped by user. Exiting cleanly.")

if __name__ == "__main__":
    continuous_aws_monitoring()
