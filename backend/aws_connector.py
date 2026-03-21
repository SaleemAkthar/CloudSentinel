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
                # Fetch logs newer than our last_seen_time
                response = logs_client.filter_log_events(
                    logGroupName=LOG_GROUP_NAME,
                    startTime=last_seen_time + 1,  # +1ms to avoid duplicates
                    filterPattern='REPORT'
                )
                
                events = response.get('events', [])
                
                if events:
                    for event in events:
                        # 1. Update timestamp tracker
                        if event['timestamp'] > last_seen_time:
                            last_seen_time = event['timestamp']
                            
                        raw_msg = event['message'].strip()
                        
                        try:
                            # 2. Extract values from AWS REPORT string
                            # Format: REPORT RequestId: 123... Duration: 45 ms ... Max Memory Used: 64 MB
                            req_id = raw_msg.split('RequestId: ')[1].split('\t')[0]
                            duration = float(raw_msg.split('Duration: ')[1].split(' ms')[0])
                            memory = int(raw_msg.split('Max Memory Used: ')[1].split(' MB')[0])
                            
                            # 3. Format it so your LogParser accepts it
                            log_data_dict = {
                                "timestamp": datetime.fromtimestamp(event['timestamp']/1000.0).isoformat(),
                                "requestId": req_id,
                                "functionName": LOG_GROUP_NAME.split('/')[-1],
                                "duration": duration,
                                "memoryUsed": memory,
                                "memorySize": 512,
                                "statusCode": 200,
                                "apiCalls": ["dynamodb:Query"], # Simulated metric
                                "ip_address": "8.8.8.8"         # Simulated metric
                            }
                            
                            # 4. Run through Layer 1 and 2 Pipeline!
                            parsed_log = parse_log(log_data_dict)
                            decision, details, metrics = pipeline.process(parsed_log)
                            
                            # 5. Print a beautiful summary for the Industry Professionals
                            score = details.get('anomaly_score', 0.0)
                            attack = details.get('attack_type', 'none')
                            
                            if decision == 'ALLOW':
                                status = f"🟢 [ALLOW  ] Score: {score:.2f} | Normal Traffic"
                            elif decision == 'INVESTIGATE':
                                status = f"🟡 [INVEST ] Score: {score:.2f} | Anomaly Detected: {attack}"
                            else:
                                status = f"🔴 [BLOCK  ] Score: {score:.2f} | ATTACK BLOCKED: {attack}"
                                
                            print(f"{status} (Duration: {duration}ms, Memory: {memory}MB)")
                            
                        except Exception as parse_err:
                            print(f"Failed to parse AWS log string: {parse_err}")
                            
                # Sleep for 10 seconds before asking AWS again
                # (prevents AWS API rate limiting and saves money)
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
