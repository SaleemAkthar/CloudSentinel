import boto3
import time
from datetime import datetime

# Initialize the AWS CloudWatch Logs client
# It will automatically find the credentials you set in the Command Prompt
logs_client = boto3.client('logs')

# CHANGE THIS to your actual Lambda function's name
LOG_GROUP_NAME = '/aws/lambda/cloud-sentinel-test'

def continuous_aws_monitoring():
    print(f"Starting continuous CloudWatch monitoring for: {LOG_GROUP_NAME}")
    print("Press Ctrl+C to stop.\n")
    
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
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] Found {len(events)} new execution logs!")
                    
                    for event in events:
                        log_time = datetime.fromtimestamp(event['timestamp'] / 1000.0).strftime('%H:%M:%S')
                        print(f"  -> [{log_time}] {event['message'].strip()}")
                        
                        # Update our tracker so we don't fetch this event again
                        if event['timestamp'] > last_seen_time:
                            last_seen_time = event['timestamp']
                            
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
