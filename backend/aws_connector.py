import boto3
import time
from datetime import datetime

# Initialize the AWS CloudWatch Logs client
# It will automatically find the credentials you set in the Command Prompt
logs_client = boto3.client('logs')

# CHANGE THIS to your actual Lambda function's name
LOG_GROUP_NAME = '/aws/lambda/cloud-sentinel-test'

def check_aws_connection():
    print(f"Attempting to connect to AWS CloudWatch: {LOG_GROUP_NAME}...")
    
    # Look for logs from the last 15 minutes
    start_time = int((time.time() - 900) * 1000)
    
    try:
        # Fetch the logs
        response = logs_client.filter_log_events(
            logGroupName=LOG_GROUP_NAME,
            startTime=start_time,
            filterPattern='REPORT' # Only get the execution summaries
        )
        
        events = response.get('events', [])
        print(f"\n SUCCESS! Connected to AWS securely.")
        print(f"Found {len(events)} real log events in the last 15 minutes.\n")
        
        # Print the first 3 logs so you can see what they look like
        for event in events[:3]:
            print(f"- {event['message'].strip()}")
            
    except logs_client.exceptions.ResourceNotFoundException:
        print("\n Connected to AWS, but the Log Group was not found.")
        print("Did you type the LOG_GROUP_NAME exactly right? Have you 'Tested' the Lambda function at least once?")
    except Exception as e:
        print(f"\n Failed to connect to AWS. Error details:\n{e}")

if __name__ == "__main__":
    check_aws_connection()
