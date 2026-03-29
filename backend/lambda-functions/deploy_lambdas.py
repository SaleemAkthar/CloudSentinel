"""
Deploy 4 Lambda functions + Cloud Sentinel Extension to real AWS.

Run from the lambda-functions folder:
    python deploy_lambdas.py
"""
import boto3
import zipfile
import os
import io
import time

REGION = "us-east-1"
ROLE_ARN = "arn:aws:iam::555847395733:role/cloud-sentinel-lambda-role"
CS_API_URL = "https://dfz05quh5rzd4.cloudfront.net/process_log"

lambda_client = boto3.client("lambda", region_name=REGION)

FUNCTIONS = {
    "cs-api-handler":    {"file": "api_handler.py",    "handler": "api_handler.lambda_handler",    "memory": 256, "timeout": 30},
    "cs-file-processor": {"file": "file_processor.py", "handler": "file_processor.lambda_handler", "memory": 512, "timeout": 60},
    "cs-db-query":       {"file": "db_query.py",       "handler": "db_query.lambda_handler",       "memory": 256, "timeout": 30},
    "cs-auth-service":   {"file": "auth_service.py",   "handler": "auth_service.lambda_handler",   "memory": 128, "timeout": 15},
}


def zip_file(filepath: str) -> bytes:
    """Zip a single Python file into a deployment package."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(filepath, os.path.basename(filepath))
    return buf.getvalue()


def deploy_function(name: str, config: dict):
    """Create or update a Lambda function."""
    zip_bytes = zip_file(config["file"])
    
    try:
        # Try to update existing function
        lambda_client.update_function_code(
            FunctionName=name,
            ZipFile=zip_bytes,
        )
        print(f"  Updated {name}")
    except lambda_client.exceptions.ResourceNotFoundException:
        # Create new function
        lambda_client.create_function(
            FunctionName=name,
            Runtime="python3.11",
            Role=ROLE_ARN,
            Handler=config["handler"],
            Code={"ZipFile": zip_bytes},
            MemorySize=config["memory"],
            Timeout=config["timeout"],
            Environment={
                "Variables": {
                    "CS_API_URL": CS_API_URL,
                }
            },
        )
        print(f"  Created {name}")
    
    # Wait a moment for the function to be ready
    time.sleep(2)


def deploy_extension_layer():
    """Package and publish the Cloud Sentinel extension as a Lambda Layer."""
    # Check if cs-extension.py exists in parent directory
    extension_path = os.path.join(os.path.dirname(__file__), "..", "cs-extension.py")
    if not os.path.exists(extension_path):
        extension_path = os.path.join(os.path.dirname(__file__), "cs-extension.py")
    if not os.path.exists(extension_path):
        print("  WARNING: cs-extension.py not found. Skipping layer deployment.")
        print("  Copy cs-extension.py to this folder and re-run.")
        return None
    
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Lambda expects extensions in the 'extensions/' folder
        zf.write(extension_path, "extensions/cs-extension")
    
    response = lambda_client.publish_layer_version(
        LayerName="cloud-sentinel-extension",
        Content={"ZipFile": buf.getvalue()},
        CompatibleRuntimes=["python3.11", "python3.12"],
        Description="Cloud Sentinel real-time monitoring extension",
    )
    
    layer_arn = response["LayerVersionArn"]
    print(f"  Published layer: {layer_arn}")
    return layer_arn


def attach_layer(function_name: str, layer_arn: str):
    """Attach the extension layer to a Lambda function."""
    try:
        # Get current config
        config = lambda_client.get_function_configuration(FunctionName=function_name)
        current_layers = [l["Arn"] for l in config.get("Layers", [])]
        
        # Remove old versions of our layer
        new_layers = [l for l in current_layers if "cloud-sentinel-extension" not in l]
        new_layers.append(layer_arn)
        
        lambda_client.update_function_configuration(
            FunctionName=function_name,
            Layers=new_layers,
        )
        print(f"  Attached layer to {function_name}")
        time.sleep(2)
    except Exception as e:
        print(f"  WARNING: Failed to attach layer to {function_name}: {e}")


def test_function(name: str):
    """Invoke a function to verify it works."""
    import json
    try:
        response = lambda_client.invoke(
            FunctionName=name,
            Payload=json.dumps({"action": "normal"}),
        )
        payload = json.loads(response["Payload"].read())
        status = response["StatusCode"]
        print(f"  {name}: status={status}, response={json.dumps(payload)[:100]}")
    except Exception as e:
        print(f"  {name}: FAILED — {e}")


if __name__ == "__main__":
    print("=" * 60)
    print("  CLOUD SENTINEL — Lambda Deployment")
    print("=" * 60)
    
    # Step 1: Deploy functions
    print("\n[1/4] Deploying Lambda functions...")
    for name, config in FUNCTIONS.items():
        deploy_function(name, config)
    
    # Step 2: Deploy extension layer
    print("\n[2/4] Deploying Cloud Sentinel extension layer...")
    layer_arn = deploy_extension_layer()
    
    # Step 3: Attach layer to all functions
    if layer_arn:
        print("\n[3/4] Attaching extension to all functions...")
        for name in FUNCTIONS:
            attach_layer(name, layer_arn)
    else:
        print("\n[3/4] Skipping layer attachment (no layer deployed)")
    
    # Step 4: Test all functions
    print("\n[4/4] Testing all functions...")
    time.sleep(5)  # Wait for layer attachment to propagate
    for name in FUNCTIONS:
        test_function(name)
    
    print("\n" + "=" * 60)
    print("  Deployment complete!")
    print(f"  Functions: {', '.join(FUNCTIONS.keys())}")
    if layer_arn:
        print(f"  Extension: {layer_arn}")
    print(f"  Target: {CS_API_URL}")
    print("=" * 60)