"""
simulation/deploy.py
=====================
Deploys all four Lambda functions to a running LocalStack instance.

Each function is zipped in memory and uploaded via the boto3 Lambda
client pointed at the LocalStack endpoint (http://localhost:4566).
If a function already exists from a previous deployment it is deleted
first, ensuring the environment is always in a clean, known state.

Prerequisites:
  - Docker Desktop running
  - LocalStack started:  localstack start -d
  - Dependencies installed: pip install boto3 awscli-local

Usage:
  python simulation/deploy.py

Verify after deployment:
  awslocal lambda list-functions

Author: Okitha (LocalStack Simulation)
"""

import boto3
import os
import zipfile
import io


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOCALSTACK_ENDPOINT = "http://localhost:4566"
AWS_REGION          = "us-east-1"

# Dummy credentials — LocalStack does not validate these,
# but boto3 requires them to be present.
AWS_ACCESS_KEY = "test"
AWS_SECRET_KEY = "test"

# IAM role ARN used by LocalStack. The role does not need to exist
# in a real AWS account — LocalStack accepts any well-formed ARN.
LAMBDA_ROLE_ARN = "arn:aws:iam::000000000000:role/lambda-role"

# Maps the deployed function name to its source folder under lambda_functions/.
FUNCTIONS = [
    {"name": "api-handler",    "folder": "api_handler"},
    {"name": "file-processor", "folder": "file_processor"},
    {"name": "db-query",       "folder": "db_query"},
    {"name": "auth-service",   "folder": "auth_service"},
]


# ---------------------------------------------------------------------------
# boto3 client — points to LocalStack instead of real AWS
# ---------------------------------------------------------------------------

lambda_client = boto3.client(
    "lambda",
    endpoint_url=LOCALSTACK_ENDPOINT,
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY,
    aws_secret_access_key=AWS_SECRET_KEY,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def zip_function(folder_path: str) -> bytes:
    """
    Walk a Lambda function directory and pack all files into a ZIP archive.

    The archive is built in memory (no temporary files on disk) and the
    resulting bytes are returned directly for upload to LocalStack.

    Args:
        folder_path: Absolute path to the Lambda function source directory.

    Returns:
        ZIP file contents as a bytes object.
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, _dirs, files in os.walk(folder_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                # Store files relative to the function root so the Lambda
                # runtime can find lambda_function.py at the top level.
                arcname = os.path.relpath(filepath, folder_path)
                zf.write(filepath, arcname)
    buf.seek(0)
    return buf.read()


def deploy_all():
    """
    Deploy every function listed in FUNCTIONS to LocalStack.

    For each function:
      1. Delete the existing deployment if present (idempotent re-deploy).
      2. Zip the source directory in memory.
      3. Create the function on LocalStack with Python 3.11 runtime.
    """
    # Resolve the lambda_functions/ directory relative to this script,
    # so the script works regardless of where it is called from.
    base_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lambda_functions")

    for func in FUNCTIONS:
        folder    = os.path.join(base_dir, func["folder"])
        zip_bytes = zip_function(folder)

        # Remove any existing deployment so we start from a clean state.
        try:
            lambda_client.delete_function(FunctionName=func["name"])
            print(f"  Removed previous deployment: {func['name']}")
        except lambda_client.exceptions.ResourceNotFoundException:
            pass  # First deployment — nothing to remove.

        lambda_client.create_function(
            FunctionName=func["name"],
            Runtime="python3.11",
            Role=LAMBDA_ROLE_ARN,
            Handler="lambda_function.lambda_handler",
            Code={"ZipFile": zip_bytes},
            Timeout=30,     # seconds — generous limit for simulation
            MemorySize=512, # MB — enough headroom for all test patterns
        )
        print(f"  Deployed: {func['name']}")

    print(f"\nAll {len(FUNCTIONS)} functions deployed to LocalStack.")
    print("Run the following to verify:  awslocal lambda list-functions")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("CLOUD SENTINEL — LAMBDA DEPLOYMENT TO LOCALSTACK")
    print("=" * 60)
    deploy_all()