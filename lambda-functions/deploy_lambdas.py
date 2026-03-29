"""
Deploy 4 Lambda functions + Cloud Sentinel Extension to real AWS.
v2 - fixes extension permissions and shebang.
"""
import boto3, zipfile, os, io, time, json, sys

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

def zip_file(fp):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(fp, os.path.basename(fp))
    return buf.getvalue()

def deploy_function(name, config):
    zb = zip_file(config["file"])
    try:
        lambda_client.update_function_code(FunctionName=name, ZipFile=zb)
        print(f"  Updated {name}")
    except lambda_client.exceptions.ResourceNotFoundException:
        lambda_client.create_function(
            FunctionName=name, Runtime="python3.11", Role=ROLE_ARN,
            Handler=config["handler"], Code={"ZipFile": zb},
            MemorySize=config["memory"], Timeout=config["timeout"],
            Environment={"Variables": {"CS_API_URL": CS_API_URL}},
        )
        print(f"  Created {name}")
    time.sleep(2)

def deploy_extension_layer():
    ep = None
    for p in ["cs-extension.py", "../cs-extension.py"]:
        if os.path.exists(p):
            ep = p
            break
    if not ep:
        print("  WARNING: cs-extension.py not found.")
        return None
    with open(ep, "r") as f:
        src = f.read()
    if not src.startswith("#!/"):
        src = "#!/usr/bin/env python3\n" + src
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("extensions/cs-extension")
        info.external_attr = 0o755 << 16
        info.compress_type = zipfile.ZIP_DEFLATED
        zf.writestr(info, src)
    resp = lambda_client.publish_layer_version(
        LayerName="cloud-sentinel-extension",
        Content={"ZipFile": buf.getvalue()},
        CompatibleRuntimes=["python3.11", "python3.12"],
        Description="Cloud Sentinel extension v2",
    )
    arn = resp["LayerVersionArn"]
    print(f"  Published: {arn}")
    return arn

def attach_layer(name, layer_arn):
    try:
        cfg = lambda_client.get_function_configuration(FunctionName=name)
        layers = [l["Arn"] for l in cfg.get("Layers", []) if "cloud-sentinel-extension" not in l["Arn"]]
        layers.append(layer_arn)
        lambda_client.update_function_configuration(FunctionName=name, Layers=layers)
        print(f"  Attached to {name}")
        time.sleep(2)
    except Exception as e:
        print(f"  WARN: {name}: {e}")

def remove_layers():
    for name in FUNCTIONS:
        try:
            cfg = lambda_client.get_function_configuration(FunctionName=name)
            layers = [l["Arn"] for l in cfg.get("Layers", []) if "cloud-sentinel-extension" not in l["Arn"]]
            lambda_client.update_function_configuration(FunctionName=name, Layers=layers)
            print(f"  Removed from {name}")
            time.sleep(2)
        except Exception as e:
            print(f"  WARN: {name}: {e}")

def test_function(name):
    try:
        resp = lambda_client.invoke(FunctionName=name, Payload=json.dumps({"action": "normal"}))
        payload = json.loads(resp["Payload"].read())
        if "errorType" in payload:
            print(f"  {name}: ERROR - {payload['errorType']}")
        else:
            body = json.loads(payload.get("body", "{}"))
            print(f"  {name}: OK - {body.get('elapsed_ms', '?')}ms")
    except Exception as e:
        print(f"  {name}: FAILED - {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("  CLOUD SENTINEL - Lambda Deployment v2")
    print("=" * 60)
    skip_ext = "--no-extension" in sys.argv
    print("\n[1/4] Deploying functions...")
    for n, c in FUNCTIONS.items():
        deploy_function(n, c)
    if skip_ext:
        print("\n[2/4] Skipping extension")
        print("\n[3/4] Removing old layers...")
        remove_layers()
    else:
        print("\n[2/4] Publishing extension layer...")
        arn = deploy_extension_layer()
        if arn:
            print("\n[3/4] Attaching layer...")
            for n in FUNCTIONS:
                attach_layer(n, arn)
        else:
            print("\n[3/4] No layer to attach")
    print("\n[4/4] Testing...")
    time.sleep(5)
    for n in FUNCTIONS:
        test_function(n)
    print("\n" + "=" * 60)
    print("  Done!")
    print("=" * 60)