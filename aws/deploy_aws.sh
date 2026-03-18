#!/bin/bash
# Cloud Sentinel — AWS Deployment Script
# ========================================
# Deploys the backend to ECS Fargate with ALB load balancer.
#
# Prerequisites:
#   - AWS CLI configured (aws configure)
#   - Docker installed and running
#   - The account ID and region set below
#
# Usage:
#   chmod +x deploy_aws.sh
#   ./deploy_aws.sh

set -e

# ── CONFIGURATION (edit these) ────────────────────────────────────────────
AWS_REGION="us-east-1"
AWS_ACCOUNT_ID="555847395733"
ECR_REPO="cloud-sentinel-api"
ECS_CLUSTER="cloud-sentinel-cluster"
ECS_SERVICE="cloud-sentinel-service"
ECS_TASK_FAMILY="cloud-sentinel-task"
ALB_NAME="cloud-sentinel-alb"
TG_NAME="cs-api-targets"
VPC_ID="vpc-06591aa6f4723504a"
SUBNET_1="subnet-064044ba3d45d7f62"
SUBNET_2="subnet-0963d39d710d10940"
SECURITY_GROUP="sg-06e9544a4d1bb65fa"
DESIRED_COUNT=3

ECR_URI="${AWS_ACCOUNT_ID}.dkr.ecr.${AWS_REGION}.amazonaws.com/${ECR_REPO}"

echo "=============================================="
echo "  CLOUD SENTINEL — AWS DEPLOYMENT"
echo "=============================================="

# ── STEP 1: Create ECR Repository ────────────────────────────────────────
echo ""
echo "[1/7] Creating ECR repository..."
aws ecr create-repository \
  --repository-name ${ECR_REPO} \
  --region ${AWS_REGION} 2>/dev/null || echo "  Repository already exists"

# ── STEP 2: Build and Push Docker Image ──────────────────────────────────
echo ""
echo "[2/7] Building and pushing Docker image..."
aws ecr get-login-password --region ${AWS_REGION} | \
  docker login --username AWS --password-stdin ${ECR_URI}

docker build -f Dockerfile.backend -t ${ECR_REPO}:latest .
docker tag ${ECR_REPO}:latest ${ECR_URI}:latest
docker push ${ECR_URI}:latest
echo "  Image pushed to ${ECR_URI}:latest"

# ── STEP 3: Create CloudWatch Log Group ──────────────────────────────────
echo ""
echo "[3/7] Creating CloudWatch log group..."
aws logs create-log-group \
  --log-group-name /ecs/cloud-sentinel \
  --region ${AWS_REGION} 2>/dev/null || echo "  Log group already exists"

# ── STEP 4: Create ECS Cluster ───────────────────────────────────────────
echo ""
echo "[4/7] Creating ECS cluster..."
aws ecs create-cluster \
  --cluster-name ${ECS_CLUSTER} \
  --region ${AWS_REGION} 2>/dev/null || echo "  Cluster already exists"

# ── STEP 5: Register Task Definition ─────────────────────────────────────
echo ""
echo "[5/7] Registering task definition..."

# Replace placeholders in task definition
sed "s/ACCOUNT_ID/${AWS_ACCOUNT_ID}/g" aws/task-definition.json > /tmp/task-def-generated.json

aws ecs register-task-definition \
  --cli-input-json file:///tmp/task-def-generated.json \
  --region ${AWS_REGION}
echo "  Task definition registered"

# ── STEP 6: Create ALB + Target Group ────────────────────────────────────
echo ""
echo "[6/7] Creating ALB and target group..."

# Create ALB
ALB_ARN=$(aws elbv2 create-load-balancer \
  --name ${ALB_NAME} \
  --subnets ${SUBNET_1} ${SUBNET_2} \
  --security-groups ${SECURITY_GROUP} \
  --scheme internet-facing \
  --type application \
  --region ${AWS_REGION} \
  --query 'LoadBalancers[0].LoadBalancerArn' \
  --output text 2>/dev/null || \
  aws elbv2 describe-load-balancers \
    --names ${ALB_NAME} \
    --region ${AWS_REGION} \
    --query 'LoadBalancers[0].LoadBalancerArn' \
    --output text)

echo "  ALB ARN: ${ALB_ARN}"

# Create Target Group
TG_ARN=$(aws elbv2 create-target-group \
  --name ${TG_NAME} \
  --protocol HTTP \
  --port 8000 \
  --vpc-id ${VPC_ID} \
  --target-type ip \
  --health-check-path /status \
  --health-check-interval-seconds 30 \
  --region ${AWS_REGION} \
  --query 'TargetGroups[0].TargetGroupArn' \
  --output text 2>/dev/null || \
  aws elbv2 describe-target-groups \
    --names ${TG_NAME} \
    --region ${AWS_REGION} \
    --query 'TargetGroups[0].TargetGroupArn' \
    --output text)

echo "  Target Group ARN: ${TG_ARN}"

# Enable sticky sessions
aws elbv2 modify-target-group-attributes \
  --target-group-arn ${TG_ARN} \
  --attributes \
    Key=stickiness.enabled,Value=true \
    Key=stickiness.type,Value=lb_cookie \
    Key=stickiness.lb_cookie.duration_seconds,Value=86400 \
  --region ${AWS_REGION} > /dev/null

echo "  Sticky sessions enabled (24h cookie)"

# Create Listener
aws elbv2 create-listener \
  --load-balancer-arn ${ALB_ARN} \
  --protocol HTTP \
  --port 80 \
  --default-actions Type=forward,TargetGroupArn=${TG_ARN} \
  --region ${AWS_REGION} > /dev/null 2>/dev/null || echo "  Listener already exists"

# ── STEP 7: Create ECS Service ───────────────────────────────────────────
echo ""
echo "[7/7] Creating ECS service with ${DESIRED_COUNT} nodes..."

aws ecs create-service \
  --cluster ${ECS_CLUSTER} \
  --service-name ${ECS_SERVICE} \
  --task-definition ${ECS_TASK_FAMILY} \
  --desired-count ${DESIRED_COUNT} \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[${SUBNET_1},${SUBNET_2}],securityGroups=[${SECURITY_GROUP}],assignPublicIp=ENABLED}" \
  --load-balancers "targetGroupArn=${TG_ARN},containerName=cloud-sentinel-api,containerPort=8000" \
  --region ${AWS_REGION} 2>/dev/null || \
  aws ecs update-service \
    --cluster ${ECS_CLUSTER} \
    --service ${ECS_SERVICE} \
    --desired-count ${DESIRED_COUNT} \
    --region ${AWS_REGION} > /dev/null

# ── DONE ─────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  DEPLOYMENT COMPLETE"
echo "=============================================="

# Get ALB DNS name
ALB_DNS=$(aws elbv2 describe-load-balancers \
  --names ${ALB_NAME} \
  --region ${AWS_REGION} \
  --query 'LoadBalancers[0].DNSName' \
  --output text)

echo ""
echo "  ALB URL:        http://${ALB_DNS}"
echo "  Health check:   http://${ALB_DNS}/status"
echo "  Cluster nodes:  ${DESIRED_COUNT}"
echo ""
echo "  Wait 2-3 minutes for tasks to start, then:"
echo "    python test_cluster.py http://${ALB_DNS}"
echo ""
echo "  To view logs:"
echo "    aws logs tail /ecs/cloud-sentinel --follow"
echo ""
echo "  To tear down:"
echo "    aws ecs update-service --cluster ${ECS_CLUSTER} --service ${ECS_SERVICE} --desired-count 0"
echo "    aws ecs delete-service --cluster ${ECS_CLUSTER} --service ${ECS_SERVICE}"
echo "    aws ecs delete-cluster --cluster ${ECS_CLUSTER}"
echo "    aws elbv2 delete-load-balancer --load-balancer-arn ${ALB_ARN}"
echo ""