AWS_REGION="us-east-1"
CLUSTER_NAME="arka-cluster"
ECR_REGISTRY="[TU_ACCOUNT_ID].dkr.ecr.us-east-1.amazonaws.com"

# Array de servicios con sus puertos
declare -A SERVICES
SERVICES=(
  ["eureka-server"]="8761"
  ["gateway"]="8080"
  ["inventory-service"]="8081"
  ["order-service"]="8082"
  ["catalog-service"]="8083"
  ["category-maintainer"]="8084"
  ["cart-service"]="8085"
  ["provider-service"]="8086"
  ["shipping-service"]="8087"
  ["notification-service"]="8088"
  ["catalog-bff-web"]="8089"
  ["catalog-bff-mobile"]="8090"
  ["auth-service"]="8091"
  ["review-service"]="8094"
)

# Crear task definition para cada servicio
for SERVICE in "${!SERVICES[@]}"; do
  PORT=${SERVICES[$SERVICE]}
  
  echo "Creating task definition for $SERVICE..."
  
  cat > task-def-$SERVICE.json <<EOF
{
  "family": "arka-$SERVICE",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "512",
  "memory": "1024",
  "executionRoleArn": "arn:aws:iam::[TU_ACCOUNT_ID]:role/arka-ecs-task-execution-role",
  "taskRoleArn": "arn:aws:iam::[TU_ACCOUNT_ID]:role/arka-ecs-task-role",
  "containerDefinitions": [
    {
      "name": "$SERVICE",
      "image": "$ECR_REGISTRY/arka-$SERVICE:latest",
      "portMappings": [
        {
          "containerPort": $PORT,
          "protocol": "tcp"
        }
      ],
      "environment": [
        {
          "name": "SPRING_PROFILES_ACTIVE",
          "value": "prod"
        },
        {
          "name": "AWS_REGION",
          "value": "$AWS_REGION"
        }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/arka-$SERVICE",
          "awslogs-region": "$AWS_REGION",
          "awslogs-stream-prefix": "ecs"
        }
      }
    }
  ]
}
EOF

  # Registrar task definition
  aws ecs register-task-definition \
    --cli-input-json file://task-def-$SERVICE.json \
    --region $AWS_REGION

  # Crear o actualizar servicio
  aws ecs create-service \
    --cluster $CLUSTER_NAME \
    --service-name arka-$SERVICE \
    --task-definition arka-$SERVICE \
    --desired-count 1 \
    --launch-type FARGATE \
    --network-configuration "awsvpcConfiguration={subnets=[subnet-xxx,subnet-yyy],securityGroups=[sg-xxx],assignPublicIp=ENABLED}" \
    --region $AWS_REGION || \
  aws ecs update-service \
    --cluster $CLUSTER_NAME \
    --service arka-$SERVICE \
    --force-new-deployment \
    --region $AWS_REGION

  rm task-def-$SERVICE.json
done

echo "✅ All services deployed to ECS!"