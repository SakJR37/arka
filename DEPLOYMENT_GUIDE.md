# Guía de Despliegue - Arka Microservices en AWS

## 📋 Prerrequisitos

1. **Cuenta de AWS activa**
2. **AWS CLI instalado y configurado**
3. **Terraform instalado (>= 1.0)**
4. **Docker instalado**
5. **Maven y JDK 17**
6. **Git y acceso al repositorio**

## 🔐 Configuración de Credenciales AWS

### 1. Obtener Credenciales de AWS

En tu consola de AWS:
1. Ve a **IAM** → **Users** → Tu usuario
2. Pestaña **Security credentials**
3. **Create access key** → Selecciona "CLI"
4. Descarga las credenciales:
   - `AWS_ACCESS_KEY_ID`
   - `AWS_SECRET_ACCESS_KEY`

### 2. Configurar AWS CLI

```bash
aws configure
# AWS Access Key ID: [TU_ACCESS_KEY]
# AWS Secret Access Key: [TU_SECRET_KEY]
# Default region: us-east-1
# Default output format: json
```

### 3. Configurar Secrets en GitHub

En tu repositorio de GitHub:
1. **Settings** → **Secrets and variables** → **Actions**
2. Agregar los siguientes secrets:
   - `AWS_ACCESS_KEY_ID`: Tu Access Key
   - `AWS_SECRET_ACCESS_KEY`: Tu Secret Key
   - `AWS_ACCOUNT_ID`: Tu Account ID de AWS (encuentra en consola AWS arriba a la derecha)
   - `DB_PASSWORD`: Contraseña para las bases de datos RDS

## 🚀 Despliegue con Terraform

### Paso 1: Inicializar Terraform

```bash
cd terraform

# Inicializar Terraform
terraform init

# (Opcional) Crear bucket S3 para el state remoto
aws s3api create-bucket \
  --bucket arka-terraform-state \
  --region us-east-1

# Descomentar el backend en main.tf y actualizar:
# backend "s3" {
#   bucket = "arka-terraform-state"
#   key    = "microservices/terraform.tfstate"
#   region = "us-east-1"
# }
```

### Paso 2: Crear archivo de variables

Crea `terraform/terraform.tfvars`:

```hcl
aws_region     = "us-east-1"
prefix         = "arka"
environment    = "production"
vpc_cidr       = "10.0.0.0/16"
db_username    = "postgres"
db_password    = "TU_PASSWORD_SEGURA"  # Cambiar!
ses_from_email = "noreply@tudominio.com"  # Verificar en SES primero
```

### Paso 3: Verificar el Plan

```bash
# Ver qué recursos se crearán
terraform plan

# Revisar aproximadamente:
# - 8 RDS PostgreSQL instances
# - 1 DocumentDB cluster
# - 14 ECR repositories
# - 1 ECS Cluster
# - VPC, Subnets, Security Groups
# - ALB, Target Groups
# - SQS queues, SNS topics
# - S3 buckets
# - IAM roles y policies
# - CloudWatch log groups y alarms
# - EventBridge rules
```

### Paso 4: Aplicar Infraestructura

```bash
# Aplicar cambios (toma ~20-30 minutos)
terraform apply

# Confirmar con: yes
```

### Paso 5: Guardar Outputs

```bash
# Guardar outputs importantes
terraform output > ../outputs.txt

# Outputs importantes:
# - alb_dns_name: URL de tu aplicación
# - ecr_repository_urls: URLs para push de imágenes
# - rds_endpoints: Endpoints de bases de datos
# - sqs_queue_urls: URLs de colas SQS
```

## 🐳 Build y Push de Imágenes Docker

### Opción 1: Manual (Primera vez)

```bash
# Login a ECR
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  [TU_ACCOUNT_ID].dkr.ecr.us-east-1.amazonaws.com

# Build y push cada servicio
SERVICES=(
  "eureka-server"
  "gateway"
  "inventory-service"
  "order-service"
  "cart-service"
  "catalog-service"
  "category-maintainer"
  "provider-service"
  "shipping-service"
  "notification-service"
  "auth-service"
  "review-service"
  "catalog-bff-web"
  "catalog-bff-mobile"
)

ECR_REGISTRY=[TU_ACCOUNT_ID].dkr.ecr.us-east-1.amazonaws.com

for SERVICE in "${SERVICES[@]}"; do
  echo "Building $SERVICE..."
  cd $SERVICE
  docker build -t arka-$SERVICE:latest \
               -t $ECR_REGISTRY/arka-$SERVICE:latest .
  docker push $ECR_REGISTRY/arka-$SERVICE:latest
  cd ..
done
```

### Opción 2: Automático (CI/CD con GitHub Actions)

El pipeline se ejecuta automáticamente en cada push a `main`:

1. **Code Quality**: Ejecuta checkstyle
2. **Build & Test**: Compila y prueba todos los servicios
3. **Build Docker**: Construye imágenes Docker
4. **Security Scan**: Escanea vulnerabilidades con Trivy
5. **Push to ECR**: Sube imágenes a ECR
6. **Deploy ECS**: Despliega servicios en ECS
7. **Deploy Lambda**: Despliega funciones Lambda
8. **Smoke Tests**: Verifica endpoints críticos

## 📦 Crear Task Definitions y Servicios ECS

### Script de Despliegue Automático

Crea `deploy-ecs.sh`:

```bash
#!/bin/bash

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
```

**Actualizar subnet y security group IDs** en el script con los outputs de Terraform.

Ejecutar:
```bash
chmod +x deploy-ecs.sh
./deploy-ecs.sh
```

## 🧪 Pruebas Post-Despliegue

### 1. Verificar Estado de Servicios

```bash
# Ver servicios en ECS
aws ecs list-services --cluster arka-cluster --region us-east-1

# Ver estado de un servicio
aws ecs describe-services \
  --cluster arka-cluster \
  --services arka-gateway \
  --region us-east-1

# Ver logs
aws logs tail /ecs/arka-gateway --follow --region us-east-1
```

### 2. Pruebas de API

Obtén el DNS del ALB:
```bash
terraform output alb_dns_name
```

Prueba endpoints:

```bash
ALB_DNS="arka-alb-xxxxx.us-east-1.elb.amazonaws.com"

# Health check del gateway
curl http://$ALB_DNS/actuator/health

# Inventario
curl http://$ALB_DNS/api/products

# Catálogo
curl http://$ALB_DNS/api/catalog

# Crear usuario
curl -X POST http://$ALB_DNS/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username":"test","email":"test@test.com","password":"123456"}'

# Login
curl -X POST http://$ALB_DNS/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"test","password":"123456"}'

# Crear orden
curl -X POST http://$ALB_DNS/api/orders \
  -H "Content-Type: application/json" \
  -d '{
    "customerEmail": "test@test.com",
    "items": [
      {"productId": 1, "quantity": 2, "price": 29.99}
    ]
  }'
```

### 3. Verificar CloudWatch

```bash
# Ver métricas
aws cloudwatch get-metric-statistics \
  --namespace Arka/Inventory \
  --metric-name LowStockCount \
  --start-time 2024-01-01T00:00:00Z \
  --end-time 2024-12-31T23:59:59Z \
  --period 3600 \
  --statistics Average \
  --region us-east-1
```

### 4. Verificar SQS/SNS

```bash
# Ver mensajes en cola
aws sqs receive-message \
  --queue-url https://sqs.us-east-1.amazonaws.com/[ACCOUNT]/arka-order-events \
  --region us-east-1

# Publicar mensaje de prueba a SNS
aws sns publish \
  --topic-arn arn:aws:sns:us-east-1:[ACCOUNT]:arka-order-created \
  --message "Test order created" \
  --region us-east-1
```

## 📊 Monitoreo con CloudWatch

### Ver Dashboards

1. AWS Console → CloudWatch → Dashboards
2. Crear dashboard personalizado con métricas de:
   - ECS CPU/Memory utilization
   - ALB request count y latency
   - RDS connections y CPU
   - SQS queue depth
   - Lambda invocations

### Configurar Alertas

Las alarmas ya están configuradas en Terraform para:
- Low stock count
- Order failures
- ECS service failures (puedes agregar más)

## 🔄 Actualizaciones

### Actualizar un Servicio

```bash
# 1. Build nueva imagen
cd inventory-service
docker build -t [ECR_REGISTRY]/arka-inventory-service:v2.0 .
docker push [ECR_REGISTRY]/arka-inventory-service:v2.0

# 2. Actualizar servicio ECS
aws ecs update-service \
  --cluster arka-cluster \
  --service arka-inventory-service \
  --force-new-deployment \
  --region us-east-1
```

### Rollback

```bash
# Listar revisiones de task definition
aws ecs list-task-definitions \
  --family-prefix arka-inventory-service \
  --region us-east-1

# Actualizar a versión anterior
aws ecs update-service \
  --cluster arka-cluster \
  --service arka-inventory-service \
  --task-definition arka-inventory-service:REVISION_ANTERIOR \
  --region us-east-1
```

## 🧹 Destruir Infraestructura

⚠️ **CUIDADO**: Esto eliminará TODOS los recursos.

```bash
cd terraform

# Ver qué se eliminará
terraform plan -destroy

# Destruir (tardará ~20 minutos)
terraform destroy

# Confirmar con: yes
```

## 📞 Troubleshooting

### Servicios no arrancan en ECS

```bash
# Ver logs de error
aws ecs describe-services \
  --cluster arka-cluster \
  --services arka-gateway \
  --region us-east-1

# Ver logs de contenedor
aws logs tail /ecs/arka-gateway --follow --region us-east-1
```

### Problemas de conexión a RDS

- Verificar security groups
- Confirmar que ECS tasks están en la misma VPC
- Verificar credenciales en variables de entorno

### ALB no responde

- Verificar target groups tienen targets saludables
- Revisar health checks
- Verificar security groups del ALB

## 📚 Recursos Adicionales

- [AWS ECS Documentation](https://docs.aws.amazon.com/ecs/)
- [Terraform AWS Provider](https://registry.terraform.io/providers/hashicorp/aws/latest/docs)
- [Spring Cloud AWS](https://spring.io/projects/spring-cloud-aws)

## ✅ Checklist de Despliegue

- [ ] AWS CLI configurado
- [ ] Secrets configurados en GitHub
- [ ] Terraform aplicado exitosamente
- [ ] Imágenes Docker en ECR
- [ ] Task definitions creadas
- [ ] Servicios ECS corriendo
- [ ] ALB respondiendo
- [ ] Health checks pasando
- [ ] Logs visibles en CloudWatch
- [ ] SQS/SNS funcionando
- [ ] Pruebas de API exitosas
- [ ] Monitoreo configurado
