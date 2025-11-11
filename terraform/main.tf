terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }

  backend "s3" {
    # Configurar después: bucket, key, region
    # Ejemplo:
    # bucket = "arka-terraform-state"
    # key    = "microservices/terraform.tfstate"
    region = "us-east-2"
  }
}

provider "aws" {
  region = var.aws_region
  
  default_tags {
    tags = {
      Project     = "Arka-Microservices"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}

# ===================== RANDOM ID =====================
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

# ===================== VPC & NETWORKING =====================
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "${var.prefix}-vpc"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${var.prefix}-igw"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.prefix}-public-subnet-${count.index + 1}"
    Type = "Public"
  }
}

resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "${var.prefix}-private-subnet-${count.index + 1}"
    Type = "Private"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "${var.prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# ===================== SECURITY GROUPS =====================
resource "aws_security_group" "ec2" {
  name        = "${var.prefix}-ec2-sg"
  description = "Security group for EC2 instance running microservices"
  vpc_id      = aws_vpc.main.id

  # HTTP access from anywhere
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access"
  }

  # HTTPS access from anywhere
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access"
  }

  # SSH access from anywhere (recommended: restrict to your IP)
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Microservices ports (8080-8095)
  ingress {
    from_port   = 8080
    to_port     = 8095
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Microservices ports"
  }

  # Eureka Server
  ingress {
    from_port   = 8761
    to_port     = 8761
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Eureka Server"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name = "${var.prefix}-ec2-sg"
  }
}

resource "aws_security_group" "rds" {
  name        = "${var.prefix}-rds-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id

  # PostgreSQL access from EC2
  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.ec2.id]
    description     = "PostgreSQL from EC2"
  }

  # PostgreSQL access from your IP for remote management
  # IMPORTANT: Replace with your actual IP or remove if not needed
  ingress {
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Change to your IP: ["YOUR_IP/32"]
    description = "PostgreSQL remote access"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.prefix}-rds-sg"
  }
}

# ===================== RDS DATABASE =====================
resource "aws_db_subnet_group" "main" {
  name       = "${var.prefix}-db-subnet-group"
  subnet_ids = aws_subnet.public[*].id  # Using public subnets for remote access

  tags = {
    Name = "${var.prefix}-db-subnet-group"
  }
}

# Single Postgres instance for all services (Free Tier eligible)
resource "aws_db_instance" "main" {
  identifier             = "${var.prefix}-db"
  engine                 = "postgres"
  engine_version         = "16.3"  # Free Tier eligible version
  instance_class         = "db.t3.micro"  # Free Tier: 750 hours/month
  allocated_storage      = 20  # Free Tier: 20GB
  storage_type           = "gp2"
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  skip_final_snapshot    = true
  publicly_accessible    = true  # Enable for remote access
  multi_az               = false
  backup_retention_period = 7  # Free Tier: automated backups included

  tags = {
    Name    = "${var.prefix}-db"
    Service = "shared-postgres"
  }
}

# ===================== S3 BUCKETS =====================
resource "aws_s3_bucket" "reports" {
  bucket = "${var.prefix}-arka-reports-${random_id.bucket_suffix.hex}"

  tags = {
    Name    = "${var.prefix}-reports"
    Purpose = "Stock reports and exports"
  }
}

resource "aws_s3_bucket_versioning" "reports" {
  bucket = aws_s3_bucket.reports.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reports" {
  bucket = aws_s3_bucket.reports.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket" "email_templates" {
  bucket = "${var.prefix}-email-templates-${random_id.bucket_suffix.hex}"

  tags = {
    Name    = "${var.prefix}-email-templates"
    Purpose = "SES email templates"
  }
}

# ===================== SQS QUEUES =====================
resource "aws_sqs_queue" "order_events" {
  name                       = "${var.prefix}-order-events"
  delay_seconds              = 0
  max_message_size           = 262144
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 10
  visibility_timeout_seconds = 300

  tags = {
    Name    = "${var.prefix}-order-events"
    Purpose = "Order saga orchestration"
  }
}

resource "aws_sqs_queue" "inventory_events" {
  name                       = "${var.prefix}-inventory-events"
  delay_seconds              = 0
  max_message_size           = 262144
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 10
  visibility_timeout_seconds = 300

  tags = {
    Name    = "${var.prefix}-inventory-events"
    Purpose = "Inventory reservation events"
  }
}

resource "aws_sqs_queue" "notification_queue" {
  name                       = "${var.prefix}-notifications"
  delay_seconds              = 0
  max_message_size           = 262144
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 10
  visibility_timeout_seconds = 300

  tags = {
    Name    = "${var.prefix}-notifications"
    Purpose = "Notification processing queue"
  }
}

resource "aws_sqs_queue" "dlq" {
  name                       = "${var.prefix}-dlq"
  delay_seconds              = 0
  max_message_size           = 262144
  message_retention_seconds  = 1209600
  receive_wait_time_seconds  = 10

  tags = {
    Name    = "${var.prefix}-dlq"
    Purpose = "Dead letter queue"
  }
}

# ===================== SNS TOPICS =====================
resource "aws_sns_topic" "order_created" {
  name = "${var.prefix}-order-created"

  tags = {
    Name    = "${var.prefix}-order-created"
    Purpose = "Order created events"
  }
}

resource "aws_sns_topic" "inventory_reserved" {
  name = "${var.prefix}-inventory-reserved"

  tags = {
    Name    = "${var.prefix}-inventory-reserved"
    Purpose = "Inventory reservation events"
  }
}

resource "aws_sns_topic" "low_stock_alert" {
  name = "${var.prefix}-low-stock-alert"

  tags = {
    Name    = "${var.prefix}-low-stock-alert"
    Purpose = "Low stock alerts"
  }
}

# Subscribe SQS queues to SNS topics
resource "aws_sns_topic_subscription" "order_to_sqs" {
  topic_arn = aws_sns_topic.order_created.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.order_events.arn
}

resource "aws_sns_topic_subscription" "inventory_to_sqs" {
  topic_arn = aws_sns_topic.inventory_reserved.arn
  protocol  = "sqs"
  endpoint  = aws_sqs_queue.inventory_events.arn
}

# SQS queue policies
resource "aws_sqs_queue_policy" "order_events" {
  queue_url = aws_sqs_queue.order_events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.order_events.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.order_created.arn
          }
        }
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.order_events.arn
      }
    ]
  })
}

resource "aws_sqs_queue_policy" "inventory_events" {
  queue_url = aws_sqs_queue.inventory_events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "sns.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.inventory_events.arn
        Condition = {
          ArnEquals = {
            "aws:SourceArn" = aws_sns_topic.inventory_reserved.arn
          }
        }
      },
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.inventory_events.arn
      }
    ]
  })
}

# ===================== ECR REPOSITORIES =====================
resource "aws_ecr_repository" "microservices" {
  for_each = toset(var.ecr_repositories)

  name                 = "${var.prefix}-${each.value}"
  image_tag_mutability = "MUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name    = "${var.prefix}-${each.value}"
    Service = each.value
  }
}

resource "aws_ecr_lifecycle_policy" "microservices" {
  for_each   = aws_ecr_repository.microservices
  repository = each.value.name

  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Keep last 5 images"
      selection = {
        tagStatus     = "any"
        countType     = "imageCountMoreThan"
        countNumber   = 5
      }
      action = {
        type = "expire"
      }
    }]
  })
}

# ===================== EC2 KEY PAIR =====================
resource "aws_key_pair" "deployer" {
  key_name = "${var.prefix}-${var.environment}-deployer-key"
  public_key = var.ssh_public_key

  tags = {
    Name = "${var.prefix}-deployer-key"
  }
}

# ===================== IAM ROLE FOR EC2 =====================
resource "aws_iam_role" "ec2_instance" {
  name = "${var.prefix}-ec2-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = { Service = "ec2.amazonaws.com" },
      Action   = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_instance_profile" "ec2" {
  name = "${var.prefix}-ec2-instance-profile"
  role = aws_iam_role.ec2_instance.name
}

resource "aws_iam_role_policy_attachment" "ec2_ecr_read" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

resource "aws_iam_role_policy_attachment" "ec2_cw_agent" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "ec2_ssm" {
  role       = aws_iam_role.ec2_instance.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy" "ec2_inline" {
  name = "${var.prefix}-ec2-inline"
  role = aws_iam_role.ec2_instance.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject","s3:PutObject","s3:ListBucket"
        ],
        Resource = [
          aws_s3_bucket.reports.arn,
          "${aws_s3_bucket.reports.arn}/*",
          aws_s3_bucket.email_templates.arn,
          "${aws_s3_bucket.email_templates.arn}/*"
        ]
      },
      {
        Effect = "Allow",
        Action = [
          "sqs:SendMessage","sqs:ReceiveMessage","sqs:DeleteMessage","sqs:GetQueueAttributes"
        ],
        Resource = [
          aws_sqs_queue.order_events.arn,
          aws_sqs_queue.inventory_events.arn,
          aws_sqs_queue.notification_queue.arn
        ]
      },
      {
        Effect = "Allow",
        Action = ["sns:Publish"],
        Resource = [
          aws_sns_topic.order_created.arn,
          aws_sns_topic.inventory_reserved.arn,
          aws_sns_topic.low_stock_alert.arn
        ]
      },
      {
        Effect = "Allow",
        Action = ["ses:SendEmail","ses:SendRawEmail","ses:VerifyEmailIdentity"],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "logs:CreateLogGroup","logs:CreateLogStream","logs:PutLogEvents"
        ],
        Resource = "*"
      },
      {
        Effect = "Allow",
        Action = [
          "ecr:GetAuthorizationToken","ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer","ecr:BatchGetImage"
        ],
        Resource = "*"
      }
    ]
  })
}

# ===================== EC2 INSTANCE =====================
data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["137112412989"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

data "aws_caller_identity" "current" {}

resource "aws_instance" "app" {
  ami                         = data.aws_ami.al2023.id
  instance_type               = "t3.micro"  # Free Tier: 750 hours/month
  subnet_id                   = aws_subnet.public[0].id
  vpc_security_group_ids      = [aws_security_group.ec2.id]
  iam_instance_profile        = aws_iam_instance_profile.ec2.name
  associate_public_ip_address = true
  key_name                    = aws_key_pair.deployer.key_name

  root_block_device {
    volume_size = 30  # Free Tier: 30GB EBS
    volume_type = "gp2"
  }

  user_data = <<-EOF
              #!/bin/bash
              set -e
              
              # Update system
              yum update -y
              
              # Install Docker
              yum install -y docker
              systemctl start docker
              systemctl enable docker
              usermod -aG docker ec2-user
              
              # Install Docker Compose
              curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
              chmod +x /usr/local/bin/docker-compose
              ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
              
              # Install AWS CLI v2
              curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
              unzip awscliv2.zip
              ./aws/install
              rm -rf aws awscliv2.zip
              
              # Install Nginx
              yum install -y nginx
              systemctl enable nginx
              
              # Create app directory
              mkdir -p /opt/arka-microservices
              cd /opt/arka-microservices
              
              # Configure Docker to use ECR
              aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com
              
              # Create environment file
              cat > .env <<'ENVEOF'
AWS_REGION=${var.aws_region}
DB_HOST=${split(":", aws_db_instance.main.endpoint)[0]}
DB_PORT=5432
DB_NAME=${var.db_name}
DB_USER=${var.db_username}
DB_PASSWORD=${var.db_password}
S3_REPORTS_BUCKET=${aws_s3_bucket.reports.bucket}
S3_EMAIL_TEMPLATES_BUCKET=${aws_s3_bucket.email_templates.bucket}
SQS_ORDER_EVENTS=${aws_sqs_queue.order_events.url}
SQS_INVENTORY_EVENTS=${aws_sqs_queue.inventory_events.url}
SQS_NOTIFICATIONS=${aws_sqs_queue.notification_queue.url}
SNS_ORDER_CREATED=${aws_sns_topic.order_created.arn}
SNS_INVENTORY_RESERVED=${aws_sns_topic.inventory_reserved.arn}
SNS_LOW_STOCK=${aws_sns_topic.low_stock_alert.arn}
ENVEOF
              
              # Create Nginx configuration for reverse proxy
              cat > /etc/nginx/conf.d/microservices.conf <<'NGINXEOF'
server {
    listen 80;
    server_name _;
    client_max_body_size 20M;

    # Gateway (main entry point)
    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }

    # Eureka Server
    location /eureka {
        proxy_pass http://localhost:8761;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
}
NGINXEOF
              
              systemctl restart nginx
              
              # Create Docker Compose file
              cat > docker-compose.yml <<'DOCKEREOF'
version: '3.8'

services:
  eureka-server:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-eureka-server:latest
    container_name: eureka-server
    ports:
      - "8761:8761"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8761/actuator/health"]
      interval: 30s
      timeout: 10s
      retries: 5

  gateway:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-gateway:latest
    container_name: gateway
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  inventory-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-inventory-service:latest
    container_name: inventory-service
    ports:
      - "8081:8081"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  order-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-order-service:latest
    container_name: order-service
    ports:
      - "8082:8082"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  catalog-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-catalog-service:latest
    container_name: catalog-service
    ports:
      - "8083:8083"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  category-maintainer:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-category-maintainer:latest
    container_name: category-maintainer
    ports:
      - "8084:8084"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  cart-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-cart-service:latest
    container_name: cart-service
    ports:
      - "8085:8085"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  provider-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-provider-service:latest
    container_name: provider-service
    ports:
      - "8086:8086"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  shipping-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-shipping-service:latest
    container_name: shipping-service
    ports:
      - "8087:8087"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  notification-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-notification-service:latest
    container_name: notification-service
    ports:
      - "8088:8088"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  catalog-bff-web:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-catalog-bff-web:latest
    container_name: catalog-bff-web
    ports:
      - "8089:8089"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  catalog-bff-mobile:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-catalog-bff-mobile:latest
    container_name: catalog-bff-mobile
    ports:
      - "8090:8090"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  auth-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-auth-service:latest
    container_name: auth-service
    ports:
      - "8091:8091"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

  review-service:
    image: ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com/${var.prefix}-review-service:latest
    container_name: review-service
    ports:
      - "8094:8094"
    environment:
      - SPRING_PROFILES_ACTIVE=prod
      - EUREKA_SERVER_URL=http://eureka-server:8761/eureka
    env_file:
      - .env
    depends_on:
      - eureka-server
    restart: unless-stopped

networks:
  default:
    name: arka-network
DOCKEREOF
              
              # Create deployment script
              cat > /usr/local/bin/deploy-microservices <<'DEPLOYEOF'
#!/bin/bash
set -e

echo "Starting deployment..."

# Login to ECR
aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com

cd /opt/arka-microservices

# Pull latest images
echo "Pulling latest images..."
docker-compose pull

# Stop and remove old containers
echo "Stopping old containers..."
docker-compose down

# Start new containers
echo "Starting new containers..."
docker-compose up -d

# Show status
echo "Deployment complete! Container status:"
docker-compose ps

echo ""
echo "Logs available with: docker-compose logs -f [service-name]"
DEPLOYEOF
              
              chmod +x /usr/local/bin/deploy-microservices
              
              # Create update script for cron
              cat > /usr/local/bin/update-ecr-token <<'UPDATEEOF'
#!/bin/bash
aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com
UPDATEEOF
              
              chmod +x /usr/local/bin/update-ecr-token
              
              # Add cron job to refresh ECR token every 11 hours
              (crontab -l 2>/dev/null; echo "0 */11 * * * /usr/local/bin/update-ecr-token") | crontab -
              
              echo "Setup complete! Use 'deploy-microservices' to deploy your services."
              EOF

  tags = {
    Name = "${var.prefix}-app-ec2"
  }
}

# ===================== CLOUDWATCH LOG GROUPS =====================
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ec2/${var.prefix}-app"
  retention_in_days = 7

  tags = {
    Name = "${var.prefix}-app-logs"
  }
}

# ===================== CLOUDWATCH ALARMS =====================
resource "aws_cloudwatch_metric_alarm" "ec2_high_cpu" {
  alarm_name          = "${var.prefix}-ec2-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alert when EC2 average CPU > 80%"
  alarm_actions       = [aws_sns_topic.low_stock_alert.arn]

  dimensions = {
    InstanceId = aws_instance.app.id
  }

  tags = {
    Name = "${var.prefix}-ec2-high-cpu"
  }
}

resource "aws_cloudwatch_metric_alarm" "rds_high_cpu" {
  alarm_name          = "${var.prefix}-rds-high-cpu"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Alert when RDS average CPU > 80%"
  alarm_actions       = [aws_sns_topic.low_stock_alert.arn]

  dimensions = {
    DBInstanceIdentifier = aws_db_instance.main.id
  }

  tags = {
    Name = "${var.prefix}-rds-high-cpu"
  }
}

# ===================== EVENTBRIDGE RULES & TARGETS =====================
resource "aws_cloudwatch_event_rule" "abandoned_cart_check" {
  name                = "${var.prefix}-abandoned-cart-check"
  description         = "Trigger abandoned cart check daily at 2 AM"
  schedule_expression = "cron(0 2 * * ? *)"

  tags = { Name = "${var.prefix}-abandoned-cart-check" }
}

resource "aws_cloudwatch_event_target" "abandoned_cart_to_sqs" {
  rule      = aws_cloudwatch_event_rule.abandoned_cart_check.name
  target_id = "abandoned-cart-sqs"
  arn       = aws_sqs_queue.order_events.arn
}

resource "aws_cloudwatch_event_rule" "weekly_report" {
  name                = "${var.prefix}-weekly-stock-report"
  description         = "Generate weekly stock report every Monday at 9 AM"
  schedule_expression = "cron(0 9 ? * MON *)"

  tags = { Name = "${var.prefix}-weekly-report" }
}

resource "aws_cloudwatch_event_target" "weekly_report_to_sqs" {
  rule      = aws_cloudwatch_event_rule.weekly_report.name
  target_id = "weekly-report-sqs"
  arn       = aws_sqs_queue.inventory_events.arn
}

resource "aws_cloudwatch_event_rule" "auto_reorder_check" {
  name                = "${var.prefix}-auto-reorder-check"
  description         = "Check for low stock and trigger auto-reorder daily"
  schedule_expression = "cron(0 10 * * ? *)"

  tags = { Name = "${var.prefix}-auto-reorder-check" }
}

resource "aws_cloudwatch_event_target" "auto_reorder_to_sqs" {
  rule      = aws_cloudwatch_event_rule.auto_reorder_check.name
  target_id = "auto-reorder-sqs"
  arn       = aws_sqs_queue.inventory_events.arn
}

# ===================== LAMBDA FOR SES EMAIL PROCESSING (Optional) =====================
# IAM Role for Lambda
resource "aws_iam_role" "lambda_ses" {
  name = "${var.prefix}-lambda-ses-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_basic" {
  role       = aws_iam_role.lambda_ses.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "lambda_ses_policy" {
  name = "${var.prefix}-lambda-ses-policy"
  role = aws_iam_role.lambda_ses.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ses:SendEmail",
          "ses:SendRawEmail"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes"
        ]
        Resource = aws_sqs_queue.notification_queue.arn
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject"
        ]
        Resource = "${aws_s3_bucket.email_templates.arn}/*"
      }
    ]
  })
}





# ===================== OUTPUTS =====================
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "ec2_public_dns" {
  description = "Public DNS of the EC2 instance"
  value       = aws_instance.app.public_dns
}

output "ec2_public_ip" {
  description = "Public IP of the EC2 instance"
  value       = aws_instance.app.public_ip
}

output "ssh_connection" {
  description = "SSH connection command"
  value       = "ssh -i ${var.prefix}-deployer-key.pem ec2-user@${aws_instance.app.public_ip}"
}

output "application_url" {
  description = "Application URL"
  value       = "http://${aws_instance.app.public_dns}"
}

output "eureka_dashboard" {
  description = "Eureka Dashboard URL"
  value       = "http://${aws_instance.app.public_dns}/eureka"
}

output "ecr_repository_urls" {
  description = "ECR repository URLs"
  value       = { for k, v in aws_ecr_repository.microservices : k => v.repository_url }
}

output "rds_endpoint" {
  description = "RDS Postgres endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "rds_connection" {
  description = "RDS connection details for pgAdmin or DBeaver"
  value = {
    host     = aws_db_instance.main.address
    port     = 5432
    database = var.db_name
    username = var.db_username
    password = var.db_password
  }
  sensitive = true
}

output "s3_buckets" {
  description = "S3 bucket names"
  value = {
    reports         = aws_s3_bucket.reports.bucket
    email_templates = aws_s3_bucket.email_templates.bucket
  }
}

output "sqs_queue_urls" {
  description = "SQS queue URLs"
  value = {
    order_events       = aws_sqs_queue.order_events.url
    inventory_events   = aws_sqs_queue.inventory_events.url
    notification_queue = aws_sqs_queue.notification_queue.url
    dlq                = aws_sqs_queue.dlq.url
  }
}

output "sns_topic_arns" {
  description = "SNS topic ARNs"
  value = {
    order_created      = aws_sns_topic.order_created.arn
    inventory_reserved = aws_sns_topic.inventory_reserved.arn
    low_stock_alert    = aws_sns_topic.low_stock_alert.arn
  }
}

output "deployment_commands" {
  description = "Commands to deploy and manage your microservices"
  value = <<-EOT
    # 1. Connect to EC2:
    ssh -i ${var.prefix}-deployer-key.pem ec2-user@${aws_instance.app.public_ip}
    
    # 2. Deploy microservices:
    sudo deploy-microservices
    
    # 3. View logs:
    cd /opt/arka-microservices
    docker-compose logs -f [service-name]
    
    # 4. Check status:
    docker-compose ps
    
    # 5. Restart a service:
    docker-compose restart [service-name]
  EOT
}

output "aws_configuration" {
  description = "AWS services configuration"
  value = {
    region              = var.aws_region
    account_id          = data.aws_caller_identity.current.account_id
    ecr_login_command   = "aws ecr get-login-password --region ${var.aws_region} | docker login --username AWS --password-stdin ${data.aws_caller_identity.current.account_id}.dkr.ecr.${var.aws_region}.amazonaws.com"
  }
}

output "free_tier_usage_notes" {
  description = "Important notes about Free Tier usage"
  value = <<-EOT
    ⚠️  FREE TIER RESOURCES CREATED:
    
    ✅ EC2: 1x t3.micro (750 hours/month free for 12 months)
    ✅ RDS: 1x db.t3.micro PostgreSQL (750 hours/month free for 12 months)
    ✅ EBS: 30 GB gp2 storage (30 GB free for 12 months)
    ✅ S3: 2 buckets (5 GB storage free for 12 months)
    ✅ Lambda: 1 function (1M requests/month free ALWAYS)
    ✅ CloudWatch: Logs and metrics (10 custom metrics free ALWAYS)
    ✅ ECR: Repositories (500 MB storage free for 12 months)
    ✅ Data Transfer: 15 GB outbound per month free
    
    📊 MONITORING RECOMMENDATIONS:
    - Monitor your Free Tier usage in AWS Billing Dashboard
    - Set up billing alerts to avoid unexpected charges
    - Stop EC2 instance when not in use to save hours
    - This setup uses ~750 hours/month if running 24/7
    
    💡 COST OPTIMIZATION:
    - EC2 instance stops: aws ec2 stop-instances --instance-ids ${aws_instance.app.id}
    - EC2 instance starts: aws ec2 start-instances --instance-ids ${aws_instance.app.id}
    - After 12 months, consider migrating to ECS Fargate Spot or stopping services
  EOT
}