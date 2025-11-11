variable "aws_region" {
  description = "AWS Region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "prefix" {
  description = "Resource name prefix"
  type        = string
  default     = "arka"
}
variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "db_username" {
  description = "Database master username"
  type        = string
  default     = "postgres"
  sensitive   = true
}

variable "db_password" {
  description = "Database master password"
  type        = string
  sensitive   = true
}

variable "db_name" {
  description = "Database name for the shared Postgres instance"
  type        = string
  default     = "arkadb"
}

variable "ssh_public_key" {
  description = "SSH public key for EC2 access"
  type        = string
  default     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCigdAe+Y+8rAeISDtZIc7/vA/pZS38oZPGhKynqOH0F3DvDJmWX9Jbgz+P0UWVZ7nJLINr9ICLe3PRpwMKVI2UiScQR7wL4rKeIoptAO47WQiO0dYN3NMEodYPRKgJhpK9Yo6dI/HHcAzfU+Bl2jTdTBilQmMpB9auffEeNCaVfcJnIg20pzKG+FdI0ip3F+jrYEd3bqAC2/sVVS1Lnz2Ec8qJ/gu0UXjGFuoiFwVSw2ka/LbGGK3wNJQX1CFAdXTnvEYADg8mAQZE8gLAUt54CTwX7/x3ZCLVDIw/7MtCc19l0rjmZ33UmqILAYhABNuvfjlo17zzoccuEnpVLgyBeyiQ/y34WDgCk6LGqNtQaDOzU1s+Uca7bofDgp2+jRY84WTW+RyLQJ5aQthKjhGt2kVL7J0Saz3gjvIADfGgjBv8b7naB1Jxkfq5WwIUuIvGKs/8rnwYpV3zUKXLUvxEupxhFgVGMlKxUg0Lo68iiqc1aT8NCYyenFqMzVU8FhYD11kSJXebt+3JjLp/PgzALVN5cxRDUxEWN3Im3bwpIHBgz9y4cLAc+ZlJB5ZWKgRPAMY/18J7KbfywlJNDD0V21UFjezE40eOBQEq0wqx1YOj3NMRJLdvXcdOFf1edOpwYnK7bx9es+34NCMwqdKXLaWuPA4wjJUWLeoqzbAQmQ== juanp@DESKTOP-G87DQQI"
}



variable "ecr_repositories" {
  description = "List of ECR repositories (microservices)"
  type        = list(string)
  default = [
    "eureka-server",
    "gateway",
    "inventory-service",
    "order-service",
    "catalog-service",
    "category-maintainer",
    "cart-service",
    "provider-service",
    "shipping-service",
    "notification-service",
    "catalog-bff-web",
    "catalog-bff-mobile",
    "auth-service",
    "review-service"
  ]
}

variable "ses_from_email" {
  description = "SES verified email for sending notifications"
  type        = string
  default     = "noreply@arka.com"
}
