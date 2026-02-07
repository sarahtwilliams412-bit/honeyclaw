# =============================================================================
# Honeyclaw Honeypot Infrastructure - Main Terraform Configuration
# =============================================================================
#
# Deploys a production-grade honeypot infrastructure with:
# - Isolated VPC with strict network controls
# - Honeypot instances in private subnets
# - S3 logging with Object Lock for immutability
# - Automated rebuild cycles via scheduled tasks
#
# Usage:
#   terraform init
#   terraform plan -var-file=env/production.tfvars
#   terraform apply -var-file=env/production.tfvars
# =============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "honeyclaw-terraform-state"
    key            = "infrastructure/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "honeyclaw-terraform-lock"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "honeyclaw"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# --- Networking ---
module "networking" {
  source = "./modules/networking"

  environment       = var.environment
  vpc_cidr          = var.vpc_cidr
  public_subnets    = var.public_subnets
  private_subnets   = var.private_subnets
  availability_zones = var.availability_zones
  siem_endpoint_ip  = var.siem_endpoint_ip
  siem_endpoint_port = var.siem_endpoint_port
}

# --- Logging ---
module "logging" {
  source = "./modules/logging"

  environment           = var.environment
  log_bucket_name       = var.log_bucket_name
  retention_days        = var.log_retention_days
  object_lock_days      = var.object_lock_days
  enable_replication    = var.enable_log_replication
  replication_bucket_arn = var.replication_bucket_arn
}

# --- Honeypot Instances ---
module "honeypot" {
  source = "./modules/honeypot"

  environment        = var.environment
  vpc_id             = module.networking.vpc_id
  private_subnet_ids = module.networking.private_subnet_ids
  public_subnet_ids  = module.networking.public_subnet_ids

  honeypot_templates = var.honeypot_templates
  instance_type      = var.instance_type
  ami_id             = var.ami_id

  log_bucket_name    = module.logging.bucket_name
  log_bucket_arn     = module.logging.bucket_arn

  siem_endpoint      = var.siem_endpoint_ip
  siem_port          = var.siem_endpoint_port

  rebuild_interval_hours = var.rebuild_interval_hours
  health_check_port     = var.health_check_port

  ssh_honeypot_sg_id = module.networking.ssh_honeypot_sg_id
  api_honeypot_sg_id = module.networking.api_honeypot_sg_id
}

# --- Outputs ---
output "vpc_id" {
  value = module.networking.vpc_id
}

output "log_bucket" {
  value = module.logging.bucket_name
}

output "honeypot_instance_ids" {
  value = module.honeypot.instance_ids
}
