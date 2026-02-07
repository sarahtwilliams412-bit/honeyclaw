# HoneyClaw Infrastructure-as-Code
#
# Deploys an isolated honeypot infrastructure with:
# - Dedicated VPC with strict network isolation
# - S3 logging with Object Lock for tamper-proof retention
# - ECS Fargate containers for each honeypot template
# - Automated rebuild cycles via scheduled ECS task rotation
#
# Usage:
#   terraform init
#   terraform plan -var-file="environments/production.tfvars"
#   terraform apply -var-file="environments/production.tfvars"

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

locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# --- Networking (isolated VPC) ---
module "networking" {
  source = "./modules/networking"

  name_prefix        = local.name_prefix
  environment        = var.environment
  vpc_cidr           = var.vpc_cidr
  aws_region         = var.aws_region
  siem_endpoint_ip   = var.siem_endpoint != "" ? split(":", var.siem_endpoint)[0] : ""
  siem_endpoint_port = var.siem_endpoint != "" ? tonumber(split(":", var.siem_endpoint)[1]) : 514
  enable_flow_logs   = var.enable_flow_logs
}

# --- Logging (S3 with Object Lock) ---
module "logging" {
  source = "./modules/logging"

  name_prefix            = local.name_prefix
  environment            = var.environment
  aws_region             = var.aws_region
  log_bucket_name        = "${local.name_prefix}-logs"
  retention_days         = var.log_retention_days
  object_lock_days       = var.log_retention_days
  enable_replication     = false
  replication_bucket_arn = ""
}

# --- Honeypot instances ---
module "honeypot" {
  source   = "./modules/honeypot"
  for_each = toset(var.honeypot_templates)

  name_prefix            = local.name_prefix
  environment            = var.environment
  template_name          = each.value
  aws_region             = var.aws_region
  vpc_id                 = module.networking.vpc_id
  public_subnet_ids      = module.networking.public_subnet_ids
  private_subnet_ids     = module.networking.private_subnet_ids
  honeypot_sg_id         = module.networking.ssh_honeypot_sg_id
  log_bucket_name        = module.logging.bucket_name
  log_bucket_arn         = module.logging.bucket_arn
  instance_type          = var.honeypot_instance_type
  ami_id                 = var.honeypot_ami_id
  rebuild_interval_hours = var.rebuild_interval_hours
  max_instances          = var.max_honeypots_per_template
  health_check_port      = 9090
  siem_endpoint          = var.siem_endpoint != "" ? split(":", var.siem_endpoint)[0] : ""
  siem_port              = var.siem_endpoint != "" ? tonumber(split(":", var.siem_endpoint)[1]) : 514
}

# --- Outputs ---
output "vpc_id" {
  value = module.networking.vpc_id
}

output "log_bucket" {
  value = module.logging.bucket_name
}

output "honeypot_instance_ids" {
  value = { for k, v in module.honeypot : k => v.instance_ids }
}
