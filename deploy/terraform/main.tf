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

locals {
  name_prefix = "${var.project_name}-${var.environment}"
}

# --- Networking (isolated VPC) ---
module "networking" {
  source = "./modules/networking"

  name_prefix      = local.name_prefix
  vpc_cidr         = var.vpc_cidr
  aws_region       = var.aws_region
  siem_endpoint    = var.siem_endpoint
  enable_flow_logs = var.enable_flow_logs
}

# --- Logging (S3 with Object Lock) ---
module "logging" {
  source = "./modules/logging"

  name_prefix        = local.name_prefix
  aws_region         = var.aws_region
  log_retention_days = var.log_retention_days
}

# --- Honeypot instances ---
module "honeypot" {
  source   = "./modules/honeypot"
  for_each = toset(var.honeypot_templates)

  name_prefix            = local.name_prefix
  template_name          = each.value
  aws_region             = var.aws_region
  vpc_id                 = module.networking.vpc_id
  public_subnet_ids      = module.networking.public_subnet_ids
  private_subnet_ids     = module.networking.private_subnet_ids
  honeypot_sg_id         = module.networking.honeypot_security_group_id
  log_bucket_name        = module.logging.log_bucket_name
  log_bucket_arn         = module.logging.log_bucket_arn
  instance_type          = var.honeypot_instance_type
  rebuild_interval_hours = var.rebuild_interval_hours
  max_instances          = var.max_honeypots_per_template
  environment            = var.environment
}
