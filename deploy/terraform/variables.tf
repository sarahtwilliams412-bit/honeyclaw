# =============================================================================
# Honeyclaw Infrastructure Variables
# =============================================================================

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Environment name (production, staging, dev)"
  type        = string
  default     = "production"
}

# --- Networking ---

variable "vpc_cidr" {
  description = "CIDR block for the honeypot VPC"
  type        = string
  default     = "10.200.0.0/16"
}

variable "public_subnets" {
  description = "CIDR blocks for public subnets (ingress only)"
  type        = list(string)
  default     = ["10.200.1.0/24", "10.200.2.0/24"]
}

variable "private_subnets" {
  description = "CIDR blocks for private subnets (honeypot instances)"
  type        = list(string)
  default     = ["10.200.10.0/24", "10.200.11.0/24"]
}

variable "availability_zones" {
  description = "Availability zones for deployment"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "siem_endpoint_ip" {
  description = "IP address of SIEM endpoint for log shipping"
  type        = string
  default     = ""
}

variable "siem_endpoint_port" {
  description = "Port of SIEM endpoint"
  type        = number
  default     = 514
}

# --- Honeypot ---

variable "honeypot_templates" {
  description = "List of honeypot templates to deploy"
  type        = list(string)
  default     = ["basic-ssh", "fake-api", "enterprise-sim"]
}

variable "instance_type" {
  description = "EC2 instance type for honeypot hosts"
  type        = string
  default     = "t3.small"
}

variable "ami_id" {
  description = "AMI ID for honeypot host (Amazon Linux 2 or Ubuntu)"
  type        = string
  default     = ""
}

variable "rebuild_interval_hours" {
  description = "Hours between automated honeypot rebuilds"
  type        = number
  default     = 24
}

variable "health_check_port" {
  description = "Port for honeypot health check endpoint"
  type        = number
  default     = 9090
}

# --- Logging ---

variable "log_bucket_name" {
  description = "S3 bucket name for honeypot logs"
  type        = string
  default     = "honeyclaw-logs"
}

variable "log_retention_days" {
  description = "Days to retain raw logs before anonymization"
  type        = number
  default     = 90
}

variable "object_lock_days" {
  description = "Days for S3 Object Lock (tamper-proof retention)"
  type        = number
  default     = 90
}

variable "enable_log_replication" {
  description = "Enable cross-region log replication"
  type        = bool
  default     = false
}

variable "replication_bucket_arn" {
  description = "ARN of the replication destination bucket"
  type        = string
  default     = ""
}
