variable "aws_region" {
  description = "AWS region for honeypot infrastructure"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment (dev, staging, production)"
  type        = string
  default     = "production"

  validation {
    condition     = contains(["dev", "staging", "production"], var.environment)
    error_message = "Environment must be dev, staging, or production."
  }
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "honeyclaw"
}

variable "honeypot_templates" {
  description = "Honeypot templates to deploy"
  type        = list(string)
  default     = ["basic-ssh", "fake-api"]
}

variable "honeypot_instance_type" {
  description = "EC2 instance type for honeypot containers"
  type        = string
  default     = "t3.micro"
}

variable "honeypot_ami_id" {
  description = "AMI ID for honeypot hosts (Amazon Linux 2023 ECS-optimized). Leave empty for auto-lookup."
  type        = string
  default     = ""
}

variable "rebuild_interval_hours" {
  description = "Interval in hours between automated honeypot rebuilds"
  type        = number
  default     = 24
}

variable "max_honeypots_per_template" {
  description = "Maximum number of honeypot instances per template"
  type        = number
  default     = 3
}

variable "vpc_cidr" {
  description = "CIDR block for honeypot VPC (isolated from production)"
  type        = string
  default     = "10.200.0.0/16"
}

variable "siem_endpoint" {
  description = "SIEM endpoint IP:port for log shipping (only allowed egress)"
  type        = string
  default     = ""
}

variable "alert_email" {
  description = "Email address for deployment alerts"
  type        = string
  default     = ""
}

variable "log_retention_days" {
  description = "S3 Object Lock retention period in days"
  type        = number
  default     = 90
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs for forensic audit"
  type        = bool
  default     = true
}

variable "ssh_key_name" {
  description = "EC2 key pair name for emergency SSH access to honeypot hosts"
  type        = string
  default     = ""
}
