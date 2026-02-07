variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "template_name" {
  description = "Honeypot template to deploy (basic-ssh, fake-api, enterprise-sim)"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "vpc_id" {
  description = "VPC ID for honeypot deployment"
  type        = string
}

variable "public_subnet_ids" {
  description = "Public subnet IDs for honeypot services"
  type        = list(string)
}

variable "private_subnet_ids" {
  description = "Private subnet IDs for logging/processing"
  type        = list(string)
}

variable "honeypot_sg_id" {
  description = "Security group ID for honeypot instances"
  type        = string
}

variable "log_bucket_name" {
  description = "S3 bucket name for log shipping"
  type        = string
}

variable "log_bucket_arn" {
  description = "S3 bucket ARN for IAM policies"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type (unused for Fargate, kept for future EC2 mode)"
  type        = string
  default     = "t3.micro"
}

variable "rebuild_interval_hours" {
  description = "Hours between automated rebuilds"
  type        = number
  default     = 24
}

variable "max_instances" {
  description = "Maximum honeypot instances for this template"
  type        = number
  default     = 3
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}
