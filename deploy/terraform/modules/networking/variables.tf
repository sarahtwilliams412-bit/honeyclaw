variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the honeypot VPC"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "siem_endpoint" {
  description = "SIEM endpoint IP:port for allowed egress (empty = no SIEM egress)"
  type        = string
  default     = ""
}

variable "enable_flow_logs" {
  description = "Enable VPC flow logs"
  type        = bool
  default     = true
}
