variable "name_prefix" {
  description = "Prefix for resource names"
  type        = string
}

variable "aws_region" {
  description = "AWS region"
  type        = string
}

variable "log_retention_days" {
  description = "S3 Object Lock retention period in days"
  type        = number
  default     = 90
}
