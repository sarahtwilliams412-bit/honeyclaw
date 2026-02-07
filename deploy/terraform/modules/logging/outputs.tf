output "log_bucket_name" {
  description = "S3 bucket name for honeypot logs"
  value       = aws_s3_bucket.logs.id
}

output "log_bucket_arn" {
  description = "S3 bucket ARN for honeypot logs"
  value       = aws_s3_bucket.logs.arn
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group name"
  value       = aws_cloudwatch_log_group.honeypot.name
}
