output "vpc_id" {
  description = "Honeypot VPC ID"
  value       = aws_vpc.honeypot.id
}

output "public_subnet_ids" {
  description = "Public subnet IDs (honeypots)"
  value       = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  description = "Private subnet IDs (logging/processing)"
  value       = aws_subnet.private[*].id
}

output "honeypot_security_group_id" {
  description = "Security group ID for honeypot instances"
  value       = aws_security_group.honeypot.id
}
