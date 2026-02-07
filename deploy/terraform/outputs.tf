output "vpc_id" {
  description = "Honeypot VPC ID"
  value       = module.networking.vpc_id
}

output "log_bucket" {
  description = "S3 bucket for honeypot logs (Object Lock enabled)"
  value       = module.logging.log_bucket_name
}

output "honeypot_endpoints" {
  description = "Public endpoints for each deployed honeypot template"
  value = {
    for template, hp in module.honeypot : template => {
      service_name    = hp.service_name
      public_ip       = hp.public_ip
      task_definition = hp.task_definition_arn
    }
  }
}

output "rebuild_schedule" {
  description = "Automated rebuild schedule for honeypot containers"
  value       = "Every ${var.rebuild_interval_hours} hours"
}

output "networking_summary" {
  description = "Network isolation summary"
  value = {
    vpc_cidr          = var.vpc_cidr
    flow_logs_enabled = var.enable_flow_logs
    siem_egress_only  = var.siem_endpoint != "" ? var.siem_endpoint : "no egress allowed"
  }
}
