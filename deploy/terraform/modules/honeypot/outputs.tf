output "service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.honeypot.name
}

output "public_ip" {
  description = "Note: Fargate public IPs are dynamic. Use NLB or Elastic IP for stable addresses."
  value       = "dynamic (use aws ecs describe-tasks to get current IP)"
}

output "task_definition_arn" {
  description = "Current task definition ARN"
  value       = aws_ecs_task_definition.honeypot.arn
}

output "cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.honeypot.name
}

output "ecr_repository_url" {
  description = "ECR repository URL for pushing images"
  value       = aws_ecr_repository.honeypot.repository_url
}

output "rebuild_schedule_arn" {
  description = "EventBridge scheduler ARN for rebuild cycle"
  value       = aws_scheduler_schedule.rebuild.arn
}
