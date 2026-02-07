# Honeypot Container Module
#
# Deploys a honeypot template as an ECS Fargate service with:
# - Scheduled task rotation (automated rebuild cycle)
# - Health checks and auto-recovery
# - Log shipping to S3 and CloudWatch

variable "name_prefix" { type = string }
variable "environment" { type = string }
variable "template_name" { type = string }
variable "aws_region" { type = string }
variable "vpc_id" { type = string }
variable "public_subnet_ids" { type = list(string) }
variable "private_subnet_ids" { type = list(string) }
variable "honeypot_sg_id" { type = string }
variable "log_bucket_name" { type = string }
variable "log_bucket_arn" { type = string }
variable "instance_type" { type = string }
variable "ami_id" { type = string }
variable "rebuild_interval_hours" { type = number }
variable "max_instances" { type = number }
variable "health_check_port" { type = number }
variable "siem_endpoint" { type = string }
variable "siem_port" { type = number }

locals {
  container_port = var.template_name == "basic-ssh" ? 8022 : (
    var.template_name == "fake-api" ? 8080 : 8022
  )
  host_port = var.template_name == "basic-ssh" ? 22 : (
    var.template_name == "fake-api" ? 8080 : 22
  )
}

# --- ECS Cluster ---
resource "aws_ecs_cluster" "honeypot" {
  name = "${var.name_prefix}-${var.template_name}"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name     = "${var.name_prefix}-${var.template_name}"
    Template = var.template_name
  }
}

# --- ECR Repository ---
resource "aws_ecr_repository" "honeypot" {
  name                 = "${var.name_prefix}/${var.template_name}"
  image_tag_mutability = "IMMUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }

  tags = {
    Name     = "${var.name_prefix}-${var.template_name}"
    Template = var.template_name
  }
}

# --- Task Execution Role ---
resource "aws_iam_role" "task_execution" {
  name = "${var.name_prefix}-${var.template_name}-exec"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution" {
  role       = aws_iam_role.task_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# --- Task Role (what the container can access) ---
resource "aws_iam_role" "task" {
  name = "${var.name_prefix}-${var.template_name}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "ecs-tasks.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "task_s3_logs" {
  name = "${var.name_prefix}-${var.template_name}-s3-logs"
  role = aws_iam_role.task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "s3:PutObject",
        "s3:PutObjectRetention",
        "s3:GetObject",
        "s3:ListBucket"
      ]
      Effect   = "Allow"
      Resource = [
        var.log_bucket_arn,
        "${var.log_bucket_arn}/*"
      ]
    }]
  })
}

# --- CloudWatch Log Group ---
resource "aws_cloudwatch_log_group" "honeypot" {
  name              = "/honeyclaw/${var.name_prefix}/${var.template_name}"
  retention_in_days = 30

  tags = {
    Name     = "${var.name_prefix}-${var.template_name}-logs"
    Template = var.template_name
  }
}

# --- Task Definition ---
resource "aws_ecs_task_definition" "honeypot" {
  family                   = "${var.name_prefix}-${var.template_name}"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = 512
  memory                   = 256
  execution_role_arn       = aws_iam_role.task_execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name      = var.template_name
    image     = "${aws_ecr_repository.honeypot.repository_url}:latest"
    essential = true

    portMappings = [
      {
        containerPort = local.container_port
        hostPort      = local.container_port
        protocol      = "tcp"
      },
      {
        containerPort = var.health_check_port
        hostPort      = var.health_check_port
        protocol      = "tcp"
      }
    ]

    environment = [
      { name = "HONEYPOT_TEMPLATE", value = var.template_name },
      { name = "HONEYPOT_ID", value = "${var.name_prefix}-${var.template_name}" },
      { name = "LOG_BUCKET", value = var.log_bucket_name },
      { name = "ENVIRONMENT", value = var.environment },
      { name = "HONEYCLAW_HEALTH_PORT", value = tostring(var.health_check_port) },
      { name = "HONEYCLAW_SELF_HEAL_ENABLED", value = "true" },
      { name = "RATELIMIT_ENABLED", value = "true" },
      { name = "RATELIMIT_CONN_PER_MIN", value = "20" },
      { name = "RATELIMIT_AUTH_PER_HOUR", value = "200" },
    ]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = aws_cloudwatch_log_group.honeypot.name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = var.template_name
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "curl -f http://localhost:${var.health_check_port}/health || exit 1"]
      interval    = 30
      timeout     = 5
      retries     = 3
      startPeriod = 60
    }

    # Security: read-only root filesystem
    readonlyRootFilesystem = true

    # Writable tmp and data dirs via tmpfs
    mountPoints = [
      {
        sourceVolume  = "tmp"
        containerPath = "/tmp"
        readOnly      = false
      },
      {
        sourceVolume  = "data"
        containerPath = "/data"
        readOnly      = false
      },
      {
        sourceVolume  = "var-log"
        containerPath = "/var/log/honeyclaw"
        readOnly      = false
      },
      {
        sourceVolume  = "recordings"
        containerPath = "/var/lib/honeyclaw/recordings"
        readOnly      = false
      },
    ]

    # Drop all Linux capabilities
    linuxParameters = {
      capabilities = {
        drop = ["ALL"]
      }
      # PID limit to prevent fork bombs
      maxPids = 100
    }
  }])

  volume {
    name = "tmp"
  }

  volume {
    name = "data"
  }

  volume {
    name = "var-log"
  }

  volume {
    name = "recordings"
  }

  tags = {
    Name     = "${var.name_prefix}-${var.template_name}"
    Template = var.template_name
  }
}

# --- ECS Service ---
resource "aws_ecs_service" "honeypot" {
  name            = "${var.name_prefix}-${var.template_name}"
  cluster         = aws_ecs_cluster.honeypot.id
  task_definition = aws_ecs_task_definition.honeypot.arn
  desired_count   = 1
  launch_type     = "FARGATE"

  # Force new deployment on service update (for rebuild cycle)
  force_new_deployment = true

  network_configuration {
    subnets          = var.public_subnet_ids
    security_groups  = [var.honeypot_sg_id]
    assign_public_ip = true
  }

  deployment_configuration {
    # Blue-green: start new task before killing old one
    minimum_healthy_percent = 100
    maximum_percent         = 200
  }

  tags = {
    Name     = "${var.name_prefix}-${var.template_name}"
    Template = var.template_name
  }
}

# --- Scheduled Rebuild (EventBridge + ECS rolling update) ---
# Triggers a new deployment every N hours, which forces ECS to
# pull the latest image and restart all tasks (blue-green).

resource "aws_iam_role" "scheduler" {
  name = "${var.name_prefix}-${var.template_name}-scheduler"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "scheduler.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "scheduler_ecs" {
  name = "${var.name_prefix}-${var.template_name}-scheduler-ecs"
  role = aws_iam_role.scheduler.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "ecs:UpdateService",
        "ecs:DescribeServices",
      ]
      Effect   = "Allow"
      Resource = aws_ecs_service.honeypot.id
    }]
  })
}

resource "aws_scheduler_schedule" "rebuild" {
  name       = "${var.name_prefix}-${var.template_name}-rebuild"
  group_name = "default"

  flexible_time_window {
    mode                      = "FLEXIBLE"
    maximum_window_in_minutes = 30
  }

  schedule_expression = "rate(${var.rebuild_interval_hours} hours)"

  target {
    arn      = "arn:aws:scheduler:::aws-sdk:ecs:updateService"
    role_arn = aws_iam_role.scheduler.arn

    input = jsonencode({
      Cluster            = aws_ecs_cluster.honeypot.name
      Service            = aws_ecs_service.honeypot.name
      ForceNewDeployment = true
    })
  }

  state = "ENABLED"
}

# --- Outputs ---
output "instance_ids" {
  value = aws_ecs_service.honeypot.id
}

output "cluster_name" {
  value = aws_ecs_cluster.honeypot.name
}

output "service_name" {
  value = aws_ecs_service.honeypot.name
}
