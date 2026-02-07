# =============================================================================
# Honeyclaw Honeypot Instance Module
# Deploys and manages honeypot containers with automated rebuild cycles
# =============================================================================

variable "environment" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "public_subnet_ids" { type = list(string) }
variable "honeypot_templates" { type = list(string) }
variable "instance_type" { type = string }
variable "ami_id" { type = string }
variable "log_bucket_name" { type = string }
variable "log_bucket_arn" { type = string }
variable "siem_endpoint" { type = string }
variable "siem_port" { type = number }
variable "rebuild_interval_hours" { type = number }
variable "health_check_port" { type = number }
variable "ssh_honeypot_sg_id" { type = string }
variable "api_honeypot_sg_id" { type = string }

# --- IAM Role for Honeypot Instances ---

resource "aws_iam_role" "honeypot" {
  name_prefix = "honeyclaw-instance-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "honeypot_logs" {
  name_prefix = "honeyclaw-s3-logs-"
  role        = aws_iam_role.honeypot.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "s3:PutObject",
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

resource "aws_iam_instance_profile" "honeypot" {
  name_prefix = "honeyclaw-"
  role        = aws_iam_role.honeypot.name
}

# --- Launch Template ---

resource "aws_launch_template" "honeypot" {
  for_each = toset(var.honeypot_templates)

  name_prefix   = "honeyclaw-${each.key}-"
  image_id      = var.ami_id != "" ? var.ami_id : data.aws_ami.amazon_linux.id
  instance_type = var.instance_type

  iam_instance_profile {
    arn = aws_iam_instance_profile.honeypot.arn
  }

  metadata_options {
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    http_endpoint               = "enabled"
  }

  monitoring {
    enabled = true
  }

  user_data = base64encode(templatefile("${path.module}/userdata.sh.tpl", {
    template_name          = each.key
    log_bucket             = var.log_bucket_name
    siem_endpoint          = var.siem_endpoint
    siem_port              = var.siem_port
    health_check_port      = var.health_check_port
    rebuild_interval_hours = var.rebuild_interval_hours
    environment            = var.environment
  }))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name     = "honeyclaw-${each.key}-${var.environment}"
      Template = each.key
    }
  }
}

# --- Auto Scaling Group ---

resource "aws_autoscaling_group" "honeypot" {
  for_each = toset(var.honeypot_templates)

  name_prefix      = "honeyclaw-${each.key}-"
  min_size         = 1
  max_size         = 3
  desired_capacity = 1

  vpc_zone_identifier = var.private_subnet_ids

  launch_template {
    id      = aws_launch_template.honeypot[each.key].id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 300

  tag {
    key                 = "Name"
    value               = "honeyclaw-${each.key}-${var.environment}"
    propagate_at_launch = true
  }

  tag {
    key                 = "AutoRebuild"
    value               = "true"
    propagate_at_launch = true
  }
}

# --- Scheduled Rebuild (Instance Refresh) ---

resource "aws_autoscaling_schedule" "rebuild" {
  for_each = toset(var.honeypot_templates)

  scheduled_action_name  = "honeyclaw-rebuild-${each.key}"
  autoscaling_group_name = aws_autoscaling_group.honeypot[each.key].name
  recurrence             = "0 */${var.rebuild_interval_hours} * * *"
  min_size               = 1
  max_size               = 3
  desired_capacity       = 1
}

# --- Default AMI lookup ---

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }
}

# --- Outputs ---

output "instance_ids" {
  value = { for k, v in aws_autoscaling_group.honeypot : k => v.id }
}
