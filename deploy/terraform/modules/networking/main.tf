# =============================================================================
# Honeyclaw Networking Module
# Isolated VPC with strict egress controls for honeypot deployment
# =============================================================================

variable "environment" { type = string }
variable "vpc_cidr" { type = string }
variable "public_subnets" { type = list(string) }
variable "private_subnets" { type = list(string) }
variable "availability_zones" { type = list(string) }
variable "siem_endpoint_ip" { type = string }
variable "siem_endpoint_port" { type = number }

# --- VPC (No peering to production) ---

resource "aws_vpc" "honeypot" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "honeyclaw-${var.environment}"
  }
}

# --- Internet Gateway (for ingress only) ---

resource "aws_internet_gateway" "honeypot" {
  vpc_id = aws_vpc.honeypot.id
  tags   = { Name = "honeyclaw-igw-${var.environment}" }
}

# --- Public Subnets (ingress load balancer) ---

resource "aws_subnet" "public" {
  count                   = length(var.public_subnets)
  vpc_id                  = aws_vpc.honeypot.id
  cidr_block              = var.public_subnets[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = true

  tags = { Name = "honeyclaw-public-${count.index}-${var.environment}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.honeypot.id
  tags   = { Name = "honeyclaw-public-rt-${var.environment}" }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.honeypot.id
}

resource "aws_route_table_association" "public" {
  count          = length(var.public_subnets)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# --- Private Subnets (honeypots) ---

resource "aws_subnet" "private" {
  count             = length(var.private_subnets)
  vpc_id            = aws_vpc.honeypot.id
  cidr_block        = var.private_subnets[count.index]
  availability_zone = var.availability_zones[count.index]

  tags = { Name = "honeyclaw-private-${count.index}-${var.environment}" }
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.honeypot.id
  tags   = { Name = "honeyclaw-private-rt-${var.environment}" }
}

resource "aws_route_table_association" "private" {
  count          = length(var.private_subnets)
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# --- Network ACLs (explicit deny-all egress except SIEM) ---

resource "aws_network_acl" "honeypot" {
  vpc_id     = aws_vpc.honeypot.id
  subnet_ids = aws_subnet.private[*].id

  # Allow all inbound (honeypot must accept attacker connections)
  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow ephemeral port responses (for established connections)
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow SIEM log shipping
  dynamic "egress" {
    for_each = var.siem_endpoint_ip != "" ? [1] : []
    content {
      protocol   = "tcp"
      rule_no    = 200
      action     = "allow"
      cidr_block = "${var.siem_endpoint_ip}/32"
      from_port  = var.siem_endpoint_port
      to_port    = var.siem_endpoint_port
    }
  }

  # Allow DNS to VPC resolver
  egress {
    protocol   = "udp"
    rule_no    = 300
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 53
    to_port    = 53
  }

  # Allow S3 via VPC endpoint (HTTPS)
  egress {
    protocol   = "tcp"
    rule_no    = 400
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 443
    to_port    = 443
  }

  # Deny everything else
  egress {
    protocol   = -1
    rule_no    = 900
    action     = "deny"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  tags = { Name = "honeyclaw-nacl-${var.environment}" }
}

# --- Security Groups ---

resource "aws_security_group" "ssh_honeypot" {
  name_prefix = "honeyclaw-ssh-"
  vpc_id      = aws_vpc.honeypot.id
  description = "SSH honeypot security group"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Health check"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "SIEM only"
    from_port   = var.siem_endpoint_port
    to_port     = var.siem_endpoint_port
    protocol    = "tcp"
    cidr_blocks = var.siem_endpoint_ip != "" ? ["${var.siem_endpoint_ip}/32"] : []
  }

  egress {
    description = "S3 endpoint"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "honeyclaw-ssh-sg-${var.environment}" }
}

resource "aws_security_group" "api_honeypot" {
  name_prefix = "honeyclaw-api-"
  vpc_id      = aws_vpc.honeypot.id
  description = "API honeypot security group"

  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "API port"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Health check"
    from_port   = 9090
    to_port     = 9090
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "S3 endpoint"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "honeyclaw-api-sg-${var.environment}" }
}

# --- VPC Flow Logs ---

resource "aws_flow_log" "honeypot" {
  vpc_id               = aws_vpc.honeypot.id
  traffic_type         = "ALL"
  log_destination_type = "cloud-watch-logs"
  log_destination      = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn         = aws_iam_role.flow_logs.arn

  tags = { Name = "honeyclaw-flow-logs-${var.environment}" }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/honeyclaw/${var.environment}/vpc-flow-logs"
  retention_in_days = 30
}

resource "aws_iam_role" "flow_logs" {
  name_prefix = "honeyclaw-flow-logs-"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "vpc-flow-logs.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name_prefix = "honeyclaw-flow-logs-"
  role        = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams"
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# --- S3 VPC Endpoint ---

resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.honeypot.id
  service_name = "com.amazonaws.${data.aws_region.current.name}.s3"

  route_table_ids = [
    aws_route_table.private.id,
    aws_route_table.public.id,
  ]

  tags = { Name = "honeyclaw-s3-endpoint-${var.environment}" }
}

data "aws_region" "current" {}

# --- Outputs ---

output "vpc_id" {
  value = aws_vpc.honeypot.id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "ssh_honeypot_sg_id" {
  value = aws_security_group.ssh_honeypot.id
}

output "api_honeypot_sg_id" {
  value = aws_security_group.api_honeypot.id
}
