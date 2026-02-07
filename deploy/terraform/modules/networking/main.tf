# Honeypot Network Isolation Module
#
# Creates a dedicated VPC with NO peering to production.
# Egress is blocked except for log shipping to the SIEM endpoint.

variable "name_prefix" { type = string }
variable "environment" { type = string }
variable "vpc_cidr" { type = string }
variable "aws_region" { type = string }
variable "siem_endpoint_ip" { type = string }
variable "siem_endpoint_port" { type = number }
variable "enable_flow_logs" { type = bool }

data "aws_availability_zones" "available" {
  state = "available"
}

locals {
  azs            = slice(data.aws_availability_zones.available.names, 0, 2)
  public_cidrs   = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i)]
  private_cidrs  = [for i, az in local.azs : cidrsubnet(var.vpc_cidr, 8, i + 100)]
}

# --- VPC (No peering to production) ---
resource "aws_vpc" "honeypot" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${var.name_prefix}-vpc"
  }
}

# --- Internet Gateway (ingress only via NACLs) ---
resource "aws_internet_gateway" "honeypot" {
  vpc_id = aws_vpc.honeypot.id

  tags = {
    Name = "${var.name_prefix}-igw"
  }
}

# --- Public Subnets (honeypots live here for ingress) ---
resource "aws_subnet" "public" {
  count = length(local.azs)

  vpc_id                  = aws_vpc.honeypot.id
  cidr_block              = local.public_cidrs[count.index]
  availability_zone       = local.azs[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "${var.name_prefix}-public-${local.azs[count.index]}"
    Tier = "public"
  }
}

# --- Private Subnets (logging/processing, no direct internet) ---
resource "aws_subnet" "private" {
  count = length(local.azs)

  vpc_id            = aws_vpc.honeypot.id
  cidr_block        = local.private_cidrs[count.index]
  availability_zone = local.azs[count.index]

  tags = {
    Name = "${var.name_prefix}-private-${local.azs[count.index]}"
    Tier = "private"
  }
}

# --- Route Tables ---
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.honeypot.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.honeypot.id
  }

  tags = {
    Name = "${var.name_prefix}-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count = length(local.azs)

  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "private" {
  vpc_id = aws_vpc.honeypot.id

  tags = {
    Name = "${var.name_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count = length(local.azs)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# --- NACLs: strict egress control ---
resource "aws_network_acl" "honeypot" {
  vpc_id     = aws_vpc.honeypot.id
  subnet_ids = aws_subnet.public[*].id

  # Allow all inbound (honeypot must accept attacker connections)
  ingress {
    protocol   = -1
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 0
    to_port    = 0
  }

  # Allow ephemeral outbound (responses to inbound connections)
  egress {
    protocol   = "tcp"
    rule_no    = 100
    action     = "allow"
    cidr_block = "0.0.0.0/0"
    from_port  = 1024
    to_port    = 65535
  }

  # Allow DNS outbound (UDP 53) to VPC resolver only
  egress {
    protocol   = "udp"
    rule_no    = 200
    action     = "allow"
    cidr_block = var.vpc_cidr
    from_port  = 53
    to_port    = 53
  }

  # Allow HTTPS outbound to SIEM endpoint only (if configured)
  dynamic "egress" {
    for_each = var.siem_endpoint_ip != "" ? [1] : []
    content {
      protocol   = "tcp"
      rule_no    = 300
      action     = "allow"
      cidr_block = "${var.siem_endpoint_ip}/32"
      from_port  = var.siem_endpoint_port
      to_port    = var.siem_endpoint_port
    }
  }

  # Allow HTTPS to AWS S3 (for log shipping via VPC endpoint)
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

  tags = {
    Name = "${var.name_prefix}-honeypot-nacl"
  }
}

# --- Security Groups ---
resource "aws_security_group" "ssh_honeypot" {
  name_prefix = "${var.name_prefix}-ssh-honeypot-"
  description = "SSH honeypot inbound access - allows attacker connections"
  vpc_id      = aws_vpc.honeypot.id

  # SSH honeypot
  ingress {
    description = "SSH honeypot"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SSH honeypot alt port"
    from_port   = 2222
    to_port     = 2222
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

  # Egress: only to S3 VPC endpoint and SIEM
  egress {
    description = "S3 VPC endpoint (log shipping)"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS resolution"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  dynamic "egress" {
    for_each = var.siem_endpoint_ip != "" ? [1] : []
    content {
      description = "SIEM only"
      from_port   = var.siem_endpoint_port
      to_port     = var.siem_endpoint_port
      protocol    = "tcp"
      cidr_blocks = ["${var.siem_endpoint_ip}/32"]
    }
  }

  tags = {
    Name = "${var.name_prefix}-ssh-honeypot-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "api_honeypot" {
  name_prefix = "${var.name_prefix}-api-honeypot-"
  description = "API honeypot inbound access"
  vpc_id      = aws_vpc.honeypot.id

  # HTTP/HTTPS honeypot
  ingress {
    description = "HTTP honeypot"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS honeypot"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # API honeypot
  ingress {
    description = "API honeypot"
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

  # Enterprise simulation ports (RDP, WinRM, SMB, LDAP)
  ingress {
    description = "RDP honeypot"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "SMB honeypot"
    from_port   = 445
    to_port     = 445
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "LDAP honeypot"
    from_port   = 389
    to_port     = 389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "S3 endpoint"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "DNS"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${var.name_prefix}-api-honeypot-sg"
  }

  lifecycle {
    create_before_destroy = true
  }
}

# --- S3 VPC Endpoint (private log shipping, no internet egress needed) ---
resource "aws_vpc_endpoint" "s3" {
  vpc_id       = aws_vpc.honeypot.id
  service_name = "com.amazonaws.${var.aws_region}.s3"

  route_table_ids = [
    aws_route_table.public.id,
    aws_route_table.private.id,
  ]

  tags = {
    Name = "${var.name_prefix}-s3-endpoint"
  }
}

# --- CloudWatch Logs VPC Endpoint ---
resource "aws_vpc_endpoint" "logs" {
  vpc_id              = aws_vpc.honeypot.id
  service_name        = "com.amazonaws.${var.aws_region}.logs"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = aws_subnet.private[*].id
  private_dns_enabled = true

  security_group_ids = [aws_security_group.ssh_honeypot.id]

  tags = {
    Name = "${var.name_prefix}-logs-endpoint"
  }
}

# --- VPC Flow Logs ---
resource "aws_flow_log" "honeypot" {
  count = var.enable_flow_logs ? 1 : 0

  iam_role_arn    = aws_iam_role.flow_logs[0].arn
  log_destination = aws_cloudwatch_log_group.flow_logs[0].arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.honeypot.id

  tags = {
    Name = "${var.name_prefix}-flow-logs"
  }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name              = "/honeyclaw/${var.name_prefix}/vpc-flow-logs"
  retention_in_days = 30

  tags = {
    Name = "${var.name_prefix}-flow-logs"
  }
}

resource "aws_iam_role" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.name_prefix}-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = {
        Service = "vpc-flow-logs.amazonaws.com"
      }
    }]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  count = var.enable_flow_logs ? 1 : 0

  name = "${var.name_prefix}-flow-logs-policy"
  role = aws_iam_role.flow_logs[0].id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents",
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
      ]
      Effect   = "Allow"
      Resource = "*"
    }]
  })
}

# --- Outputs ---
output "vpc_id" {
  value = aws_vpc.honeypot.id
}

output "public_subnet_ids" {
  value = aws_subnet.public[*].id
}

output "private_subnet_ids" {
  value = aws_subnet.private[*].id
}

output "ssh_honeypot_sg_id" {
  value = aws_security_group.ssh_honeypot.id
}

output "api_honeypot_sg_id" {
  value = aws_security_group.api_honeypot.id
}
