terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "honeyclaw-terraform-state"
    key            = "honeyclaw/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "honeyclaw-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "honeyclaw"
      ManagedBy   = "terraform"
      Environment = var.environment
    }
  }
}
