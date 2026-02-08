# Secure VPC configuration — passes all checks

resource "aws_vpc" "secure_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "secure-vpc"
  }
}

resource "aws_flow_log" "secure_vpc_flow" {
  vpc_id          = aws_vpc.secure_vpc.id
  traffic_type    = "ALL"
  iam_role_arn    = aws_iam_role.flow_log_role.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
}

resource "aws_default_security_group" "secure_default" {
  vpc_id = aws_vpc.secure_vpc.id
  # No ingress or egress rules — deny all
}

resource "aws_subnet" "private_subnet" {
  vpc_id                  = aws_vpc.secure_vpc.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "us-east-1a"
  map_public_ip_on_launch = false

  tags = {
    Name = "private-subnet"
  }
}
