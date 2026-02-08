# Insecure EC2 configuration — multiple security issues

resource "aws_security_group" "insecure_sg" {
  name        = "insecure-sg"
  description = "Allow all inbound traffic"
  vpc_id      = "vpc-12345"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "insecure_web" {
  ami                         = "ami-12345678"
  instance_type               = "t3.medium"
  associate_public_ip_address = true

  # No IMDSv2
  # No monitoring
  # No EBS optimization

  user_data = <<-EOF
    #!/bin/bash
    export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
    export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
    export PASSWORD=SuperSecret123!
  EOF
}

resource "aws_ebs_volume" "insecure_volume" {
  availability_zone = "us-east-1a"
  size              = 100
  # encrypted not set — defaults to false
}
