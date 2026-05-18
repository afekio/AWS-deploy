resource "aws_instance" "front" {
  ami                         = var.ec2_configs["front"].ami
  instance_type               = var.ec2_configs["front"].instance_type
  key_name                    = var.ec2_configs["front"].key_name
  subnet_id                   = var.public_subnet
  vpc_security_group_ids      = [var.front_sg_id]
  associate_public_ip_address = true
  iam_instance_profile        = var.front_profile

  tags = { Name = "${var.project_name}-front-server" }
}

resource "aws_instance" "back" {
  ami                         = var.ec2_configs["back"].ami
  instance_type               = var.ec2_configs["back"].instance_type
  key_name                    = var.ec2_configs["back"].key_name
  subnet_id                   = var.public_subnet
  vpc_security_group_ids      = [var.back_sg_id]
  associate_public_ip_address = true
  iam_instance_profile        = var.back_profile
  tags = { Name = "${var.project_name}-back-server" }
}

resource "aws_instance" "auth" {
  ami                         = var.ec2_configs["auth"].ami
  instance_type               = var.ec2_configs["auth"].instance_type
  key_name                    = var.ec2_configs["auth"].key_name
  subnet_id                   = var.public_subnet
  vpc_security_group_ids      = [var.auth_sg_id]
  associate_public_ip_address = true
  iam_instance_profile        = var.auth_profile  
  tags = { Name = "${var.project_name}-auth-server" }
}