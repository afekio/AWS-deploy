# Module: Networking | Defines inputs for VPC, Subnets, and Security Groups
variable "project_name" {}
variable "environment" {}
variable "vpc_cidr" {}
variable "public_subnet_cidrs" { type = list(string) }
variable "availability_zones" { type = list(string) }
variable "namespace_name" {}