# Module: ALB | Defines inputs for the Application Load Balancer
variable "project_name" {}
variable "vpc_id" {}
variable "subnet_ids" { type = list(string) }
variable "alb_sg_id" {}