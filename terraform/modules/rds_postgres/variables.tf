# Module: RDS | Defines database parameters and secrets
variable "project_name" {}
variable "subnet_ids" { type = list(string) }
variable "db_sg_id" {}
variable "db_engine_version" {}
variable "db_instance_class" {}
variable "db_allocated_storage" { type = number }
variable "db_name" {}
variable "db_username" {}
variable "db_password" { type = string }