# ==========================================
# ROOT VARIABLES DECLARATION
# Purpose: Declares all variables used by the root module.
# ==========================================
variable "aws_region" { type = string }
variable "project_name" { type = string }
variable "environment" { type = string }
variable "vpc_cidr" { type = string }
variable "public_subnet_cidrs" { type = list(string) }
variable "availability_zones" { type = list(string) }
variable "namespace_name" { type = string }
variable "db_engine_version" { type = string }
variable "db_instance_class" { type = string }
variable "db_allocated_storage" { type = number }
variable "db_name" { type = string }
variable "db_username" { type = string }
variable "db_password" { type = string}
variable "frontend_image" { type = string }
variable "backend_image" { type = string }
variable "auth_image" { type = string }
variable "ecs_task_cpu" { type = string }
variable "ecs_task_memory" { type = string }
variable "app_min_tasks" { type = number }
variable "app_max_tasks" { type = number }
variable "cpu_scale_target" { type = number }
variable "app_secret_key" { type = string}
variable "alert_emails" { type = list(string) }
variable "enable_sqs" {
  description = "Set to true to deploy the SQS queue and connect it to ECS containers."
  type        = bool
  default     = true
}