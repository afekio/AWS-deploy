# Module: ECS | Defines all container specs, scaling rules, and env vars
variable "project_name" {}
variable "aws_region" {}
variable "subnet_ids" { type = list(string) }
variable "namespace_id" {}
variable "namespace_name" {}
variable "frontend_sg_id" {}
variable "backend_sg_id" {}
variable "auth_sg_id" {}
variable "execution_role_arn" {}
variable "task_role_arn" {}
variable "target_group_arn" {}
variable "db_endpoint" {}
variable "db_password" { type = string }
variable "db_username" {}
variable "db_name" {}
variable "s3_bucket_name" {}
variable "sns_topic_arn" {}
variable "app_secret_key" { type = string }
variable "frontend_image" {}
variable "backend_image" {}
variable "auth_image" {}
variable "ecs_task_cpu" {}
variable "ecs_task_memory" {}
variable "app_min_tasks" { type = number }
variable "app_max_tasks" { type = number }
variable "cpu_scale_target" { type = number }
variable "enable_sqs" { type = bool }
variable "sqs_queue_url" { 
  type = string 
  default = ""
}