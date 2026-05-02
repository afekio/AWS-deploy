# ==========================================
# ROOT MAIN ORCHESTRATOR
# Purpose: Calls all child modules and passes variables between them.
# ==========================================

module "networking" {
  source              = "./modules/networking"
  project_name        = var.project_name
  environment         = var.environment
  vpc_cidr            = var.vpc_cidr
  public_subnet_cidrs = var.public_subnet_cidrs
  availability_zones  = var.availability_zones
  namespace_name      = var.namespace_name
  
}

module "s3_bucket" {
  source       = "./modules/s3_bucket"
  project_name = var.project_name
  environment  = var.environment
}

module "sns_topic" {
  source       = "./modules/sns_topic"
  project_name = var.project_name
  environment  = var.environment
  alert_emails = var.alert_emails
}

module "iam" {
  source       = "./modules/iam"
  project_name = var.project_name
  s3_arn       = module.s3_bucket.bucket_arn
  sns_arn      = module.sns_topic.topic_arn
  # Pass SQS info ONLY if the module was created
  enable_sqs   = var.enable_sqs
  sqs_arn      = var.enable_sqs ? module.sqs_queue[0].queue_arn : ""
}

module "rds_postgres" {
  source               = "./modules/rds_postgres"
  project_name         = var.project_name
  subnet_ids           = module.networking.public_subnet_ids
  db_sg_id             = module.networking.db_sg_id
  db_engine_version    = var.db_engine_version
  db_instance_class    = var.db_instance_class
  db_allocated_storage = var.db_allocated_storage
  db_name              = var.db_name
  db_username          = var.db_username
  db_password          = var.db_password
}

module "load_balancer" {
  source       = "./modules/load_balancer"
  project_name = var.project_name
  vpc_id       = module.networking.vpc_id
  subnet_ids   = module.networking.public_subnet_ids
  alb_sg_id    = module.networking.alb_sg_id
}

module "ecs" {
  source             = "./modules/ecs"
  project_name       = var.project_name
  aws_region         = var.aws_region
  subnet_ids         = module.networking.public_subnet_ids
  namespace_id       = module.networking.namespace_id
  namespace_name     = var.namespace_name
  
  frontend_sg_id     = module.networking.frontend_sg_id
  backend_sg_id      = module.networking.backend_sg_id
  auth_sg_id         = module.networking.auth_sg_id
  
  execution_role_arn = module.iam.execution_role_arn
  task_role_arn      = module.iam.task_role_arn
  
  target_group_arn   = module.load_balancer.target_group_arn
  db_endpoint        = module.rds_postgres.db_endpoint
  db_password        = var.db_password
  s3_bucket_name     = module.s3_bucket.bucket_name
  sns_topic_arn      = module.sns_topic.topic_arn
  app_secret_key     = var.app_secret_key
  db_name            = var.db_name
  db_username        = var.db_username
  
  frontend_image     = var.frontend_image
  backend_image      = var.backend_image
  auth_image         = var.auth_image
  
  ecs_task_cpu       = var.ecs_task_cpu
  ecs_task_memory    = var.ecs_task_memory
  app_min_tasks      = var.app_min_tasks
  app_max_tasks      = var.app_max_tasks
  cpu_scale_target   = var.cpu_scale_target
  enable_sqs         = var.enable_sqs
  sqs_queue_url      = var.enable_sqs ? module.sqs_queue[0].queue_url : ""
}

module "sqs_queue" {
  source       = "./modules/sqs"
  count        = var.enable_sqs ? 1 : 0 

  project_name = var.project_name
  environment  = var.environment
}
