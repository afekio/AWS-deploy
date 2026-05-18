provider "aws" {
  region = var.aws_region
}

module "networking" {
  source       = "./modules/networking"
  project_name = var.project_name
  my_ip        = var.my_ip
}

module "s3_bucket" {
  source       = "./modules/s3"
  project_name = var.project_name
}

module "sns_topic" {
  source       = "./modules/sns"
  project_name = var.project_name
  sns_emails   = var.sns_emails
}

module "sqs_queue" {
  source       = "./modules/sqs"
  project_name = var.project_name
}

module "rds_postgres" {
  source               = "./modules/rds"
  project_name         = var.project_name
  db_name              = var.db_name
  db_username          = var.db_username
  db_password          = var.db_password
  db_subnet_group_name = module.networking.db_subnet_group_name
  rds_sg_id            = module.networking.rds_sg_id
}

module "iam_roles" {
  source        = "./modules/iam"
  project_name  = var.project_name
  s3_bucket_arn = module.s3_bucket.bucket_arn
  sqs_queue_arn = module.sqs_queue.queue_arn
  sns_topic_arn = module.sns_topic.topic_arn
}

module "ec2_instances" {
  source         = "./modules/ec2"
  project_name   = var.project_name
  ec2_configs    = var.ec2_configs
  
  public_subnet  = module.networking.public_subnet_id
  front_sg_id    = module.networking.front_sg_id
  back_sg_id     = module.networking.back_sg_id
  auth_sg_id     = module.networking.auth_sg_id
  
  front_profile  = module.iam_roles.front_profile_name
  back_profile   = module.iam_roles.back_profile_name
  auth_profile   = module.iam_roles.auth_profile_name
}