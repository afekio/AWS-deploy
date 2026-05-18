output "front_public_ip" {
  value = module.ec2_instances.front_public_ip
}
output "front_private_ip" {
  description = "The Private IP of the Frontend EC2 instance"
  value       = module.ec2_instances.front_private_ip
}

output "back_public_ip" {
  value = module.ec2_instances.back_public_ip
}

output "back_private_ip" {
  description = "The Private IP of the Backend EC2 instance"
  value       = module.ec2_instances.back_private_ip
}

output "auth_public_ip" {
  value = module.ec2_instances.auth_public_ip
}
output "auth_private_ip" {
  description = "The Private IP of the Auth EC2 instance"
  value       = module.ec2_instances.auth_private_ip
}

output "rds_endpoint" {
  value = module.rds_postgres.db_endpoint
}

output "s3_bucket_name" {
  value = module.s3_bucket.bucket_name
}

output "sns_topic_arn" {
  value = module.sns_topic.topic_arn
}

output "sqs_queue_url" {
  value = module.sqs_queue.queue_url
}

output "db_user" {
  value = var.db_username # או איך שקראת למשתנה
}

output "db_name" {
  value = var.db_name # או איך שקראת למשתנה
}



