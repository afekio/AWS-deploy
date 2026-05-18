variable "project_name" {
  description = "The core name of the project"
  type        = string
}

variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
}

variable "db_name" {
  type = string
}

variable "db_username" {
  type = string
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "ec2_configs" {
  description = "Configuration mapping for EC2 instances"
  type = map(object({
    ami           = string
    instance_type = string
    key_name      = string
  }))
}

variable "sns_emails" {
  description = "List of email addresses to subscribe to the SNS topic"
  type        = set(string)
  default     = []
}

variable "my_ip" {
  description = "The IP address to allow SSH access"
  type        = string
}