# Module: IAM | Defines inputs for security roles
variable "project_name" {}
variable "s3_arn" {}
variable "sns_arn" {}
variable "sqs_arn" {
  description = "The ARN of the SQS queue (if enabled)"
  type        = string
  default     = ""
}
variable "enable_sqs" {
  type    = bool
  default = true
}