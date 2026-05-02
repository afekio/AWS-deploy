# Module: SNS | Defines inputs for notification alerts
variable "project_name" {}
variable "environment" {}
variable "alert_emails" { type = list(string) }