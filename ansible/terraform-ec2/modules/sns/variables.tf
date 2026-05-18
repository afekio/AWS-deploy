variable "project_name" { type = string }
variable "sns_emails" {
  description = "List of email addresses to subscribe to the SNS topic"
  type        = set(string)
  default     = []
}