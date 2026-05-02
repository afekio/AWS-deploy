# ==========================================
# SNS TOPIC MODULE MAIN
# Purpose: Manages email notifications and subscriptions.
# ==========================================
resource "aws_sns_topic" "alerts" { 
  name = "${var.project_name}-${var.environment}-alerts" 
}

resource "aws_sns_topic_subscription" "email" {
  for_each  = toset(var.alert_emails)
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = each.value
}