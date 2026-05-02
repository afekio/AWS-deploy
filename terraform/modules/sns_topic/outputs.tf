# Module: SNS | Exports topic ARN for IAM and ECS modules
output "topic_arn" { value = aws_sns_topic.alerts.arn }