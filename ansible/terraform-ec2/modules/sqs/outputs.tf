output "queue_url" {
  value = aws_sqs_queue.app_queue.url
}
output "queue_arn" {
  value = aws_sqs_queue.app_queue.arn
}