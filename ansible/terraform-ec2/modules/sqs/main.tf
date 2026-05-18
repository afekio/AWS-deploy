resource "aws_sqs_queue" "app_queue" {
  name = "${var.project_name}-queue"
}