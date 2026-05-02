# ==========================================
# SQS MODULE MAIN
# Purpose: Creates a Standard SQS queue for background tasks.
# ==========================================
resource "aws_sqs_queue" "app_queue" {
  name                      = "${var.project_name}-${var.environment}-tasks-queue"
  delay_seconds             = 0
  max_message_size          = 262144 # 256 KB
  message_retention_seconds = 86400  # 1 day
  receive_wait_time_seconds = 10     # Long polling (crucial for cost saving!)
  
  tags = {
    Environment = var.environment
    Service     = "AsyncTasks"
  }
}