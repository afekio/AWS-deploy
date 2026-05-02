# ==========================================
# IAM MODULE MAIN
# Purpose: Follows Principle of Least Privilege. Grants exact permissions to containers.
# ==========================================

# 1. Role for ECS to pull images and write logs
resource "aws_iam_role" "exec" {
  name = "${var.project_name}-exec-role"
  assume_role_policy = jsonencode({ 
    Version = "2012-10-17", 
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" } }] 
  })
}

resource "aws_iam_role_policy_attachment" "exec_policy" {
  role       = aws_iam_role.exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# 2. Role for the actual Application code (Python/Node)
resource "aws_iam_role" "task" {
  name = "${var.project_name}-task-role"
  assume_role_policy = jsonencode({ 
    Version = "2012-10-17", 
    Statement = [{ Action = "sts:AssumeRole", Effect = "Allow", Principal = { Service = "ecs-tasks.amazonaws.com" } }] 
  })
}

# 3. THE DATA BLOCK: Calculates the permissions (S3, SNS, and optionally SQS)
data "aws_iam_policy_document" "task_doc" {
  statement {
    effect    = "Allow"
    actions   = ["s3:*"]
    resources = [var.s3_arn, "${var.s3_arn}/*"]
  }

  statement {
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [var.sns_arn]
  }

  # --- DYNAMIC SQS PERMISSIONS ---
  # Only add this statement if enable_sqs is true
  dynamic "statement" {
    for_each = var.enable_sqs ? [1] : []
    content {
      effect = "Allow"
      actions = [
        "sqs:SendMessage",
        "sqs:ReceiveMessage",
        "sqs:DeleteMessage",
        "sqs:GetQueueAttributes"
      ]
      resources = [var.sqs_arn]
    }
  }
}

# 4. THE RESOURCE: Applies the calculated permissions to the role
resource "aws_iam_role_policy" "task_permissions" {
  name   = "${var.project_name}-task-policy"
  role   = aws_iam_role.task.id
  
  policy = data.aws_iam_policy_document.task_doc.json
}