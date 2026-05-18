data "aws_iam_policy_document" "ec2_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ==========================================
# 1. Backend Role & Permissions (S3 + SQS)
# ==========================================
resource "aws_iam_role" "back_role" {
  name               = "${var.project_name}-back-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_policy" "back_policy" {
  name        = "${var.project_name}-back-policy"
  description = "Least privilege access to S3 and SQS for Backend"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action   = ["s3:PutObject", "s3:GetObject", "s3:DeleteObject", "s3:ListBucket"]
        Effect   = "Allow"

        Resource = [var.s3_bucket_arn, "${var.s3_bucket_arn}/*"]
      },
      {
        Action   = ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"]
        Effect   = "Allow"

        Resource = [var.sqs_queue_arn]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "back_attach" {
  role       = aws_iam_role.back_role.name
  policy_arn = aws_iam_policy.back_policy.arn
}

resource "aws_iam_instance_profile" "back_profile" {
  name = "${var.project_name}-back-profile"
  role = aws_iam_role.back_role.name
}

# ==========================================
# 2. Auth Role & Permissions (SNS)
# ==========================================
resource "aws_iam_role" "auth_role" {
  name               = "${var.project_name}-auth-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}

resource "aws_iam_policy" "auth_policy" {
  name        = "${var.project_name}-auth-policy"
  description = "Least privilege access to SNS for Auth"
  policy = jsonencode({
    Version = "2012-10-17"
Statement = [
      {

        Action   = ["sns:Publish"]
        Effect   = "Allow"
        Resource = [var.sns_topic_arn]
      },
      {

        Action   = [
          "sqs:ReceiveMessage", 
          "sqs:DeleteMessage", 
          "sqs:GetQueueAttributes"
        ]
        Effect   = "Allow"
        Resource = [var.sqs_queue_arn]
      },
      {
        Action   = ["s3:GetObject", "s3:ListBucket"]
        Effect   = "Allow"
        Resource = [var.s3_bucket_arn, "${var.s3_bucket_arn}/*"]
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "auth_attach" {
  role       = aws_iam_role.auth_role.name
  policy_arn = aws_iam_policy.auth_policy.arn
}

resource "aws_iam_instance_profile" "auth_profile" {
  name = "${var.project_name}-auth-profile"
  role = aws_iam_role.auth_role.name
}

# ==========================================
# 3. Frontend Role (No special permissions yet)
# ==========================================
resource "aws_iam_role" "front_role" {
  name               = "${var.project_name}-front-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume_role.json
}
resource "aws_iam_instance_profile" "front_profile" {
  name = "${var.project_name}-front-profile"
  role = aws_iam_role.front_role.name
}