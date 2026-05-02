# Module: IAM | Exports role ARNs for ECS tasks
output "execution_role_arn" { value = aws_iam_role.exec.arn }
output "task_role_arn" { value = aws_iam_role.task.arn }