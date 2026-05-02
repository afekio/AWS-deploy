# Module: ALB | Exports Target Group ARN for ECS and DNS name for the user
output "target_group_arn" { value = aws_lb_target_group.frontend.arn }
output "alb_dns" { value = aws_lb.main.dns_name }