# Module: Networking | Exports IDs to be used by other modules
output "vpc_id" { value = aws_vpc.main.id }
output "public_subnet_ids" { value = aws_subnet.public[*].id }
output "namespace_id" { value = aws_service_discovery_private_dns_namespace.internal.id }
output "namespace_name" { value = aws_service_discovery_private_dns_namespace.internal.name }
output "alb_sg_id" { value = aws_security_group.alb.id }
output "frontend_sg_id" { value = aws_security_group.frontend.id }
output "backend_sg_id" { value = aws_security_group.backend.id }
output "auth_sg_id" { value = aws_security_group.auth.id }
output "db_sg_id" { value = aws_security_group.db.id }