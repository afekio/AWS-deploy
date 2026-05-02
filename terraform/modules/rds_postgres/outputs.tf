# Module: RDS | Exports endpoint for application connection strings
output "db_endpoint" { value = aws_db_instance.postgres.endpoint }