output "vpc_id" {
  value = aws_vpc.main.id
}

output "public_subnet_id" {
  value = aws_subnet.public.id
}

output "db_subnet_group_name" {
  value = aws_db_subnet_group.rds_subnet_group.name
}

output "front_sg_id" {
  value = aws_security_group.front_sg.id
}

output "back_sg_id" {
  value = aws_security_group.back_sg.id
}

output "auth_sg_id" {
  value = aws_security_group.auth_sg.id
}

output "rds_sg_id" {
  value = aws_security_group.rds_sg.id
}