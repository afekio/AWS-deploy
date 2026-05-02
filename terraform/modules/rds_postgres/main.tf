# ==========================================
# RDS MODULE MAIN
# Purpose: Provisions a private PostgreSQL database.
# ==========================================
resource "aws_db_subnet_group" "db_subnets" {
  name       = "${var.project_name}-db-subnets"
  subnet_ids = var.subnet_ids
}

resource "aws_db_instance" "postgres" {
  identifier             = "${var.project_name}-db"
  allocated_storage      = var.db_allocated_storage
  engine                 = "postgres"
  engine_version         = var.db_engine_version
  instance_class         = var.db_instance_class
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  db_subnet_group_name   = aws_db_subnet_group.db_subnets.name
  vpc_security_group_ids = [var.db_sg_id]
  skip_final_snapshot    = true
  publicly_accessible    = false
}