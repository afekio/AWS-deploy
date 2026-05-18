resource "aws_db_instance" "postgres" {
  identifier             = "${var.project_name}-db"
  engine                 = "postgres"
  engine_version         = "18.3"
  instance_class         = "db.t3.micro"
  allocated_storage      = 20
  
  db_name                = var.db_name
  username               = var.db_username
  password               = var.db_password
  
  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = [var.rds_sg_id]
  
  skip_final_snapshot    = true
  publicly_accessible    = false
  multi_az               = false
  

}