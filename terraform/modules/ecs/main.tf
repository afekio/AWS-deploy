# ==========================================
# ECS MODULE MAIN
# Purpose: Manages Fargate clusters, task definitions, and auto-scaling rules.
# ==========================================
resource "aws_ecs_cluster" "main" { name = "${var.project_name}-cluster" }

resource "aws_cloudwatch_log_group" "logs" {
  for_each = toset(["frontend", "backend", "auth"])
  name     = "/ecs/${var.project_name}/${each.key}"
}

# Map services to Cloud Map (Internal DNS)
resource "aws_service_discovery_service" "auth" {
  name = "auth"
  dns_config {
    namespace_id = var.namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

resource "aws_service_discovery_service" "backend" {
  name = "backend"
  dns_config {
    namespace_id = var.namespace_id
    dns_records {
      ttl  = 10
      type = "A"
    }
  }
}

# --- Task Definitions (Blueprints for containers) ---
resource "aws_ecs_task_definition" "auth" {
  family                   = "${var.project_name}-auth"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.ecs_task_cpu
  memory                   = var.ecs_task_memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([{
    name         = "auth"
    image        = var.auth_image
    essential    = true
    portMappings = [{ containerPort = 5001 }]
    environment = concat(
      [
        { name = "DATABASE_URL", value = "postgresql://${var.db_username}:${var.db_password}@${var.db_endpoint}/${var.db_name}" },
        { name = "SECRET_KEY", value = var.app_secret_key },
        { name = "S3_BUCKET_NAME", value = var.s3_bucket_name },
        { name = "SNS_TOPIC_ARN", value = var.sns_topic_arn },
        { name = "AWS_REGION", value = var.aws_region }
      ],
      var.enable_sqs ? [{ name = "SQS_QUEUE_URL", value = var.sqs_queue_url }] : []
    ),
    logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = "/ecs/${var.project_name}/auth", "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "ecs" } }
  }])
}

resource "aws_ecs_task_definition" "backend" {
  family                   = "${var.project_name}-backend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.ecs_task_cpu
  memory                   = var.ecs_task_memory
  execution_role_arn       = var.execution_role_arn
  task_role_arn            = var.task_role_arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([{
    name         = "backend"
    image        = var.backend_image
    essential    = true
    portMappings = [{ containerPort = 5000 }]
    environment = concat(
      [
        { name = "AUTH_SERVICE_URL", value = "http://auth.${var.namespace_name}:5001" },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "SECRET_KEY", value = var.app_secret_key },
        { name = "S3_BUCKET_NAME", value = var.s3_bucket_name },
        { name = "SNS_TOPIC_ARN", value = var.sns_topic_arn }
      ],
      var.enable_sqs ? [{ name = "SQS_QUEUE_URL", value = var.sqs_queue_url }] : []
    ),
    logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = "/ecs/${var.project_name}/backend", "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "ecs" } }
  }])
}

resource "aws_ecs_task_definition" "frontend" {
  family                   = "${var.project_name}-frontend"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.ecs_task_cpu
  memory                   = var.ecs_task_memory
  execution_role_arn       = var.execution_role_arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }
  container_definitions = jsonencode([{
    name         = "frontend"
    image        = var.frontend_image
    essential    = true
    portMappings = [{ containerPort = 80 }]
    logConfiguration = { logDriver = "awslogs", options = { "awslogs-group" = "/ecs/${var.project_name}/frontend", "awslogs-region" = var.aws_region, "awslogs-stream-prefix" = "ecs" } }
  }])
}

# --- Services (Runners for tasks) ---
resource "aws_ecs_service" "auth_svc" {
  name             = "auth-service"
  cluster          = aws_ecs_cluster.main.id
  task_definition  = aws_ecs_task_definition.auth.arn
  desired_count    = 1
  launch_type      = "FARGATE"
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.auth_sg_id]
    assign_public_ip = true
  }
  service_registries {
    registry_arn = aws_service_discovery_service.auth.arn
  }
}

resource "aws_ecs_service" "backend_svc" {
  name            = "backend-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.backend.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.backend_sg_id]
    assign_public_ip = true
  }
  service_registries {
    registry_arn = aws_service_discovery_service.backend.arn
  }
}

resource "aws_ecs_service" "frontend_svc" {
  name            = "frontend-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.frontend.arn
  desired_count   = var.app_min_tasks
  launch_type     = "FARGATE"
  network_configuration {
    subnets          = var.subnet_ids
    security_groups  = [var.frontend_sg_id]
    assign_public_ip = true
  }
  load_balancer {
    target_group_arn = var.target_group_arn
    container_name   = "frontend"
    container_port   = 80
  }
}

# --- Auto Scaling (For Frontend) ---
resource "aws_appautoscaling_target" "frontend_target" {
  max_capacity       = var.app_max_tasks
  min_capacity       = var.app_min_tasks
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.frontend_svc.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "frontend_cpu" {
  name               = "frontend-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.frontend_target.resource_id
  scalable_dimension = aws_appautoscaling_target.frontend_target.scalable_dimension
  service_namespace  = aws_appautoscaling_target.frontend_target.service_namespace
  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value = var.cpu_scale_target
  }
}