# ==========================================
# ROOT OUTPUTS
# Purpose: Values printed to the console after a successful deployment.
# ==========================================
output "app_url" {
  description = "The URL of the Load Balancer to access the App"
  value       = "http://${module.load_balancer.alb_dns}"
}