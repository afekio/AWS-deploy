# ==========================================
# BACKEND CONFIGURATION
# Purpose: Defines where Terraform stores its state file.
# Note: Allows team collaboration and protects sensitive state data.
# ==========================================
terraform {
  backend "s3" {
    bucket  = "my-app-s3-382535610286-us-east-1-an"
    key     = "afek-app/dev/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }
}