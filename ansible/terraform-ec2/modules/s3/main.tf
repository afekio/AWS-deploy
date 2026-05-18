# יוצר מחרוזת אקראית כדי להבטיח ששם ה-Bucket יהיה ייחודי בעולם
resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "aws_s3_bucket" "app_bucket" {
  bucket = "${var.project_name}-bucket-${random_string.suffix.result}"
}