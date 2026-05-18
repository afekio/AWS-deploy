output "front_profile_name" { value = aws_iam_instance_profile.front_profile.name }
output "back_profile_name"  { value = aws_iam_instance_profile.back_profile.name }
output "auth_profile_name"  { value = aws_iam_instance_profile.auth_profile.name }