
output "front_public_ip" { value = aws_instance.front.public_ip }
output "back_public_ip"  { value = aws_instance.back.public_ip }
output "auth_public_ip"  { value = aws_instance.auth.public_ip }


output "front_private_ip" { value = aws_instance.front.private_ip }
output "back_private_ip"  { value = aws_instance.back.private_ip }
output "auth_private_ip"  { value = aws_instance.auth.private_ip }