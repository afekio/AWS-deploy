variable "project_name" { type = string }
variable "public_subnet" { type = string }
variable "front_sg_id" { type = string }
variable "back_sg_id" { type = string }
variable "auth_sg_id" { type = string }

variable "ec2_configs" {
  type = map(object({
    ami           = string
    instance_type = string
    key_name      = string
  }))
}
variable "front_profile" { type = string }
variable "back_profile" { type = string }
variable "auth_profile" { type = string }