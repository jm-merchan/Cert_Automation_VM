variable "aws_region" {
  description = "AWS region to deploy resources"
  type        = string
  default     = "eu-west-1"
}

variable "project_name" {
  description = "Project name used for resource naming"
  type        = string
  default     = "cert-automation"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "availability_zone" {
  description = "Availability zone for resources"
  type        = string
  default     = "us-east-1a"
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the instances (RDP/SSH)"
  type        = list(string)
  default     = ["0.0.0.0/0"] # IMPORTANT: Restrict this to your IP for production
}

variable "ssh_public_key" {
  description = "SSH public key for EC2 instances"
  type        = string
  # Generate with: ssh-keygen -t rsa -b 4096 -f ~/.ssh/aws_key
  # Then use the content of ~/.ssh/aws_key.pub
}

variable "windows_instance_type" {
  description = "Instance type for Windows Server"
  type        = string
  default     = "t3.medium"
}

variable "ubuntu_instance_type" {
  description = "Instance type for Ubuntu Server"
  type        = string
  default     = "t3.small"
}

variable "windows_disk_size" {
  description = "Root disk size in GB for Windows Server"
  type        = number
  default     = 50
}

variable "ubuntu_disk_size" {
  description = "Root disk size in GB for Ubuntu Server"
  type        = number
  default     = 20
}

variable "windows_timezone" {
  description = "Timezone for Windows Server"
  type        = string
  default     = "Eastern Standard Time"
}

variable "ubuntu_timezone" {
  description = "Timezone for Ubuntu Server"
  type        = string
  default     = "America/New_York"
}
