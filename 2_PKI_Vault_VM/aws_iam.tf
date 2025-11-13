/*
data "aws_ami" "hc-security-base" {
  filter {
    name   = "name"
    values = ["hc-security-base-ubuntu-2204*"]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
  most_recent = true
  owners      = ["888995627335"]
}
*/

data "aws_region" "current" {}

data "aws_caller_identity" "current" {}

data "aws_iam_policy" "demo_user_permissions_boundary" {
  name = "DemoUser"
}

data "aws_iam_policy" "security_compute_access" {
  name = "SecurityComputeAccess"
}

data "aws_iam_policy_document" "client_policy" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}


locals {
  my_email = split("/", data.aws_caller_identity.current.arn)[2]
}

# EC2 IAM role for authenticating with Vault
resource "aws_iam_role" "vault_target_iam_role" {
  name               = "aws-ec2role-for-vault-authmethod"
  assume_role_policy = data.aws_iam_policy_document.client_policy.json
}

resource "aws_iam_role_policy_attachment" "security_compute_access" {
  role       = aws_iam_role.vault_target_iam_role.name
  policy_arn = data.aws_iam_policy.security_compute_access.arn
}

# IAM policy for Route53 access (needed for ACME DNS-01 challenge)
resource "aws_iam_policy" "route53_acme" {
  name        = "route53-acme-policy"
  description = "Policy for ACME clients to update Route53 for DNS-01 challenges"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "route53:GetChange",
          "route53:ListHostedZones"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets"
        ]
        Resource = "arn:aws:route53:::hostedzone/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "route53_acme" {
  role       = aws_iam_role.vault_target_iam_role.name
  policy_arn = aws_iam_policy.route53_acme.arn
}

resource "aws_iam_instance_profile" "instance_profile" {
  name = "demo_profile"
  role = aws_iam_role.vault_target_iam_role.name
}

# IAM User for Vault AWS Auth Method

resource "aws_iam_user" "vault_mount_user" {
  name                 = "demo-${local.my_email}"
  permissions_boundary = data.aws_iam_policy.demo_user_permissions_boundary.arn
  force_destroy        = true
}

resource "aws_iam_user_policy_attachment" "vault_mount_user" {
  user       = aws_iam_user.vault_mount_user.name
  policy_arn = data.aws_iam_policy.demo_user_permissions_boundary.arn
}

resource "aws_iam_access_key" "vault_mount_user" {
  user = aws_iam_user.vault_mount_user.name
}

