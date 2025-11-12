# AWS Certificate Automation VM Infrastructure

This Terraform configuration deploys a Windows Server 2022 and Ubuntu 22.04 LTS server in AWS.

## Architecture

- **VPC**: Custom VPC with Internet Gateway
- **Subnet**: Public subnet with auto-assigned public IPs
- **Windows Server 2022**: t3.medium instance with RDP access
- **Ubuntu Server 22.04**: t3.small instance with SSH access
- **Security Groups**: Separate security groups for each instance
- **Elastic IPs**: Static public IPs for both instances

## Prerequisites

1. **AWS Account** with appropriate permissions
2. **AWS CLI** configured with credentials
3. **Terraform** v1.0+ installed
4. **SSH Key Pair** generated

## Setup Instructions

### 1. Generate SSH Key Pair

```bash
ssh-keygen -t rsa -b 4096 -f ~/.ssh/aws_key
```

### 2. Configure AWS Credentials

```bash
aws configure
```

### 3. Create terraform.tfvars

```bash
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars` and update:
- `ssh_public_key`: Paste the content of `~/.ssh/aws_key.pub`
- `allowed_cidr_blocks`: Replace with your IP address (recommended for security)

### 4. Initialize Terraform

```bash
terraform init
```

### 5. Review the Plan

```bash
terraform plan
```

### 6. Deploy Infrastructure

```bash
terraform apply
```

Type `yes` when prompted to confirm.

## Connecting to Instances

### Windows Server (RDP)

1. Get the Windows administrator password:
```bash
aws ec2 get-password-data \
  --instance-id <instance-id> \
  --priv-launch-key ~/.ssh/aws_key \
  --region us-east-1
```

2. Connect using the output command or RDP client:
   - **Host**: Use the `windows_public_ip` from Terraform outputs
   - **Username**: Administrator
   - **Password**: From step 1

### Ubuntu Server (SSH)

Use the SSH command from Terraform outputs:
```bash
ssh -i ~/.ssh/aws_key ubuntu@<ubuntu_public_ip>
```

## Resources Created

- 1 VPC
- 1 Internet Gateway
- 1 Public Subnet
- 1 Route Table
- 2 Security Groups (Windows and Ubuntu)
- 1 Key Pair
- 2 EC2 Instances (Windows and Ubuntu)
- 2 Elastic IPs

## Cost Estimate

Approximate monthly costs (us-east-1):
- Windows Server t3.medium: ~$60-70/month
- Ubuntu t3.small: ~$15-20/month
- EBS Storage (70 GB): ~$7/month
- Elastic IPs: Free while attached to running instances
- **Total**: ~$82-97/month

## Security Notes

⚠️ **IMPORTANT**: 
- The default configuration allows access from any IP (`0.0.0.0/0`)
- For production, update `allowed_cidr_blocks` in `terraform.tfvars` to your specific IP
- Both instances have encrypted EBS volumes
- Change default passwords immediately after deployment

## Customization

### Change Instance Types

Edit `terraform.tfvars`:
```hcl
windows_instance_type = "t3.large"  # More powerful
ubuntu_instance_type  = "t3.micro"  # Smaller/cheaper
```

### Change Disk Sizes

Edit `terraform.tfvars`:
```hcl
windows_disk_size = 100  # Increase to 100 GB
ubuntu_disk_size  = 30   # Increase to 30 GB
```

### Change Region

Edit `terraform.tfvars`:
```hcl
aws_region        = "us-west-2"
availability_zone = "us-west-2a"
```

## Cleanup

To destroy all resources:

```bash
terraform destroy
```

Type `yes` when prompted to confirm.

## Outputs

After deployment, Terraform will display:
- Instance IDs
- Public and Private IP addresses
- Connection commands (RDP and SSH)
- AMI IDs used
- VPC and Subnet IDs

View outputs anytime with:
```bash
terraform output
```

## Troubleshooting

### Can't connect to Windows via RDP
- Ensure security group allows your IP on port 3389
- Wait 5-10 minutes after deployment for Windows to fully initialize
- Check that Elastic IP is attached

### Can't connect to Ubuntu via SSH
- Verify the SSH key path: `~/.ssh/aws_key`
- Ensure key has correct permissions: `chmod 400 ~/.ssh/aws_key`
- Check security group allows your IP on port 22

### Terraform errors
- Run `terraform validate` to check syntax
- Run `terraform fmt` to format files
- Check AWS credentials: `aws sts get-caller-identity`

## License

This configuration is provided as-is for educational and development purposes.
