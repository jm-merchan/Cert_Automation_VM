#!/bin/bash
# Ubuntu Server Configuration Script
# Project: ${project_name}
# Instance: ${instance_name}

set -e

# Log all output
exec > >(tee /var/log/userdata.log)
exec 2>&1

echo "Starting Ubuntu Server configuration..."
echo "Timestamp: $(date)"

# Update system packages
echo "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get upgrade -y

# Install essential packages
echo "Installing essential packages..."
sudo apt-get install -y \
    curl \
    wget \
    unzip \
    git \
    vim \
    htop \
    net-tools \
    build-essential \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    nginx

# Configure timezone
echo "Configuring timezone to ${timezone}..."
timedatectl set-timezone ${timezone}

# Enable and configure automatic security updates
echo "Configuring automatic security updates..."
apt-get install -y unattended-upgrades apt-listchanges
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
echo 'Unattended-Upgrade::Automatic-Reboot-Time "02:00";' >> /etc/apt/apt.conf.d/50unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# Configure hostname description
echo "Setting hostname..."
hostnamectl set-hostname ${instance_name}


# Install vault agent
echo "Installing Vault Agent..."
VAULT_VERSION="1.20.4"
wget https://releases.hashicorp.com/vault/"$VAULT_VERSION"/vault_"$VAULT_VERSION"_linux_amd64.zip
unzip vault_"$VAULT_VERSION"_linux_amd64.zip
sudo mv vault /usr/local/bin/
rm vault_"$VAULT_VERSION"_linux_amd64.zip

# Create Vault Agent configuration
sudo mkdir -p /etc/vault
sudo mkdir -p /etc/vault/templates
sudo mkdir -p /etc/ssl/vault-certs
sudo chown -R root:root /etc/ssl/vault-certs
sudo chmod 755 /etc/ssl/vault-certs

echo "Creating Vault Agent configuration..."
sudo tee /etc/vault/vault-agent-config.hcl > /dev/null <<'AGENTEOF'
exit_after_auth = false
pid_file = "/var/run/vault-agent.pid"

auto_auth {
  method "aws" {
      mount_path = "auth/aws"
      config = {
          type = "iam"
          role = "vault-role-for-aws-ec2role"
      }
  }

  sink "file" {
      config = {
          path = "/etc/vault/vault-token-via-agent"
      }
  }
}

vault {
  address = "${hcp_vault_cluster_url}"
}

template {
  source      = "/etc/vault/templates/certificate.tpl"
  destination = "/etc/ssl/vault-certs/cert-bundle.txt"
  exec {
        # Run the reload script through a shell to ensure a predictable environment
        command = ["/bin/bash", "-lc", "/usr/local/bin/reload-nginx.sh"]
  }
}

template_config {
  exit_on_retry_failure         = true
  max_connections_per_host      = 10
}
AGENTEOF

# Create certificate template using single pkiCert request with writeToFile
echo "Creating certificate template..."
sudo tee /etc/vault/templates/certificate.tpl > /dev/null <<'CERTEOF'
{{- with pkiCert "pki_int/issue/jose-merchan-sbx-hashidemos-io" "common_name=${dns_hostname}.${hosted_zone}" "ttl=2m" "alt_names=${instance_name}.example.com" -}}
{{ .Key | writeToFile "/etc/ssl/vault-certs/server.key" "root" "www-data" "0640" }}
{{ .Cert | writeToFile "/etc/ssl/vault-certs/server.crt" "root" "root" "0644" }}
{{ .CA | writeToFile "/etc/ssl/vault-certs/ca-chain.pem" "root" "root" "0644" }}
# Also render the certificate PEM to the template destination so Vault Agent detects
# changes to this template file when the certificate is renewed and triggers the exec.
{{- printf "%s" .Cert -}}
{{- end -}}
CERTEOF

# Create Nginx reload script
echo "Creating Nginx reload script..."
sudo tee /usr/local/bin/reload-nginx.sh > /dev/null <<'RELOADEOF'
#!/bin/bash
# Script to reload Nginx after certificate renewal
logger "Vault Agent: Reloading Nginx due to certificate renewal"
/usr/sbin/nginx -t 2>&1 | logger
/usr/sbin/nginx -s reload 2>&1 | logger
if [ $? -eq 0 ]; then
    logger "Vault Agent: Nginx reloaded successfully"
else
    logger "Vault Agent: Nginx reload failed"
    exit 1
fi
RELOADEOF

sudo chmod +x /usr/local/bin/reload-nginx.sh

# Set proper permissions
sudo chown -R root:root /etc/vault
sudo chmod 755 /etc/vault
sudo chmod 644 /etc/vault/vault-agent-config.hcl
sudo chmod 644 /etc/vault/templates/*.tpl


# Create systemd service for Vault Agent
echo "Creating systemd service for Vault Agent..."
sudo tee /etc/systemd/system/vault-agent.service > /dev/null <<SERVICEEOF
[Unit]
Description=Vault Agent
After=network-online.target
StartLimitIntervalSec=30
StartLimitBurst=3

[Service]
Type=simple
User=root
Group=root
Environment=VAULT_NAMESPACE=admin
ExecStart=/usr/local/bin/vault agent -config=/etc/vault/vault-agent-config.hcl
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
NoNewPrivileges=false

[Install]
WantedBy=multi-user.target
SERVICEEOF

# Enable and start Vault Agent service
echo "Enabling and starting Vault Agent service..."
sudo systemctl daemon-reload
sudo systemctl enable vault-agent
sudo systemctl start vault-agent

# Wait a moment for certificates to be generated
sleep 10

# Verify certificates were created
echo "Verifying certificate generation..."
if [ -f /etc/ssl/vault-certs/server.crt ]; then
    echo "✓ Certificate generated successfully"
    openssl x509 -in /etc/ssl/vault-certs/server.crt -noout -text | grep -E "Subject:|Issuer:|Not After"
else
    echo "✗ Certificate generation failed - check vault-agent logs"
    sudo journalctl -u vault-agent -n 50
fi

# Configure Nginx with HTTPS
echo "Configuring Nginx with HTTPS..."
sudo tee /etc/nginx/sites-available/default > /dev/null <<NGINXEOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${dns_hostname}.${hosted_zone} _;

    # Redirect HTTP to HTTPS
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name ${dns_hostname}.${hosted_zone} _;

    # SSL Configuration using Vault-issued certificates
    ssl_certificate /etc/ssl/vault-certs/server.crt;
    ssl_certificate_key /etc/ssl/vault-certs/server.key;
    ssl_trusted_certificate /etc/ssl/vault-certs/ca-chain.pem;

    # SSL Settings (Mozilla Intermediate configuration)
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=63072000" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Certificate info endpoint
    location /cert-info {
        access_log off;
        default_type text/plain;
        return 200 "Certificate Common Name: ${dns_hostname}.${hosted_zone}\nIssued by Vault PKI\n";
    }
}
NGINXEOF

# Create a simple landing page
echo "Creating landing page..."
sudo tee /var/www/html/index.html > /dev/null <<HTMLEOF
<!DOCTYPE html>
<html>
<head>
    <title>Vault PKI Certificate Demo</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            max-width: 800px;
            margin: 50px auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        h1 { color: #333; }
        .info { background: #e8f4f8; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .success { color: #28a745; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vault PKI Certificate Demo</h1>
        <p class="success">HTTPS is working with Vault-issued certificate!</p>
        
        <div class="info">
            <h3>Server Information</h3>
            <p><strong>Hostname:</strong> ${dns_hostname}.${hosted_zone}</p>
            <p><strong>Instance:</strong> ${instance_name}</p>
            <p><strong>Project:</strong> ${project_name}</p>
        </div>

        <div class="info">
            <h3>Certificate Details</h3>
            <p>This server is using a certificate issued by HashiCorp Vault PKI engine.</p>
            <p>Certificates are automatically renewed by Vault Agent before expiration.</p>
            <p><strong>Certificate Location:</strong> <code>/etc/ssl/vault-certs/server.crt</code></p>
            <p><strong>Private Key Location:</strong> <code>/etc/ssl/vault-certs/server.key</code></p>
        </div>

        <h3>Endpoints</h3>
        <ul>
            <li><a href="/health">/health</a> - Health check endpoint</li>
            <li><a href="/cert-info">/cert-info</a> - Certificate information</li>
        </ul>
    </div>
</body>
</html>
HTMLEOF

# Verify HTML file was created
echo "Verifying HTML file..."
if [ -f /var/www/html/index.html ]; then
    echo "✓ index.html created successfully"
    ls -lh /var/www/html/index.html
else
    echo "✗ Failed to create index.html"
fi

# Set proper permissions
sudo chown www-data:www-data /var/www/html/index.html
sudo chmod 644 /var/www/html/index.html

# Remove default Nginx page if it exists
sudo rm -f /var/www/html/index.nginx-debian.html

# Test Nginx configuration
echo "Testing Nginx configuration..."
sudo nginx -t

# Start Nginx
echo "Starting Nginx..."
sudo systemctl enable nginx
sudo systemctl restart nginx

# Display Nginx status
echo "Nginx status:"
sudo systemctl status nginx --no-pager

echo "✓ Nginx configured with HTTPS using Vault certificates"
echo "Access your site at: https://${dns_hostname}.${hosted_zone}"


# Create a marker file to indicate userdata completion
echo "UserData script completed at $(date)" > /var/log/userdata_completed.txt

echo "Ubuntu Server configuration completed successfully!"
         