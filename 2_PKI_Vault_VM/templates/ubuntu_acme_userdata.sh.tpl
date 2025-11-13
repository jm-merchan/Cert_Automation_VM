#!/bin/bash
# Ubuntu ACME Server Configuration Script
# Project: ${project_name}
# Instance: ${instance_name}
# Purpose: Certbot with Nginx using Vault PKI as ACME server

set -e

# Log all output
exec > >(tee /var/log/userdata.log)
exec 2>&1

echo "Starting Ubuntu ACME Server configuration..."
echo "Timestamp: $(date)"

# Update system packages
echo "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update
sudo apt-get upgrade -y

# Install essential packages including Lego (ACME client with custom header support)
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

# Install Certbot with Nginx plugin
echo "Installing Certbot..."
sudo apt-get install -y python3-certbot-nginx

if ! command -v certbot &> /dev/null; then
    echo "[ERROR] Certbot installation failed"
    exit 1
fi

echo "[OK] Certbot installed successfully"
certbot --version

# Configure timezone
echo "Configuring timezone to ${timezone}..."
timedatectl set-timezone ${timezone}

# Enable and configure automatic security updates
echo "Configuring automatic security updates..."
apt-get install -y unattended-upgrades apt-listchanges
echo 'Unattended-Upgrade::Automatic-Reboot "false";' >> /etc/apt/apt.conf.d/50unattended-upgrades
echo 'Unattended-Upgrade::Automatic-Reboot-Time "02:00";' >> /etc/apt/apt.conf.d/50unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades

# Configure hostname
echo "Setting hostname..."
hostnamectl set-hostname ${instance_name}

# Create initial Nginx configuration (HTTP only for now)
echo "Configuring Nginx for HTTP..."
sudo tee /etc/nginx/sites-available/default > /dev/null <<'NGINXEOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${dns_hostname}.${hosted_zone};

    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files $uri $uri/ =404;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }

    # Well-known directory for ACME challenges
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }
}
NGINXEOF

# Create landing page
echo "Creating landing page..."
sudo tee /var/www/html/index.html > /dev/null <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Vault PKI ACME Demo - Certbot</title>
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
        .warning { background: #fff3cd; padding: 15px; border-radius: 4px; margin: 20px 0; }
        .success { color: #28a745; }
        code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: monospace; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 4px; overflow-x: auto; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Vault PKI ACME Demo - Certbot</h1>
        
        <div class="info">
            <h3>Certificate Setup</h3>
            <p>This server automatically obtains SSL certificates from Vault PKI via ACME protocol during startup.</p>
            <p>If you're seeing this page over HTTP, the certificate setup may still be in progress. Check back in a few moments or access via HTTPS.</p>
        </div>
        
        <div class="info">
            <h3>Server Information</h3>
            <p><strong>Hostname:</strong> ${dns_hostname}.${hosted_zone}</p>
            <p><strong>Instance:</strong> ${instance_name}</p>
            <p><strong>Project:</strong> ${project_name}</p>
        </div>

        <div class="info">
            <h3>Certbot Configuration</h3>
            <p>Certbot automatically obtains certificates from Vault PKI using ACME with External Account Binding (EAB).</p>
            <p><strong>ACME Server:</strong> HashiCorp Vault PKI</p>
            <p><strong>Method:</strong> HTTP-01 Challenge</p>
            <p><strong>Certificate Directory:</strong> <code>/etc/letsencrypt/live/${dns_hostname}.${hosted_zone}/</code></p>
            <p><strong>Auto-renewal:</strong> Enabled via Certbot timer</p>
        </div>

        <div class="info">
            <h3>Manual Certificate Renewal</h3>
            <p>To manually renew the certificate, SSH into the server and run:</p>
            <pre><code>sudo /usr/local/bin/get-vault-cert.sh</code></pre>
            <p><small>Or use Certbot directly:</small></p>
            <pre><code>sudo certbot renew</code></pre>
        </div>

        <h3>Endpoints</h3>
        <ul>
            <li><a href="/health">/health</a> - Health check endpoint</li>
        </ul>
    </div>
</body>
</html>
HTMLEOF

# Set proper permissions
sudo chown www-data:www-data /var/www/html/index.html
sudo chmod 644 /var/www/html/index.html
sudo rm -f /var/www/html/index.nginx-debian.html

# Start Nginx
echo "Starting Nginx..."
sudo systemctl enable nginx
sudo systemctl restart nginx

# Wait for DNS to propagate and Nginx to be ready
echo "Waiting for services to be ready..."
sleep 30

# Download Vault's CA certificate for validation
echo "Downloading Vault CA certificate..."
sudo mkdir -p /etc/vault
VAULT_CACERT_URL="${hcp_vault_cluster_url}/v1/admin/pki/ca/pem"
sudo curl -k -s "$VAULT_CACERT_URL" -o /etc/vault/vault-ca.pem

if [ -f /etc/vault/vault-ca.pem ] && [ -s /etc/vault/vault-ca.pem ]; then
    echo "[OK] Vault CA certificate downloaded successfully"
    
    # Install the CA certificate to system trust store
    sudo cp /etc/vault/vault-ca.pem /usr/local/share/ca-certificates/vault-ca.crt
    sudo update-ca-certificates
    
    echo "[OK] Vault CA certificate added to system trust store"
else
    echo "[ERROR] Failed to download Vault CA certificate"
fi

# Create Certbot configuration directory
echo "Creating Certbot configuration..."
sudo mkdir -p /etc/letsencrypt
sudo mkdir -p /var/log/certbot

# Note: With HCP Vault ACME enabled with eab_policy=always-required, 
# you'll need to obtain EAB credentials first
echo "Note: Vault ACME is configured with External Account Binding (EAB) required."
echo "To obtain certificates, you must first get EAB credentials from Vault."

# Create helper script for manual certificate renewal
sudo tee /usr/local/bin/get-vault-cert.sh > /dev/null <<'CERTSCRIPT'
#!/bin/bash
# Helper script to obtain certificate from Vault PKI via ACME using Certbot

DOMAIN="${dns_hostname}.${hosted_zone}"
VAULT_ACME_URL="${hcp_vault_cluster_url}/v1/admin/pki_int/acme/directory"
EMAIL="admin@${hosted_zone}"
EAB_KID="${eab_kid}"
EAB_HMAC="${eab_hmac_key}"

echo "=========================================="
echo "Vault PKI ACME Certificate Request"
echo "=========================================="
echo "Domain: $DOMAIN"
echo "ACME Server: $VAULT_ACME_URL"
echo ""

# Test ACME directory accessibility
echo "Testing ACME directory endpoint..."
curl -s "$VAULT_ACME_URL" | python3 -m json.tool || echo "Warning: Could not fetch ACME directory"
echo ""

echo "Requesting certificate with Certbot..."
sudo certbot --nginx \
  --domain "$DOMAIN" \
  --email "$EMAIL" \
  --server "$VAULT_ACME_URL" \
  --eab-kid "$EAB_KID" \
  --eab-hmac-key "$EAB_HMAC" \
  --non-interactive \
  --agree-tos

if [ $? -eq 0 ]; then
    echo ""
    echo "[OK] Certificate obtained successfully!"
    echo "Certificates stored in: /etc/letsencrypt/live/$DOMAIN/"
else
    echo ""
    echo "[ERROR] Certificate request failed!"
    exit 1
fi
CERTSCRIPT

sudo chmod +x /usr/local/bin/get-vault-cert.sh

# Automatically obtain certificate using Certbot with EAB credentials
echo "=========================================="
echo "Obtaining SSL Certificate from Vault PKI"
echo "=========================================="

DOMAIN="${dns_hostname}.${hosted_zone}"
VAULT_ACME_URL="${hcp_vault_cluster_url}/v1/admin/pki_int/acme/directory"
EMAIL="admin@${hosted_zone}"
EAB_KID="${eab_kid}"
EAB_HMAC="${eab_hmac_key}"

echo "Domain: $DOMAIN"
echo "ACME Server: $VAULT_ACME_URL"
echo "EAB Kid: $EAB_KID"
echo ""

# Test ACME directory accessibility
echo "Testing ACME directory endpoint..."
curl -s "$VAULT_ACME_URL" | python3 -m json.tool || echo "Warning: Could not fetch ACME directory"
echo ""

# Run Certbot with EAB credentials
sudo certbot --nginx \
  --domain "$DOMAIN" \
  --email "$EMAIL" \
  --server "$VAULT_ACME_URL" \
  --eab-kid "$EAB_KID" \
  --eab-hmac-key "$EAB_HMAC" \
  --non-interactive \
  --agree-tos \
  2>&1 | tee /var/log/certbot-initial.log

if [ $? -eq 0 ]; then
    echo ""
    echo "[OK] Certificate obtained successfully!"
    echo "[OK] Certificate location: /etc/letsencrypt/live/$DOMAIN/"
    
    # Display certificate info
    if [ -f "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" ]; then
        echo ""
        echo "Certificate Details:"
        openssl x509 -in "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" -noout -text | grep -E "Subject:|Issuer:|Not After"
        echo "[OK] Nginx configured with HTTPS by Certbot"
    fi
else
    echo ""
    echo "[ERROR] Certificate request failed - check /var/log/certbot-initial.log"
fi

# Display Nginx status
echo ""
echo "Nginx status:"
sudo systemctl status nginx --no-pager

echo ""
echo "=========================================="
echo "[OK] Ubuntu ACME Server Setup Complete"
echo "=========================================="
echo ""
echo "Server URL: https://${dns_hostname}.${hosted_zone}"
echo "ACME Directory: ${hcp_vault_cluster_url}/v1/admin/pki_int/acme/directory"
echo ""
echo "Certificate automatically obtained and configured!"
echo "Check logs: /var/log/certbot-initial.log"
echo ""
echo "To manually renew certificate, run:"
echo "  sudo /usr/local/bin/get-vault-cert.sh"
echo ""

# Create a marker file to indicate userdata completion
echo "UserData script completed at $(date)" > /var/log/userdata_completed.txt

echo "Ubuntu ACME Server configuration completed successfully!"
