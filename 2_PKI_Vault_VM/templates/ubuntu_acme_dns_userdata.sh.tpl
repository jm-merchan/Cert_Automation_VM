#!/bin/bash
# Ubuntu ACME Server Configuration Script (DNS-01 Validation)
# Project: ${project_name}
# Instance: ${instance_name}
# Purpose: Certbot with Nginx using Vault PKI as ACME server with DNS-01 challenge

set -e

# Log all output
exec > >(tee /var/log/userdata.log)
exec 2>&1

echo "Starting Ubuntu ACME Server configuration (DNS-01 validation)..."
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
    nginx \
    python3-pip

# Install Certbot with Nginx and Route53 DNS plugins
echo "Installing Certbot with Route53 DNS plugin..."
sudo apt-get install -y python3-certbot-nginx
sudo pip3 install certbot-dns-route53

if ! command -v certbot &> /dev/null; then
    echo "[ERROR] Certbot installation failed"
    exit 1
fi

echo "[OK] Certbot installed successfully"
certbot --version

# Verify Route53 plugin is available
if certbot plugins | grep -q dns-route53; then
    echo "[OK] Certbot Route53 DNS plugin installed successfully"
else
    echo "[ERROR] Certbot Route53 DNS plugin not found"
    exit 1
fi

# Create Certbot deploy hook to reload Nginx after renewal
sudo tee /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh > /dev/null <<'EOF'
#!/bin/bash
systemctl reload nginx
EOF
sudo chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh

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
}
NGINXEOF

# Create landing page
echo "Creating landing page..."
sudo tee /var/www/html/index.html > /dev/null <<'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>Vault PKI ACME Demo - Certbot DNS-01</title>
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
        <h1>Vault PKI ACME Demo - Certbot DNS-01</h1>
        
        <div class="info">
            <h3>Certificate Setup</h3>
            <p>This server automatically obtains SSL certificates from Vault PKI via ACME protocol with DNS-01 validation during startup.</p>
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
            <p><strong>Method:</strong> DNS-01 Challenge (Route53)</p>
            <p><strong>Certificate Directory:</strong> <code>/etc/letsencrypt/live/${dns_hostname}.${hosted_zone}/</code></p>
            <p><strong>Auto-renewal:</strong> Enabled via Certbot timer</p>
        </div>

        <div class="info">
            <h3>DNS-01 Validation</h3>
            <p>DNS-01 validation uses AWS Route53 to create TXT records for domain ownership verification.</p>
            <p><strong>Benefits:</strong></p>
            <ul>
                <li>Works without requiring HTTP/HTTPS access</li>
                <li>Supports wildcard certificates</li>
                <li>Validates domain ownership via DNS</li>
            </ul>
        </div>

        <div class="info">
            <h3>Manual Certificate Renewal</h3>
            <p>To manually renew the certificate, SSH into the server and run:</p>
            <pre><code>sudo /usr/local/bin/get-vault-cert-dns.sh</code></pre>
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

# Create helper script for manual certificate renewal
sudo tee /usr/local/bin/get-vault-cert-dns.sh > /dev/null <<'CERTSCRIPT'
#!/bin/bash
# Helper script to obtain certificate from Vault PKI via ACME using Certbot with DNS-01 validation

DOMAIN="${dns_hostname}.${hosted_zone}"
VAULT_ACME_URL="${hcp_vault_cluster_url}/v1/admin/pki_int/acme/directory"
EMAIL="admin@${hosted_zone}"
EAB_KID="${eab_kid}"
EAB_HMAC="${eab_hmac_key}"

echo "=========================================="
echo "Vault PKI ACME Certificate Request (DNS-01)"
echo "=========================================="
echo "Domain: $DOMAIN"
echo "ACME Server: $VAULT_ACME_URL"
echo ""

# Test ACME directory accessibility
echo "Testing ACME directory endpoint..."
curl -s "$VAULT_ACME_URL" | python3 -m json.tool || echo "Warning: Could not fetch ACME directory"
echo ""

echo "Requesting certificate with Certbot (DNS-01 validation)..."
echo "Note: This will create TXT records in Route53 for domain validation"
echo ""

sudo certbot certonly \
  --dns-route53 \
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

sudo chmod +x /usr/local/bin/get-vault-cert-dns.sh

# Automatically obtain certificate using Certbot with EAB credentials and DNS-01 validation
echo "=========================================="
echo "Obtaining SSL Certificate from Vault PKI (DNS-01)"
echo "=========================================="

DOMAIN="${dns_hostname}.${hosted_zone}"
VAULT_ACME_URL="${hcp_vault_cluster_url}/v1/admin/pki_int/acme/directory"
EMAIL="admin@${hosted_zone}"
EAB_KID="${eab_kid}"
EAB_HMAC="${eab_hmac_key}"

echo "Domain: $DOMAIN"
echo "ACME Server: $VAULT_ACME_URL"
echo "EAB Kid: $EAB_KID"
echo "Validation: DNS-01 (Route53)"
echo ""

# Test ACME directory accessibility
echo "Testing ACME directory endpoint..."
curl -s "$VAULT_ACME_URL" | python3 -m json.tool || echo "Warning: Could not fetch ACME directory"
echo ""

echo "Note: DNS-01 validation will create TXT records in Route53"
echo "This requires IAM permissions for Route53 (attached via instance profile)"
echo ""

# Run Certbot with EAB credentials and DNS-01 validation
sudo certbot certonly \
  --dns-route53 \
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
        
        # Configure Nginx with the certificate
        echo "Configuring Nginx with SSL certificate..."
        sudo tee /etc/nginx/sites-available/default > /dev/null <<NGINXSSL
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name $DOMAIN;
    
    # Redirect HTTP to HTTPS
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name $DOMAIN;

    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    
    # SSL configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;

    root /var/www/html;
    index index.html index.htm;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # Health check endpoint
    location /health {
        access_log off;
        return 200 "healthy\\n";
        add_header Content-Type text/plain;
    }
}
NGINXSSL
        
        # Test and reload Nginx
        sudo nginx -t && sudo systemctl reload nginx
        echo "[OK] Nginx configured with HTTPS"
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
echo "[OK] Ubuntu ACME DNS Server Setup Complete"
echo "=========================================="
echo ""
echo "Server URL: https://${dns_hostname}.${hosted_zone}"
echo "ACME Directory: ${hcp_vault_cluster_url}/v1/admin/pki_int/acme/directory"
echo "Validation Method: DNS-01 (Route53)"
echo ""
echo "Certificate automatically obtained and configured!"
echo "Check logs: /var/log/certbot-initial.log"
echo ""
echo "To manually renew certificate, run:"
echo "  sudo /usr/local/bin/get-vault-cert-dns.sh"
echo ""

# Create a marker file to indicate userdata completion
echo "UserData script completed at $(date)" > /var/log/userdata_completed.txt

echo "Ubuntu ACME DNS Server configuration completed successfully!"
