<powershell>
# Windows Server 2022 ACME Configuration Script (DNS-01 Validation)
# Project: ${project_name}
# Instance: ${instance_name}
# Purpose: Certbot with IIS using Vault PKI as ACME server with DNS-01 challenge via Route53

# Log function
function Write-Log {
    param([string]$Message)
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    Write-Output $logMessage
    Add-Content -Path "C:\userdata.log" -Value $logMessage
}

Write-Log "Starting Windows ACME DNS Server configuration..."

# Set timezone
Write-Log "Setting timezone to ${timezone}..."
Set-TimeZone -Id "${timezone}"

# Set hostname
Write-Log "Setting hostname to ${instance_name}..."
Rename-Computer -NewName "${instance_name}" -Force

# Install IIS with management tools
Write-Log "Installing IIS..."
Install-WindowsFeature -Name Web-Server -IncludeManagementTools
Install-WindowsFeature -Name Web-Mgmt-Console

# Configure Windows Firewall to allow HTTPS
Write-Log "Configuring Windows Firewall for HTTPS..."
New-NetFirewallRule -DisplayName "Allow HTTPS Inbound" -Direction Inbound -Protocol TCP -LocalPort 443 -Action Allow -Enabled True
Write-Log "Firewall rules created for HTTP and HTTPS"

# Wait for IIS to be ready
Write-Log "Waiting for IIS to initialize..."
Start-Sleep -Seconds 10


# Create a simple web page (minimal HTML, no style)
Write-Log "Creating web page..."
$htmlContent = @"
<!DOCTYPE html>
<html>
<head>
    <title>Vault PKI ACME Demo - Windows DNS-01</title>
</head>
<body>
    <h1>Vault PKI ACME Demo - Windows DNS-01</h1>
    <p>Hostname: ${dns_hostname}.${hosted_zone}</p>
    <p>Instance: ${instance_name}</p>
    <p>Project: ${project_name}</p>
</body>
</html>
"@

$htmlContent | Out-File -FilePath "C:\inetpub\wwwroot\index.html" -Encoding utf8 -Force
Remove-Item "C:\inetpub\wwwroot\iisstart.htm" -ErrorAction SilentlyContinue

Write-Log "Web page created successfully"

# Install Python and Certbot
Write-Log "Installing Python and Certbot..."

# Download and install Python
Write-Log "Downloading Python installer..."
$pythonUrl = "https://www.python.org/ftp/python/3.11.9/python-3.11.9-amd64.exe"
$pythonInstaller = "C:\python-installer.exe"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $pythonUrl -OutFile $pythonInstaller

Write-Log "Installing Python..."
Start-Process -FilePath $pythonInstaller -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait

# Refresh environment variables
$env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path","User")

Write-Log "Installing Certbot and Route53 plugin..."
& "C:\Program Files\Python311\python.exe" -m pip install --upgrade pip
& "C:\Program Files\Python311\python.exe" -m pip install certbot certbot-dns-route53

Write-Log "Python and Certbot installed successfully"

# Download Vault CA certificate
Write-Log "Downloading Vault CA certificate..."
$vaultUrl = "${hcp_vault_cluster_url}"
$caCertUrl = "$vaultUrl/v1/admin/pki/ca/pem"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Path "C:\certbot" -Force | Out-Null
Invoke-WebRequest -Uri $caCertUrl -OutFile "C:\certbot\vault-ca.pem"

# Import Vault CA to Trusted Root store
Write-Log "Importing Vault CA certificate to Trusted Root store..."
$caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\certbot\vault-ca.pem")
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($caCert)
$store.Close()
Write-Log "Vault CA certificate imported successfully"

# Request certificate using Certbot with DNS-01 validation
Write-Log "Requesting certificate from Vault PKI via ACME (DNS-01)..."

$hostname = "${dns_hostname}.${hosted_zone}"
$eabKid = "${eab_kid}"
$eabKey = "${eab_hmac_key}"
$acmeDirectory = "$vaultUrl/v1/admin/pki_int/acme/directory"

Write-Log "Domain: $hostname"
Write-Log "ACME Server: $acmeDirectory"
Write-Log "EAB Kid: $eabKid"
Write-Log "Validation: DNS-01 (Route53)"

try {
    # Run Certbot with DNS-01 Route53 validation
    # Certbot automatically uses IAM instance profile credentials
    Write-Log "Running Certbot with Route53 DNS-01 validation..."
    
    $certbotArgs = @(
        "certonly",
        "--dns-route53",
        "--domain", $hostname,
        "--email", "admin@${hosted_zone}",
        "--server", $acmeDirectory,
        "--eab-kid", $eabKid,
        "--eab-hmac-key", $eabKey,
        "--non-interactive",
        "--agree-tos"
    )
    
    $certbotPath = "C:\Program Files\Python311\Scripts\certbot.exe"
    $process = Start-Process -FilePath $certbotPath `
        -ArgumentList $certbotArgs `
        -NoNewWindow `
        -Wait `
        -PassThru `
        -RedirectStandardOutput "C:\certbot\certbot.log" `
        -RedirectStandardError "C:\certbot\certbot-error.log"
    
    $exitCode = $process.ExitCode
    Write-Log "Certbot exit code: $exitCode"
    
    if ($exitCode -eq 0) {
        Write-Log "Certificate obtained successfully!"
        
        # Get certificate files
        $certPath = "C:\Certbot\live\$hostname"
        $certFile = "$certPath\cert.pem"
        $keyFile = "$certPath\privkey.pem"
        $chainFile = "$certPath\chain.pem"
        $fullchainFile = "$certPath\fullchain.pem"
        
        Write-Log "Certificate files:"
        Write-Log "  Cert: $certFile"
        Write-Log "  Key: $keyFile"
        Write-Log "  Chain: $chainFile"
        Write-Log "  Fullchain: $fullchainFile"
        
        # Convert PEM to PFX for IIS using Python cryptography library
        Write-Log "Converting certificate to PFX for IIS..."
        $pfxPassword = "certbot123"
        $pfxPath = "C:\certbot\$hostname.pfx"
        
        # Create Python script to convert PEM to PFX
        $pythonScript = @"
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Read certificate and key
with open(r'$fullchainFile', 'rb') as f:
    cert_data = f.read()
with open(r'$keyFile', 'rb') as f:
    key_data = f.read()

# Parse certificate and key
cert = x509.load_pem_x509_certificate(cert_data, default_backend())
key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

# Create PFX
pfx = pkcs12.serialize_key_and_certificates(
    name=b'$hostname',
    key=key,
    cert=cert,
    cas=None,
    encryption_algorithm=serialization.BestAvailableEncryption(b'$pfxPassword')
)

# Write PFX file
with open(r'$pfxPath', 'wb') as f:
    f.write(pfx)

print('PFX created successfully')
"@
        
        $pythonScript | Out-File -FilePath "C:\certbot\create_pfx.py" -Encoding UTF8
        & "C:\Program Files\Python311\python.exe" "C:\certbot\create_pfx.py"
        Write-Log "PFX file created at $pfxPath"
        
        # Install certificate in IIS
        Write-Log "Installing certificate in IIS..."
        Import-Module WebAdministration
        
        # Remove existing HTTPS binding if present
        $existingBinding = Get-WebBinding -Name "Default Web Site" -Protocol "https"
        if ($existingBinding) {
            Remove-WebBinding -Name "Default Web Site" -Protocol "https"
        }
        
        # Import PFX to certificate store
        $certPassword = ConvertTo-SecureString -String $pfxPassword -Force -AsPlainText
        $certObj = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\LocalMachine\My" -Password $certPassword
        
        # Create HTTPS binding
        New-WebBinding -Name "Default Web Site" -Protocol "https" -Port 443
        
        # Bind certificate to IIS
        $binding = Get-WebBinding -Name "Default Web Site" -Protocol "https"
        $binding.AddSslCertificate($certObj.Thumbprint, "my")
        
        Write-Log "Certificate installed and bound to IIS successfully"
        "Certificate obtained and installed at $(Get-Date)" | Out-File -FilePath "C:\certbot\success.txt"
    } else {
        Write-Log "ERROR: Certificate request failed with exit code $exitCode"
        Write-Log "Check logs at C:\certbot\certbot.log and C:\certbot\certbot-error.log"
    }
    
    # Display Certbot logs
    if (Test-Path "C:\certbot\certbot.log") {
        Write-Log "=== Certbot output ==="
        Get-Content "C:\certbot\certbot.log" | ForEach-Object { Write-Log $_ }
    }
    
    if (Test-Path "C:\certbot\certbot-error.log") {
        Write-Log "=== Certbot errors ==="
        Get-Content "C:\certbot\certbot-error.log" | ForEach-Object { Write-Log $_ }
    }
    
} catch {
    Write-Log "ERROR: Exception during certificate request: $_"
    Write-Log "Exception details: $($_.Exception.Message)"
    Write-Log "Stack trace: $($_.ScriptStackTrace)"
}

# Create scheduled task for automatic renewal
Write-Log "Creating scheduled task for certificate renewal..."
$taskName = "Certbot-Renewal"

# Create PowerShell script for renewal with IIS certificate update
$renewalScript = @"
# Certbot renewal with IIS certificate update
`$logFile = "C:\certbot\renewal.log"
`$timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

# Function to write to log
function Write-RenewalLog {
    param([string]`$Message)
    "`$timestamp - `$Message" | Out-File -FilePath `$logFile -Append
    Write-Output `$Message
}

Write-RenewalLog "Starting Certbot renewal check..."

# Run Certbot renewal
& "C:\Program Files\Python311\Scripts\certbot.exe" renew 2>&1 | Out-File -FilePath `$logFile -Append

# Check if any certificates were renewed
`$renewalOutput = Get-Content `$logFile -Tail 20
if (`$renewalOutput -match "Certificate not yet due for renewal") {
    Write-RenewalLog "No certificates needed renewal"
} elseif (`$renewalOutput -match "Successfully received certificate" -or `$renewalOutput -match "Congratulations") {
    Write-RenewalLog "Certificate was renewed! Updating IIS binding..."
    
    # Re-convert and re-install certificate in IIS
    `$hostname = "${dns_hostname}.${hosted_zone}"
    `$pfxPassword = "certbot123"
    `$pfxPath = "C:\certbot\`$hostname.pfx"
    `$fullchainFile = "C:\Certbot\live\`$hostname\fullchain.pem"
    `$keyFile = "C:\Certbot\live\`$hostname\privkey.pem"
    
    # Create PFX using Python
    `$pythonScript = @'
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from cryptography.hazmat.backends import default_backend

with open(r'$fullchainFile', 'rb') as f:
    cert_data = f.read()
with open(r'$keyFile', 'rb') as f:
    key_data = f.read()

cert = x509.load_pem_x509_certificate(cert_data, default_backend())
key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())

pfx = pkcs12.serialize_key_and_certificates(
    name=b'$hostname',
    key=key,
    cert=cert,
    cas=None,
    encryption_algorithm=serialization.BestAvailableEncryption(b'$pfxPassword')
)

with open(r'$pfxPath', 'wb') as f:
    f.write(pfx)
'@
    
    `$pythonScript | Out-File -FilePath "C:\certbot\renew_pfx.py" -Encoding UTF8
    & "C:\Program Files\Python311\python.exe" "C:\certbot\renew_pfx.py"
    
    # Import new certificate
    Import-Module WebAdministration
    `$certPassword = ConvertTo-SecureString -String `$pfxPassword -Force -AsPlainText
    `$certObj = Import-PfxCertificate -FilePath `$pfxPath -CertStoreLocation "Cert:\LocalMachine\My" -Password `$certPassword
    
    # Update IIS binding
    `$binding = Get-WebBinding -Name "Default Web Site" -Protocol "https"
    `$binding.AddSslCertificate(`$certObj.Thumbprint, "my")
    
    Write-RenewalLog "Certificate updated in IIS with thumbprint: `$(`$certObj.Thumbprint)"
} else {
    Write-RenewalLog "Certbot renewal completed"
}

Write-RenewalLog "Renewal check completed"
"@

$renewalScript | Out-File -FilePath "C:\certbot\renew.ps1" -Encoding utf8

# Check if task already exists
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Log "Scheduled task already exists, unregistering..."
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\certbot\renew.ps1"
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

Register-ScheduledTask -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Principal $principal `
    -Settings $settings `
    -Description "Automatic renewal of Certbot certificates from Vault PKI with IIS update"

Write-Log "Scheduled task created successfully"

# Display final status
Write-Log "=========================================="
Write-Log "Windows ACME DNS Server Setup Complete"
Write-Log "=========================================="
Write-Log ""
Write-Log "Server URL: https://${dns_hostname}.${hosted_zone}"
Write-Log "ACME Directory: $vaultUrl/v1/admin/pki_int/acme/directory"
Write-Log "Validation Method: DNS-01 (Route53)"
Write-Log "ACME Client: Certbot (Python)"
Write-Log ""
Write-Log "Certificate details:"
Write-Log "  - Location: C:\Certbot\live\${dns_hostname}.${hosted_zone}\"
Write-Log "  - IIS Site: Default Web Site"
Write-Log "  - Automatic renewal: Daily at 3 AM"
Write-Log ""
Write-Log "Certbot location: C:\Program Files\Python311\Scripts\certbot.exe"
Write-Log "Logs: C:\certbot\ and C:\userdata.log"
Write-Log ""
Write-Log "Configuration completed at $(Get-Date)"

# Create completion marker
"UserData script completed at $(Get-Date)" | Out-File -FilePath "C:\userdata_completed.txt"

Write-Log "Windows ACME DNS Server configuration completed successfully!"

</powershell>
<persist>true</persist>
