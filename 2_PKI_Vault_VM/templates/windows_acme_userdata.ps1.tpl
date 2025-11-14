<powershell>
Set-ExecutionPolicy Bypass -Scope Process -Force
Set-TimeZone -Id "${timezone}"
Enable-PSRemoting -Force
Set-Item WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item WSMan:\localhost\Service\AllowUnencrypted -Value $true
netsh advfirewall firewall add rule name="HTTP" dir=in localport=80 protocol=TCP action=allow | Out-Null
netsh advfirewall firewall add rule name="HTTPS" dir=in localport=443 protocol=TCP action=allow | Out-Null
Restart-Service WinRM
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "srvcomment" -Value "${instance_name}"

# Install IIS
Install-WindowsFeature -Name Web-Server,Web-Mgmt-Console | Out-Null
Start-Service W3SVC
Set-Service W3SVC -StartupType Automatic

# Create web root content
$wwwRoot = 'C:\inetpub\wwwroot'
@"
<!DOCTYPE html>
<html>
<head>
    <title>Vault PKI ACME Certificate Demo</title>
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
        <h1>Vault PKI ACME Certificate Demo</h1>
        <p class="success">HTTPS is working with Vault ACME-issued certificate!</p>
        
        <div class="info">
            <h3>Server Information</h3>
            <p><strong>Hostname:</strong> ${dns_hostname}.${hosted_zone}</p>
            <p><strong>Instance:</strong> ${instance_name}</p>
            <p><strong>Project:</strong> ${project_name}</p>
        </div>

        <div class="info">
            <h3>Certificate Details</h3>
            <p>This server is using a certificate issued by HashiCorp Vault PKI via ACME protocol.</p>
            <p>Certificates are automatically renewed by win-acme before expiration.</p>
            <p><strong>ACME Client:</strong> win-acme (supports PKCS12 for IIS)</p>
            <p><strong>Certificate Store:</strong> Local Machine Personal Store</p>
        </div>

        <div class="info">
            <h3>ACME Configuration</h3>
            <p><strong>ACME Server:</strong> Vault PKI</p>
            <p><strong>Directory URL:</strong> <code>${hcp_vault_cluster_url}/v1/admin/pki_int/acme/directory</code></p>
            <p><strong>Authentication:</strong> External Account Binding (EAB)</p>
            <p><strong>Renewal:</strong> Automatic via Windows Scheduled Task</p>
        </div>

        <h3>Endpoints</h3>
        <ul>
            <li><a href="/health">/health</a> - Health check endpoint</li>
            <li><a href="/cert-info">/cert-info</a> - Certificate information</li>
        </ul>
    </div>
</body>
</html>
"@ | Out-File "$wwwRoot\index.html" -Encoding UTF8
"healthy" | Out-File "$wwwRoot\health" -Encoding ASCII
"Certificate Common Name: ${dns_hostname}.${hosted_zone}`nIssued by Vault PKI via ACME" | Out-File "$wwwRoot\cert-info" -Encoding ASCII

# Install Chocolatey
$chocoBin = "C:\ProgramData\chocolatey\bin\choco.exe"
if (-not (Test-Path $chocoBin)) {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
  Start-Sleep 5
}
if (Test-Path $chocoBin) {
  $env:Path += ";C:\ProgramData\chocolatey\bin"
  [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
}

# Create win-acme directory
New-Item -ItemType Directory -Force -Path "C:\win-acme" | Out-Null
New-Item -ItemType Directory -Force -Path "C:\win-acme\logs" | Out-Null

# Download win-acme
$winAcmeVersion = "2.2.9.1701"
$winAcmeUrl = "https://github.com/win-acme/win-acme/releases/download/v$${winAcmeVersion}/win-acme.v$${winAcmeVersion}.x64.pluggable.zip"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $winAcmeUrl -OutFile "C:\win-acme\win-acme.zip"
Expand-Archive -Path "C:\win-acme\win-acme.zip" -DestinationPath "C:\win-acme" -Force
Remove-Item "C:\win-acme\win-acme.zip"

# Download Vault CA certificate
$hostedZone = "${hosted_zone}".TrimEnd('.')
$vaultUrl = "${hcp_vault_cluster_url}"
$caCertUrl = "$vaultUrl/v1/admin/pki/ca/pem"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $caCertUrl -OutFile "C:\win-acme\vault-ca.pem"

# Import Vault CA to Trusted Root store
$caCert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2("C:\win-acme\vault-ca.pem")
$store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
$store.Open("ReadWrite")
$store.Add($caCert)
$store.Close()

# Configure IIS to serve extensionless files (required for ACME challenges)
Import-Module WebAdministration

# Allow double escaping for .well-known paths
Set-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter "system.webServer/security/requestFiltering" -Name "allowDoubleEscaping" -Value $true

# Add MIME type for extensionless files at the site level
try {
    Remove-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter "system.webServer/staticContent" -Name "." -AtElement @{fileExtension='.'} -ErrorAction SilentlyContinue
} catch {}

Add-WebConfigurationProperty -PSPath "IIS:\Sites\Default Web Site" -Filter "system.webServer/staticContent" -Name "." -Value @{fileExtension='.'; mimeType='text/plain'}

# Restart IIS to apply changes
iisreset | Out-Null
Start-Sleep 3

# Create win-acme settings.json with EAB configuration
$settingsJson = @"
{
  "ClientName": "${instance_name}",
  "BaseUri": "$vaultUrl/v1/admin/pki_int/acme/directory",
  "Acme": {
    "DefaultBaseUri": "$vaultUrl/v1/admin/pki_int/acme/directory",
    "PostAsGet": true
  },
  "Validation": {
    "AllowHttp": true
  },
  "Store": {
    "CertificateStore": {
      "DefaultStore": "My"
    }
  }
}
"@
$settingsJson | Out-File "C:\win-acme\settings.json" -Encoding ASCII

# Create win-acme script for certificate request with EAB
$hostname = "${dns_hostname}.$hostedZone"
$eabKid = "${eab_kid}"
$eabKey = "${eab_hmac_key}"

$requestScript = @"
`$wacs = "C:\win-acme\wacs.exe"
`$logPath = "C:\win-acme\logs\request.log"

# Request certificate with EAB
& `$wacs --source manual ``
  --host "$hostname" ``
  --webroot "C:\inetpub\wwwroot" ``
  --validation filesystem ``
  --validationmode http-01 ``
  --installation iis ``
  --installationsiteid 1 ``
  --store certificatestore ``
  --baseuri "$vaultUrl/v1/admin/pki_int/acme/directory" ``
  --emailaddress "admin@$hostedZone" ``
  --accepttos ``
  --eab-key-identifier "$eabKid" ``
  --eab-key "$eabKey" ``
  --verbose ``
  > `$logPath 2>&1

if (`$LASTEXITCODE -eq 0) {
  "Certificate request successful: `$(Get-Date)" | Out-File "C:\win-acme\success.txt"
  
  # Get the certificate thumbprint and bind to IIS
  `$cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { `$_.Subject -like "*$hostname*" } | Sort-Object NotBefore -Descending | Select-Object -First 1
  
  if (`$cert) {
    Import-Module WebAdministration
    
    # Remove existing HTTPS binding if it exists
    if (Get-WebBinding -Name "Default Web Site" -Protocol https -ErrorAction SilentlyContinue) {
      Remove-WebBinding -Name "Default Web Site" -Protocol https -Port 443
    }
    
    # Create new HTTPS binding
    New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -IPAddress "*" | Out-Null
    
    # Bind certificate
    `$sslPath = "IIS:\SslBindings\0.0.0.0!443"
    if (Test-Path `$sslPath) { Remove-Item `$sslPath -Force }
    New-Item -Path `$sslPath -Value `$cert -SSLFlags 0 | Out-Null
    
    # Restart IIS
    iisreset /restart | Out-Null
    
    "Certificate bound to IIS: `$(Get-Date)" | Out-File "C:\win-acme\iis-bound.txt"
  }
} else {
  "Certificate request failed with exit code `$LASTEXITCODE" | Out-File "C:\win-acme\error.txt"
}
"@
$requestScript | Out-File "C:\win-acme\request-cert.ps1" -Encoding ASCII

# Execute the certificate request
& PowerShell.exe -ExecutionPolicy Bypass -File "C:\win-acme\request-cert.ps1"

# Create scheduled task for automatic renewal
# win-acme creates its own scheduled task, but we'll ensure it runs at startup too
$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -WindowStyle Hidden -File C:\win-acme\request-cert.ps1"
$Trigger = New-ScheduledTaskTrigger -Daily -At 3am
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "VaultACMERenewal" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null

# Wait for certificate to be issued and bound
Start-Sleep 60

# Verify HTTPS is working
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
  $response = Invoke-WebRequest -Uri "https://$hostname/health" -UseBasicParsing -TimeoutSec 10
  if ($response.StatusCode -eq 200) {
    "HTTPS verification successful: $(Get-Date)" | Out-File "C:\win-acme\https-verified.txt"
  }
} catch {
  "HTTPS verification failed: $_" | Out-File "C:\win-acme\https-error.txt"
}

"Userdata completed: $(Get-Date)" | Out-File "C:\userdata_completed.txt"
</powershell>
