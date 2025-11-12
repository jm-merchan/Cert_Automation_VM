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

Install-WindowsFeature -Name Web-Server,Web-Mgmt-Console | Out-Null
Start-Service W3SVC
Set-Service W3SVC -StartupType Automatic
$wwwRoot = 'C:\inetpub\wwwroot'
@"
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
            <p><strong>Certificate Location:</strong> <code>C:\vault\certs\server.crt</code></p>
            <p><strong>Private Key Location:</strong> <code>C:\vault\certs\server.key</code></p>
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
"Certificate Common Name: ${dns_hostname}.${hosted_zone}`nIssued by Vault PKI" | Out-File "$wwwRoot\cert-info" -Encoding ASCII

$VaultVersion = "1.20.4"
$VaultZip = "vault_$${VaultVersion}_windows_amd64.zip"
$VaultUrl = "https://releases.hashicorp.com/vault/$${VaultVersion}/$${VaultZip}"
New-Item -ItemType Directory -Force -Path "C:\vault\templates","C:\vault\certs","C:\vault\logs" | Out-Null
icacls "C:\vault" /grant "NT AUTHORITY\SYSTEM:(OI)(CI)F" | Out-Null
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $VaultUrl -OutFile "C:\vault\$VaultZip"
Expand-Archive -Path "C:\vault\$VaultZip" -DestinationPath "C:\vault" -Force
Remove-Item "C:\vault\$VaultZip"
$env:Path += ";C:\vault"
[Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)

@"
exit_after_auth = false
pid_file = "C:/vault/pidfile"

auto_auth {
  method "aws" {
    mount_path = "auth/aws"
    config = {
      type = "iam"
      role = "vault-role-for-aws-ec2role"
    }
  }

  sink "file" {
    wrap_ttl = "5m"
    config = {
      path = "C:/vault/vault-token-via-agent"
    }
  }
}

vault {
  address = "${hcp_vault_cluster_url}"
}

template {
  source = "C:/vault/templates/certificate.tpl"
  destination = "C:/vault/certs/cert-bundle.pem"
  exec {
    command = ["powershell", "-ExecutionPolicy", "Bypass", "-File", "C:/vault/reload-iis.ps1"]
  }
}

template_config {
  exit_on_retry_failure = true
}
"@ | Out-File "C:\vault\vault-agent-config.hcl" -Encoding ASCII

"C:\vault\vault.exe agent -config=C:\vault\vault-agent-config.hcl -namespace=admin" | Out-File "C:\vault\start-vault-agent.ps1" -Encoding ASCII

$hostedZone = "${hosted_zone}".TrimEnd('.')
@"
{{- with pkiCert "pki_int/issue/jose-merchan-sbx-hashidemos-io" "common_name=${dns_hostname}.$hostedZone" "ttl=2m" -}}
{{ .Key | writeToFile "C:/vault/certs/server.key" "" "" "0600" }}
{{ .Cert | writeToFile "C:/vault/certs/server.crt" "" "" "0644" }}
{{ .CA | writeToFile "C:/vault/certs/ca-chain.pem" "" "" "0644" }}
{{- printf "%s" .Cert -}}
{{- end -}}
"@ | Out-File "C:\vault\templates\certificate.tpl" -Encoding ASCII

$chocoBin = "C:\ProgramData\chocolatey\bin\choco.exe"
if (-not (Test-Path $chocoBin)) {
  iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
  Start-Sleep 5
}
if (Test-Path $chocoBin) {
  $env:Path += ";C:\ProgramData\chocolatey\bin"
  [Environment]::SetEnvironmentVariable("Path", $env:Path, [EnvironmentVariableTarget]::Machine)
  & $chocoBin install openssl.light -y --no-progress --force
  Start-Sleep 10
}

@'
$pfxPath = "C:\vault\certs\server.pfx"
$openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
if (-not $openssl) { $openssl = "C:\ProgramData\chocolatey\bin\openssl.exe" }
if (-not (Test-Path $openssl)) {
  $choco = "C:\ProgramData\chocolatey\bin\choco.exe"
  if (Test-Path $choco) { & $choco install openssl.light -y --no-progress; Start-Sleep 5 }
  $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
  if (-not $openssl) { exit 1 }
}
& $openssl pkcs12 -export -out $pfxPath -inkey C:\vault\certs\server.key -in C:\vault\certs\server.crt -certfile C:\vault\certs\ca-chain.pem -passout pass:changeit
if ($LASTEXITCODE -ne 0) { exit 1 }
$pwd = ConvertTo-SecureString -String "changeit" -AsPlainText -Force
$cert = Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation Cert:\LocalMachine\My -Password $pwd -Exportable
Import-Module WebAdministration
if (-not (Get-WebBinding -Name "Default Web Site" -Protocol https -ErrorAction SilentlyContinue)) {
  New-WebBinding -Name "Default Web Site" -Protocol https -Port 443 -IPAddress "*" | Out-Null
}
$sslPath = "IIS:\SslBindings\0.0.0.0!443"
if (Test-Path $sslPath) { Remove-Item $sslPath -Force }
New-Item -Path $sslPath -Value $cert | Out-Null
iisreset /restart | Out-Null
'@ | Out-File "C:\vault\reload-iis.ps1" -Encoding ASCII

icacls "C:\vault\reload-iis.ps1" /grant "NT AUTHORITY\SYSTEM:(RX)" | Out-Null

$Action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File C:\vault\start-vault-agent.ps1"
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
Register-ScheduledTask -TaskName "VaultAgent" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings | Out-Null
Start-ScheduledTask -TaskName "VaultAgent"
Start-Sleep 30
if (Test-Path "C:\vault\certs\server.crt") { & "C:\vault\reload-iis.ps1" }
"Completed: $(Get-Date)" | Out-File "C:\userdata_completed.txt"
</powershell>
