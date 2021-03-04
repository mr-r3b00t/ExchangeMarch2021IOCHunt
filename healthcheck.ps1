#Runs the microsoft exchange health check script
#just speeds this process up

#Requires -RunAsAdministrator
Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn

$TLS12Protocol = [System.Net.SecurityProtocolType] 'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol

wget https://github.com/dpaulson45/HealthChecker/releases/download/v3.3.2/HealthChecker.ps1 -OutFile HealthChecker.ps1

.\HealthChecker.ps1
.\HealthChecker.ps1 -BuildHtmlServersReport
