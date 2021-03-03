#quick and dirty download hotfix and install msp file for exchange 2016 cu 18

$TLS12Protocol = [System.Net.SecurityProtocolType] 'Tls12'
[System.Net.ServicePointManager]::SecurityProtocol = $TLS12Protocol

wget -Uri https://download.microsoft.com/download/0/e/4/0e4056bd-0d6d-4738-a43b-bf9e23b14298/Exchange2016-KB5000871-x64-en.msp -OutFile Exchange2016-KB5000871-x64-en.msp

msiexec /p Exchange2016-KB5000871-x64-en.msp /qb!
