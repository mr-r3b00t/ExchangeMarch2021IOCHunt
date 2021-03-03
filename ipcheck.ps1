#Hunt for bad ips in IIS logs
# mRr3b00t 
# crappy detection script made in a rush 03/03/2021
# version 0.2
# added in IP from reddit post: https://www.reddit.com/r/msp/comments/lwmo5c/mass_exploitation_of_onprem_exchange_servers/


#Requires -RunAsAdministrator




$badips = "103.77.192.219","104.140.114.110","104.250.191.110","108.61.246.56","149.28.14.163","157.230.221.198","167.99.168.251","185.250.151.72","192.81.208.169","203.160.69.66","211.56.98.146","5.254.43.18","80.92.205.81","165.232.154.116"

$files = Get-ChildItem -Recurse "C:\inetpub\logs\LogFiles\*.log"

foreach($file in $files)
{
#read the file contents into memory
write-host "Reading files"
write-host $file.Name
$readfile = Get-Content -Path $file


foreach($badIP in $badips){
write-host "Hunting for string $BadIP" -ForegroundColor Cyan

$readfile -match $badIP

}



}
