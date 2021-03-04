#Hunt for bad ips in IIS logs
# mRr3b00t 
# crappy detection script made in a rush 03/03/2021
# version 0.1


#Requires -RunAsAdministrator




$badips = "103.77.192.219","104.140.114.110","104.250.191.110","108.61.246.56","149.28.14.163","157.230.221.198","167.99.168.251","185.250.151.72","192.81.208.169","203.160.69.66","211.56.98.146","5.254.43.18","80.92.205.81","165.232.154.116","104.248.49.97","5.2.69.13","91.192.103.43","161.35.45.41","45.77.252.175"

$files = Get-ChildItem -Recurse "C:\inetpub\logs\LogFiles\*.log"

foreach($file in $files)
{
#read the file contents into memory
write-host "Reading files"
write-host $file.Name
$readfile = Get-Content -Path $file


foreach($badIP in $badips){
write-host "Hunting for string $BadIP" -ForegroundColor Cyan

$found = $readfile -match $badIP
if($found){write-host $found -ForegroundColor Red

Read-Host -Prompt "YOu might want to investigate this event! Press enter to continue..."
}

}



}
