# IOC CHECKS
# mRr3b00t - use at own risk i don't have an infected system to test on
# uses default paths
# tested on a clean exchange 2016 server
# run with admin rights as you need them to get to the paths 
# version 0.7

#check this folder for asp files C:\inetpub\wwwroot\aspnet_client\system_web

#using SHA256 for file hash checking

#Enable following line to see the progress step through this scripts. Not required for automation.
#$verbosepreference = "Continue"

#Requires -RunAsAdministrator

$badhash = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0","097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e","2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1","65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5","511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1","4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea","811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d","1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944"
Write-host "Checking C:\inetpub\wwwroot\aspnet_client for extra files"
$enumfiles = Get-ChildItem -Path C:\inetpub\wwwroot\aspnet_client -Recurse -File
foreach($file in $enumfiles){
write-host $file.DirectoryName
write-host $file.FullName
write-host $file.Name
$filehash = Get-FileHash -Path $file.FullName -Algorithm SHA256
$filehash.Hash
if($badhash.Contains($filehash.Hash)){write-host "BAD HASH DETECTED ASSUME BREACH" -ForegroundColor Red}
}
Write-host "Checking for suspect events in the event logs" -ForegroundColor Cyan
#there should be no events
Write-host "Checking IIS-W3SVC-WP event logs"
Get-EventLog -LogName Application -Source IIS-W3SVC-WP -InstanceId 2303
Write-host "Checking IIS-APPHOSTSVC event logs"
Get-EventLog -LogName Application -Source IIS-APPHOSTSVC -InstanceId 9009

Write-host "Checking for suspect events in the event logs" -ForegroundColor Cyan
#there should be no entries
Write-host "Checking OABGenerator logs" -ForegroundColor Cyan
findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"

#there should be no events
Write-host "Checking Unified Message event logs"  -ForegroundColor Cyan
Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }

#this should be blank
Write-host "Checking for Set-VirtualDirectory indicators"
Select-String -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory'

#read all the IIS logs looking for POST requests to /owa/auth/Current/themes/resources/
Write-host "Checking for theme resource indicators"
$parse1 = Select-String -Path "C:\inetpub\logs\LogFiles\W3SVC1\*.log" -Pattern 'POST /owa/auth/Current/themes/resources/'

foreach($line in $parse1){

write-host "Might want to investigate this" -ForegroundColor DarkRed
write-host $line -ForegroundColor DarkYellow


}

#IOC check from mS blog CVE-2021-26855
Write-host "Checking for CVE-2021-26855 in the HttpProxy logs" -ForegroundColor Cyan
#Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -Filter '*.log').FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox
# this totally broke on a live exchange box so i re-wrote my own detection method (tread carefully)
$files = Get-ChildItem -Recurse "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy\*.log"

foreach($file in $files)
{
#read the file contents into memory
write-host "Reading files"   -foregroundcolor Blue
write-host $file.Name  -foregroundcolor Yellow

$readfile = Get-Content -Path $file

if($readfile -like "*ServerInfo~*/*"){
#write-host $file.FullName  -foregroundcolor cyan
#write-host "SUSPICIOUS LOG DETECTED" -foregroundcolor red
#write-host "investigate further look for if the AuthenticatedUser is '' / NULL and if so its a sign of attempted exploit"

$suspect = $readfile | Select-String -Pattern "ServerInfo"

        #yoinked this from microsoft (thanks MS luv mRr3b00t)
      
         $fileResults = @(Import-Csv -Path $file.FullName -ErrorAction SilentlyContinue | Where-Object AnchorMailbox -Like 'ServerInfo~*/*' | Select-Object -Property DateTime, RequestId, ClientIPAddress, UrlHost, UrlStem, RoutingHint, UserAgent, AnchorMailbox, HttpStatus)
                            ForEach($item in $fileResults){
                            write-host "THANKS MICROSOFT ##" -ForegroundColor Gray
                            write-host "Suspicious item detected in : $file.FullName"  -foregroundcolor red
                                write-host $item -ForegroundColor White
                                read-host -Prompt "press enter to continue"
                            }
                             


    }

}


Write-host "Check for odd aspx files and odd timestamps in C:\inetpub\wwwroot\aspnet_client\ " -ForegroundColor Cyan

#look for odd aspx files
Get-ChildItem -Path C:\inetpub\wwwroot\aspnet_client\ -Recurse -Filter "*.aspx"

# look for odd aspx files (deafult names are "errorFE.aspx", "ExpiredPassword.aspx","frowny.aspex","logoff.aspx","logon.aspx","OutlookCN.aspx"."RedirSuiteServiceProxy.aspx",signout.aspx"
Write-host "Check for odd aspx files and odd timestamps in C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\" -ForegroundColor Cyan

Get-ChildItem -Path "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\" -Recurse -Filter "*.aspx*"


write-host "if anytihng is found then investigate - this is not a fully developed script - use at own risk. check the MS docs." -ForegroundColor Red
write-host "###########################################################" -ForegroundColor Gray

write-host "IOC Hunting development script made by mRr3b00t. Fight the bad pews, save the world! Hax4Good" -ForegroundColor Red
