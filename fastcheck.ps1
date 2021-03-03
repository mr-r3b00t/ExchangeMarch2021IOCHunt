# IOC CHECKS
# mRr3b00t - use at own risk i don't have an infected system to test on
# uses default paths
# tested on a clean exchange 2016 server
# run with admin rights as you need them to get to the paths 
# version 0.3

#check this folder for asp files C:\inetpub\wwwroot\aspnet_client\system_web

#using SHA256 for file hash checking

#Enable following line to see the progress step through this scripts. Not required for automation.
#$verbosepreference = "Continue"

#Requires -RunAsAdministrator

$badhash = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0","097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e","2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1","65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5","511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1","4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea","811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d","1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944"
write-verbose "Checking C:\inetpub\wwwroot\aspnet_client for extra files"
$enumfiles = Get-ChildItem -Path C:\inetpub\wwwroot\aspnet_client -Recurse -File
foreach($file in $enumfiles){
write-host $file.DirectoryName
write-host $file.FullName
write-host $file.Name
$filehash = Get-FileHash -Path $file.FullName -Algorithm SHA256
$filehash.Hash
if($badhash.Contains($filehash.Hash)){write-host "BAD HASH DETECTED ASSUME BREACH" -ForegroundColor Red}
}

#there should be no events
Write-verbose "Checking IIS-W3SVC-WP event logs"
Get-EventLog -LogName Application -Source IIS-W3SVC-WP -InstanceId 2303
Write-verbose "Checking IIS-APPHOSTSVC event logs"
Get-EventLog -LogName Application -Source IIS-APPHOSTSVC -InstanceId 9009

#there should be no entries
Write-verbose "Checking OABGenerator logs"
findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"

#there should be no events
Write-verbose "Checking Unified Message event logs"
Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }

#this should be blank
Write-verbose "Checking for Set-VirtualDirectory indicators"
Select-String -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory'

#read all the IIS logs looking for POST requests to /owa/auth/Current/themes/resources/
Write-verbose "Checking for theme resource indicators"
$parse1 = Select-String -Path "C:\inetpub\logs\LogFiles\W3SVC1\*.log" -Pattern 'POST /owa/auth/Current/themes/resources/'

foreach($line in $parse1){

write-host "Might want to investigate this" -ForegroundColor DarkRed
write-host $line -ForegroundColor DarkYellow


}

#IOC check from mS blog
Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -Filter '*.log').FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox

#look for odd aspx files
Get-ChildItem -Path C:\inetpub\wwwroot\aspnet_client\ -Recurse -Filter "*.aspx"

# look for odd aspx files (deafult names are "errorFE.aspx", "ExpiredPassword.aspx","frowny.aspex","logoff.aspx","logon.aspx","OutlookCN.aspx"."RedirSuiteServiceProxy.aspx",signout.aspx"
Get-ChildItem -Path "C:\Program Files\Microsoft\Exchange Server\V15\FrontEnd\HttpProxy\owa\auth\" -Recurse -Filter "*.aspx*"


#if anytihng is found then investigate - this is not a fully developed script - use at own risk. check the mS docs.
