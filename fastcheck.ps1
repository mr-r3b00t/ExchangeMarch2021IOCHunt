# IOC CHECKS
# mRr3b00t - use at own risk i don't have an infected system to test on
# uses default paths
# tested on a clean exchange 2016 server
# run with admin rights as you need them to get to the paths 
# version 0.3

#check this folder for asp files C:\inetpub\wwwroot\aspnet_client\system_web

#using SHA256 for file hash checking

#Requires -RunAsAdministrator

$badhash = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0","097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e","2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1","65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5","511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1","4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea","811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d","1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944"

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
Get-EventLog -LogName Application -Source IIS-W3SVC-WP -InstanceId 2303
Get-EventLog -LogName Application -Source IIS-APPHOSTSVC -InstanceId 9009

#there should be entries
findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"

#there should be no events
Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }

#this should be blank
Select-String -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory'

#read all the IIS logs looking for POST requests to /owa/auth/Current/themes/resources/
$parse1 = Select-String -Path "C:\inetpub\logs\LogFiles\W3SVC1\*.log" -Pattern 'POST /owa/auth/Current/themes/resources/'

#if anytihng is found then investigate - this is not a fully developed script - use at own risk. check the mS docs.
