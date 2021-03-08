# IOC CHECKS
# mRr3b00t - use at own risk i don't have an infected system to test on
# uses default paths
# tested on a clean exchange 2016 server
# run with admin rights as you need them to get to the paths 

#check this folder for asp files \inetpub\wwwroot\aspnet_client\system_web

#using SHA256 for file hash checking

#Enable following line to see the progress step through this scripts. Not required for automation.
#$verbosepreference = "Continue"

#Requires -RunAsAdministrator


############################# GET EXCHANGE PATH ###############################
#where is excahnge insatlled? borrowed from MS fanks MS peeps
  $exchangepath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v15\Setup -ErrorAction SilentlyContinue).MsiInstallPath
  if ($null -eq $exchangepath) {
                        $exchangepath = (Get-ItemProperty -Path Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\ExchangeServer\v14\Setup -ErrorAction SilentlyContinue).MsiInstallPath
                    }

                    if($exchangepath -ne ''){
                    write-host "Exchange Found" -ForegroundColor Green
                    write-host $exchangepath
                 
                    }
                    else {
                       write-host "Exchange not found" -ForegroundColor Magenta
                    break Uknown
                    
                    }

############################ END OF GET EXCHANGE PATH ###############################

read-host "Press ENTER to Continue"

##############################CHECK WINDOWS EVENT LOGS###############################

Write-host "############Checking for suspect events in the Windows event logs#############" -ForegroundColor Cyan
#there should be no events
Write-host "Checking IIS-W3SVC-WP event logs" -ForegroundColor Cyan
Get-EventLog -LogName Application -Source IIS-W3SVC-WP -InstanceId 2303 -ErrorAction SilentlyContinue
Write-host "Checking IIS-APPHOSTSVC event logs" -ForegroundColor Cyan
Get-EventLog -LogName Application -Source IIS-APPHOSTSVC -InstanceId 9009 -ErrorAction SilentlyContinue


#CHECK UNIFIED MESSAGING LOGS

#there should be no events
Write-host "Checking Unified Message event logs"  -ForegroundColor Cyan
Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*System.InvalidCastException*" } 

##############################CHECK WINDOWS EVENT LOGS END ###############################


######################################
#CHECK PROXY LOGS
######################################

#IOC check from mS blog CVE-2021-26855
Write-host "############################################################################" -ForegroundColor Cyan
Write-host "Checking for CVE-2021-26855 in the HttpProxy logs" -ForegroundColor Cyan

read-host "Press ENTER to Continue"

#Import-Csv -Path (Get-ChildItem -Recurse -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\HttpProxy" -Filter '*.log').FullName | Where-Object {  $_.AuthenticatedUser -eq '' -and $_.AnchorMailbox -like 'ServerInfo~*/*' } | select DateTime, AnchorMailbox
# this totally broke on a live exchange box so i re-wrote my own detection method (tread carefully)

#HTTP Proxy path

$proxylogpath = $exchangepath + "Logging\HttpProxy\*.log"
$proxylogpath

$files = Get-ChildItem -Recurse $proxylogpath

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


######################################
#STOP CHECKING HTTP PROXY LOGS
######################################


######################################
# CHECK OAB LOGS
######################################

write-host "########################################################"
Write-host "Checking OABGenerator logs" -ForegroundColor Cyan

$frontendpath = $exchangepath + "FrontEnd\HttpProxy\owa\auth\"
$frontendpath

read-host "Press ENTER to Continue"

Write-host "Check for odd aspx files and odd timestamps in $frontendpath" -ForegroundColor Cyan

Get-ChildItem -Path $frontendpath -Recurse -Filter "*.aspx*"

######################################
# STOP CHECKING OAB LOGS
######################################


######################################################
# CHECK IIS LOGS FOR KNOWN BAD IPS
#Check for known bad IPS - this is already in the repo in a ipcheck.ps1 script but i've moved it here as well
######################################################

Write-host "Checking IIS logs for known bad IPs associated with Hafnium" -ForegroundColor Cyan
read-host "Press ENTER to Continue"

#this list is taken from veloxity and privately reported Ips - you need to check what they traffic is doing not just assume
$badips = "103.77.192.219","104.140.114.110","104.250.191.110","108.61.246.56","149.28.14.163","157.230.221.198","167.99.168.251","185.250.151.72","192.81.208.169","203.160.69.66","211.56.98.146","5.254.43.18","80.92.205.81","165.232.154.116","104.248.49.97","5.2.69.13","91.192.103.43","161.35.45.41","45.77.252.175","1.36.203.86","1.65.152.106","103.212.223.210","104.225.219.16","108.172.93.199","110.36.235.230","110.36.238.2","110.39.189.202","112.168.90.84","114.205.37.150","116.49.101.143","117.146.53.162","119.197.26.38","119.231.129.222","121.154.50.51","121.174.31.220","121.176.145.25","122.213.178.102","123.16.231.247","124.5.24.161","139.59.56.239","161.35.76.1","167.179.67.3","170.10.228.74","172.105.87.139","179.1.65.54","182.165.53.4","185.171.166.188","185.224.83.137","200.52.177.138","201.17.196.211","201.208.18.226","202.182.118.99","209.58.163.131","211.177.182.80","213.219.235.158","218.39.251.104","219.100.37.239","219.100.37.243","219.78.205.63","23.95.80.191","31.182.197.163","31.28.31.132","34.87.189.145","39.123.17.120","46.101.232.43","46.23.196.21","49.36.47.211","58.126.135.235","58.190.46.175","61.82.150.49","78.188.104.84","78.189.225.136","86.105.18.116","89.147.119.227","90.230.190.92"



                    #find IIS logs path
           
           foreach($WebSite in $(get-website))
 {
    $logFilePaths="$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
    Write-host "$($WebSite.name) [$logFilePaths]"
    $WebSite.physicalPath
    #$logFilePaths

 
 #check for aspx files

 
#look for odd aspx files
# REMMED OUT AS WE DO THIS AGAIN LATER
#Get-ChildItem -Path $WebSite.physicalPath -Recurse -Filter "*.aspx"



$files = Get-ChildItem -Recurse "$logFilePaths\*.log"

foreach($file in $files)
    {
            #read the file contents into memory
            write-host "Reading files"
            write-host $file.Name
             write-host $file.FullName
            $readfile = Get-Content -Path $file


                            foreach($badIP in $badips){
                            write-host "Hunting for string $BadIP" -ForegroundColor Cyan

                            $found = $readfile -cmatch $badIP

                            if($found)
                            {
                            write-host $found -ForegroundColor Red
                            write-host "########WARNING##############" -ForegroundColor Red
                            write-host "whilst hunting for $BadIp in $file we found a match." -ForegroundColor Gray

                            if($readfile | Select-String -Pattern $badIP -SimpleMatch){Read-Host -Prompt "YOu might want to investigate this event! Press enter to continue..."}

                            Read-Host -Prompt "Review this - it's a bit buggy! Press enter to continue..."
                            }

            }

    }


}


######################################################
# STOP CHECKING IIS LOGS FOR KNOWN BAD IPS
#######################################################



   Write-host "Check for odd aspx files and odd timestamps in web content sites " -ForegroundColor Cyan
   write-host "################### WARNING THIS GENERATES QUITE A BIT OF CONTENT TO REVIEW but reviewing it is a good idea ###################"

   Read-Host "Press enter to continue"

#look for odd aspx files
# look for odd aspx files (deafult names are "errorFE.aspx", "ExpiredPassword.aspx","frowny.aspex","logoff.aspx","logon.aspx","OutlookCN.aspx"."RedirSuiteServiceProxy.aspx",signout.aspx"

#this spits out alot of data - the timestamps should be OLD (they are at least in RTM version - 2018)
#get rid of this hard coded path

          foreach($WebSite in $(get-website))
 {
    $logFilePaths="$($Website.logFile.directory)\w3svc$($website.id)".replace("%SystemDrive%",$env:SystemDrive)
    Write-host "$($WebSite.name) [$logFilePaths]"
    $WebSite.physicalPath

    #replace %SystemDrive% with actual path
    if( $WebSite.physicalPath -like '*%SystemDrive%*'){


    $osdrive = (Get-WmiObject Win32_OperatingSystem).SystemDrive

    $newpath = $WebSite.physicalPath -replace "%SystemDrive%", "$osdrive"
    (Get-WmiObject Win32_OperatingSystem).SystemDrive
    write-host "environment var detected" -ForegroundColor DarkRed
    write-host $newpath
    }
    else
    {
    
    $newpath = $WebSite.physicalPath
      
    }

    Get-ChildItem $newpath -Recurse -filter "*.aspx"


    
$badhash = "b75f163ca9b9240bf4b37ad92bc7556b40a17e27c2b8ed5c8991385fe07d17d0","097549cf7d0f76f0d99edf8b2d91c60977fd6a96e4b8c3c94b0b1733dc026d3e","2b6f1ebb2208e93ade4a6424555d6a8341fd6d9f60c25e44afe11008f5c1aad1","65149e036fff06026d80ac9ad4d156332822dc93142cf1a122b1841ec8de34b5","511df0e2df9bfa5521b588cc4bb5f8c5a321801b803394ebc493db1ef3c78fa1","4edc7770464a14f54d17f36dc9d0fe854f68b346b27b35a6f5839adf1f13f8ea","811157f9c7003ba8d17b45eb3cf09bef2cecd2701cedb675274949296a6a183d","1631a90eb5395c4e19c7dbcbf611bbe6444ff312eb7937e286e4637cb9e72944"
Write-host "Checking inetpub\wwwroot\aspnet_client for extra files"
$enumfiles = Get-ChildItem -Path $newpath -filter "*.aspx" -Recurse -File
foreach($file in $enumfiles){
write-host $file.DirectoryName
write-host $file.FullName
write-host $file.Name
$filehash = Get-FileHash -Path $file.FullName -Algorithm SHA256

write-host $filehash.Hash -ForegroundColor Gray

if($badhash.Contains($filehash.Hash)){write-host "BAD HASH DETECTED ASSUME BREACH" -ForegroundColor Red}
else
{
#do nothing as it's very noisy
}

}



}


######################################################
# HARD CODED CHECKS FOR SPECIFIC IOCS
######################################################

####CHECK THE ISS LOGS for POST Requests to /owa/auth/Current/themes/resources

#read all the IIS logs looking for POST requests to /owa/auth/Current/themes/resources/
Write-host "Checking for theme resource indicators"

#FIX THIS HARD CODED PATH
$parse1 = Select-String -Path "C:\inetpub\logs\LogFiles\W3SVC1\*.log" -Pattern 'POST /owa/auth/Current/themes/resources/'

foreach($line in $parse1){

write-host "Might want to investigate this" -ForegroundColor DarkRed
write-host $line -ForegroundColor DarkYellow


}

#CHECK OAB LOGS

$oabpath = $exchangepath + "Logging\OABGeneratorLog\*.log"
$oabpath
Write-host "Checking OABGenerator logs" -ForegroundColor Cyan

#findstr /snip /c:"192.81.208.169" C:\inetpub\logs\LogFiles\W3SVC1\*.log
findstr /snip /c:"Download failed and temporary file" $oabpath


#this should be blank
Write-host "Checking for Set-VirtualDirectory indicators"
$ecppath = $exchangepath + "Logging\ECP\Server\*.log"
$ecppath

Select-String -Path $ecppath -Pattern 'Set-.+VirtualDirectory'

######################################################
# END OF HARD CODED CHECKS FOR SPECIFIC IOCS
######################################################



######################################################
# END OF SCRIPT MESSAGE
######################################################

write-host "if anytihng is found then investigate - this is not a fully developed script - use at own risk. check the MS docs." -ForegroundColor Red
write-host "###########################################################" -ForegroundColor Red

write-host "IOC Hunting development script made by mRr3b00t. Fight the bad pews, save the world! Hax4Good" -ForegroundColor Red
