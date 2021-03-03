#IOC CHECKS
#check this folder for asp files C:\inetpub\wwwroot\aspnet_client\system_web
$count = get-content C:\inetpub\wwwroot\aspnet_client\system_web

Get-EventLog -LogName Application -Source IIS-W3SVC-WP -InstanceId 2303
Get-EventLog -LogName Application -Source IIS-APPHOSTSVC -InstanceId 9009

findstr /snip /c:"Download failed and temporary file" "%PROGRAMFILES%\Microsoft\Exchange Server\V15\Logging\OABGeneratorLog\*.log"
Get-EventLog -LogName Application -Source "MSExchange Unified Messaging" -EntryType Error | Where-Object { $_.Message -like "*System.InvalidCastException*" }
Select-String -Path "$env:PROGRAMFILES\Microsoft\Exchange Server\V15\Logging\ECP\Server\*.log" -Pattern 'Set-.+VirtualDirectory'

dir C:\inetpub\wwwroot\aspnet_client\*.asp* -r
