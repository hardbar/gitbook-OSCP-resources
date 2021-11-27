---
description: 10.10.10.75
---

# Nibbles

![](<../../.gitbook/assets/1 (3).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User -
* Root -

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.75
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-25 10:38 EST
Nmap scan report for 10.10.10.75
Host is up (0.062s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 22.40 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sC -sV -p 22,80 10.10.10.75 -n
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-25 10:40 EST
Nmap scan report for 10.10.10.75
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.68 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.75/
http://10.10.10.75/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75]                                                                                               

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.75/ -C all
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.75
+ Target Hostname:    10.10.10.75
+ Target Port:        80
+ Start Time:         2021-11-25 10:40:31 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 5d, size: 5616c3cf7fa77, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26470 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-11-25 10:49:46 (GMT-5) (555 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.75/ -q -f -t 100 -x php,sh,bak,txt
/icons/ (Status: 403)
/server-status/ (Status: 403)

```

The initial gobuster did not find anything, however, when we visited the site we found a hidden directory mentioned in the comments on the page source of the home page. Let's rerun gobuster on the /nibbleblog/ route:

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.75/nibbleblog/ -q -f -t 100 -x php,sh,bak,txt
/themes/ (Status: 200)
/feed.php (Status: 200)
/admin/ (Status: 200)
/admin.php (Status: 200)
/content/ (Status: 200)
/plugins/ (Status: 200)
/install.php (Status: 200)
/update.php (Status: 200)
/sitemap.php (Status: 200)
/languages/ (Status: 200)
/index.php (Status: 200)
/LICENSE.txt (Status: 200)
/COPYRIGHT.txt (Status: 200)
                             
```



## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* The page source for [http://10.10.10.75/](http://10.10.10.75) reveals another route; /nibbleblog/
* Nothing found in page source at the [http://10.10.10.75/nibbleblog/](http://10.10.10.75/nibbleblog/) page

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Scripts at the nibbleblog site appear to be standard, therefore they do not reveal any hidden information to us

#### Browsing

The page at [http://10.10.10.75/](http://10.10.10.75) does not have much, however, if we view the page source, we see a comment:

![](<../../.gitbook/assets/2 (4).JPG>)

![](<../../.gitbook/assets/3 (5).JPG>)

![](<../../.gitbook/assets/4 (5).JPG>)

At this stage we rerun gobuster (see output in the gobuster section above) and find some interesting files, including "admin.php".

![](<../../.gitbook/assets/5 (1).JPG>)

After trying the basic default creds such as "admin:admin" and a few others without success, we decide to try brute force the login with hydra.











## Gaining Access







## Privilege Escalation





## Resources

