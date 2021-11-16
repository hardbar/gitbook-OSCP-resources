---
description: 10.10.10.6
---

# Popcorn

![](<../../.gitbook/assets/1 (5).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User -
* Root -

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

### Gobuster (No recurive option)

Let's run a gobuster scan against the target.

```
// Some code
```

### Dirb

Let's run a dirb scan against the target.

```
// Some code
```

### Wfuzz

​ Let's run a wfuzz scan against the target.

`code` ​

## Website exploration

​

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

*
*

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

*
*

​

## Gaining Access

​ ​ ​

## Privilege Escalation

​ ​ ​ ​ ​ ​

## Resources

​ ​ ​
