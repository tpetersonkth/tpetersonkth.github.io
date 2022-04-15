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
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.85`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

![nmap](/assets/{{ imgDir }}/nmap.png)

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ sudo nmap -sS -sC -sV --min-rate 10000 -p- 10.10.10.239
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

We see a lot of web apps. If we navigate to port 443 in a non-burp browser, we get a self signed cert warning. 

![SelfSigned](/assets/{{ imgDir }}/SelfSigned.png)

If we press "Advanced..." followed by x, we can see more information about the cert. THis leaks the name of the host stage.love.htb and love.htb

![domainName](/assets/{{ imgDir }}/domainName.png)

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ echo '10.10.10.239 love.htb staging.love.htb' | sudo tee -a /etc/hosts
10.10.10.239 love.htb staging.love.htb
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ cat /etc/hosts                                  
127.0.0.1 localhost
127.0.0.1 kali

::1 localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::1 ip6-allrouters
text
10.10.10.239 love.htb staging.love.htb
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}

{% highlight none linenos %}
Placeholder
{% endhighlight %}


# Privilege Escalation

