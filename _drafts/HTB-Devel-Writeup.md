---
layout: post
title:  "Hack The Box - Devel - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Devel-Writeup" %}

# Introduction
The hack the box machine "Devel" is an easy machine which is included in [TJnull's OSCP Preparation List](). Exploiting this machine requires knowledge in the areas of 

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="BlockyCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `sudo nmap -sSCV -p- 10.10.10.5`. The `-sSCV` flag instructs nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that the host has is running a Microsoft IIS web server on port 80 and that FTP is available on port 21. In addition, the `ftp-anon` script reveals that anonymous logins to the FTP service are allowed! This means that it is possible to authenticate with the username `anonymous` and password `anonymous`

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nmap -sSCV -p- 10.10.10.5@@
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-12 08:17 EDT
Stats: 0:00:58 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 22.49% done; ETC: 08:21 (0:03:16 remaining)
Nmap scan report for 10.10.10.5
Host is up (0.066s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
@@@21/tcp open  ftp     Microsoft ftpd@@@
| ftp-syst: 
|_  SYST: Windows_NT
| @@@ftp-anon: Anonymous FTP login allowed@@@ (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png
@@@80/tcp open  http    Microsoft IIS httpd 7.5@@@
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 301.81 seconds
{% endhighlight %}



{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@ftp 10.10.10.5@@
Connected to 10.10.10.5.
220 Microsoft FTP Service
Name (10.10.10.5:kali): @@anonymous@@
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> @@dir@@
229 Entering Extended Passive Mode (|||49158|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
03-17-17  05:37PM                  689 @@@iisstart.htm@@@
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp>
{% endhighlight %}

# Privilege Escalation

{% highlight none linenos %}

{% endhighlight %}

{% highlight none linenos %}

{% endhighlight %}

{% highlight none linenos %}

{% endhighlight %}

{% highlight none linenos %}

{% endhighlight %}