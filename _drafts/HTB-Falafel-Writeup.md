---
layout: post
title:  "Hack The Box - Falafel - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSWE"]
---
{% assign imgDir="HTB-Falafel-Writeup" %}

# Introduction
The hack the box machine "Falafel" is a hard machine which is included in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). Exploiting this machine requires knowledge in the areas of arbitrary file uploads, PHP comparisions

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.85`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

![nmap](/assets/{{ imgDir }}/nmap.png)


![indexPHP](/assets/{{ imgDir }}/indexPHP.png)

![loginPHP](/assets/{{ imgDir }}/loginPHP.png)

cyberlaw.txt

{% highlight none linenos %}
s
{% endhighlight %}

{% highlight none linenos %}
kali@kali:/tmp/x$ @@ffuf -u http://10.10.10.73/FUZZ -ic -e .txt,.php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt@@

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.73/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

login.php               [Status: 200, Size: 7063, Words: 878, Lines: 103]
profile.php             [Status: 302, Size: 9787, Words: 1292, Lines: 259]
uploads                 [Status: 301, Size: 312, Words: 20, Lines: 10]
header.php              [Status: 200, Size: 288, Words: 10, Lines: 18]
.php                    [Status: 403, Size: 290, Words: 22, Lines: 12]
images                  [Status: 301, Size: 311, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 311, Words: 20, Lines: 10]
index.php               [Status: 200, Size: 7203, Words: 774, Lines: 110]
footer.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
@@@upload.php@@@              [Status: @@@302@@@, Size: 0, Words: 1, Lines: 1]
                        [Status: 200, Size: 7203, Words: 774, Lines: 110]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10]
style.php               [Status: 200, Size: 6174, Words: 690, Lines: 69]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
robots.txt              [Status: 200, Size: 30, Words: 3, Lines: 2]
@@@cyberlaw.txt@@@            [Status: @@@200@@@, Size: @@@804@@@, Words: 106, Lines: 18]
connection.php          [Status: 200, Size: 0, Words: 1, Lines: 1]
.php                    [Status: 403, Size: 290, Words: 22, Lines: 12]
                        [Status: 200, Size: 7203, Words: 774, Lines: 110]
server-status           [Status: 403, Size: 299, Words: 22, Lines: 12]
:: Progress: [661641/661641] :: Job [1/1] :: 691 req/sec :: Duration: [0:15:57] :: Errors: 0 ::
{% endhighlight %}

Visiting all the 302 results in login page
style.php - Contains styling for the website. Probably, this file is included in other php files to style every page of the website. header.php and footer.php contains the header of the website and is also included in all php files

Visiting robots.txt provides no interesting information about any hidden directories or files.
We are also not interested in any 200 OK with 0 bytes (connction.php).

403 is forbidden => not interesting

In conclusion, there are two files left that are interesting to us. The first is cyberlaw.txt since it resulted in a 200 ok and contains data. The second is upload.php since the name suggests that it allows users to upload files, meaning that we could potentially use this page to obtain RCE. However, we would first need to have access to a valid account to access this functionality.

Navigating to [10.10.10.73/cyberlaw.txt](10.10.10.73/cyberlaw.txt) results in the page below. THis page contains an email stating that there is a known problem with the authentication of the website and that there is an issue with a file upload feature which might lead to remote code execution on the target. It also tells us that it is user named "chris".

![cyberLawTXT](/assets/{{ imgDir }}/cyberLawTXT.png)

Normally, 


Trying to login with admin and 240610708 results in a successful login! We can strongly suspect that the authentication check looks something like md5(password) == "0e..."

<div style="overflow-x:auto;">
<table class="customTable"><tr><th>Hash Type</th><th>Hash Length</th><th>Input</th><th>Magic Hash</th></tr>
<tr><td>MD2</td><td>32</td><td>505144726</td><td>0e015339760548602306096794382326</td></tr>
<tr><td>MD4</td><td>32</td><td>48291204</td><td>0e266546927425668450445617970135</td></tr>
<tr><td>MD5</td><td>32</td><td>240610708</td><td>0e462097431906509019562988736854</td></tr>
<tr><td>SHA-1</td><td>40</td><td>10932435112</td><td>0e07766915004133176347055865026311692244</td></tr>
</table>
</div>

![adminLogin](/assets/{{ imgDir }}/adminLogin.png)

![loginSuccess](/assets/{{ imgDir }}/loginSuccess.png)


# Privilege Escalation

