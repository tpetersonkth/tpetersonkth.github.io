---
layout: post
title:  "Hack The Box - Json - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSWE"]
---
{% assign imgDir="HTB-Json-Writeup" %}

# Introduction
The hack the box machine "Json" is a Medium machine which is included in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). Exploiting this machine requires knowledge in the areas of deserializtion

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="BlockyCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.85`. The `-sS` `-sC` and `-sV` flags instructs nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

![nmap](/assets/{{ imgDir }}/nmap.png)


{% highlight none linenos %}
Placeholder
{% endhighlight %}

# Privilege Escalation

