---
layout: post
title:  "Hack The Box - Ready - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Ready-Writeup" %}

# Introduction
The hack the box machine "Ready" is a Medium machine which is included in [TJnull's OSCP Preparation List](). Exploiting this machine requires knowledge in the areas of arbitrary file uploads, PHP comparisions

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

![nmap](/assets/{{ imgDir }}/nmap.png)


{% highlight none linenos %}
Placeholder
{% endhighlight %}

# Privilege Escalation

