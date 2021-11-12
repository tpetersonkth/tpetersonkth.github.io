---
layout: post
title:  "Hack The Box - Popcorn - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSWE"]
---
{% assign imgDir="HTB-Popcorn-Writeup" %}

# Introduction
The hack the box machine "Popcorn" is a medium machine which is included in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). Exploiting this machine requires knowledge in the areas of 

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="BlockyCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.85`. The `-sS` `-sC` and `-sV` flags instructs nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that port 22 and 80 are open. These ports correspond to SSH and HTTP respectively. 

![nmap](/assets/{{ imgDir }}/nmap.png)

As SSH is normally a dead end, we start by investigating port 80. if we visit [http://10.10.10.6](http://10.10.10.6) in a browser, we are greeted with the index page below.

![index](/assets/{{ imgDir }}/index.png)

As this index page doesn't provide us with much interesting information, we proceed by performing directory bruteforcing. This can be performed using `ffuf` as shown below. The `-u` and `-w` flag specify a URL to brute force and a wordlist respectively. Note that the `FUZZ` keyword in the URL specifies what part of the URL we want to fuzz and that the `-ic` flag is used to ignore comments in the wordlist.

{% highlight none linenos %}
┌──(kali㉿kali)-[~]
└─$ ffuf -u http://10.10.10.6/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic
[...]
                        [Status: 200, Size: 177, Words: 22, Lines: 5]
index                   [Status: 200, Size: 177, Words: 22, Lines: 5]
test                    [Status: 200, Size: 47065, Words: 2465, Lines: 651]
torrent                 [Status: 301, Size: 310, Words: 20, Lines: 10]
rename                  [Status: 301, Size: 309, Words: 20, Lines: 10]
                        [Status: 200, Size: 177, Words: 22, Lines: 5]
:: Progress: [220547/220547] :: Job [1/1] :: 1025 req/sec :: Duration: [0:03:35] :: Errors: 1 ::
{% endhighlight %}

By visiting the `/test` page, we discover that it is a phpinfo page. This page contains infromation about PHP and how PHP is configured. The next page `/torrent`, leads us to the a torrenting page shown in the first image below. The final page is `/rename` which results in an api for renaming files, shown in the second image below. Since we know that the web application uses php and that we can rename potentially arbitrary files on the system, we should be able to get remote code execution on the host if we can just find a way to upload arbitrary php code.

![torrent](/assets/{{ imgDir }}/torrent.png)
![rename](/assets/{{ imgDir }}/rename.png)

The torrent page appears to be used for sharing `.torrent` files. This type of files are used for peer-to-peer(file sharing) file sharing and are bencoded(link). If we try to click the upload button on the torrent page, we discover that we need to login before we can upload any torrents. We can however, click the browse button and see a file which was uploaded by the `Admin` user. We can, however, not edit this file. By 

![torrentBrowse](/assets/{{ imgDir }}/torrentBrowse.png)
![torrentBrowse2](/assets/{{ imgDir }}/torrentBrowse2.png)

Something interesting on the torrent page is the `Sign up` button. If we click this button, we reach a registration form. Submitting it with the values shown below (all `x` except for the code) leads to a new account named "x" being created and us automatically being logged in.

![signUp](/assets/{{ imgDir }}/signUp.png)
![signUp2](/assets/{{ imgDir }}/signUp2.png)

![Upload](/assets/{{ imgDir }}/upload.png)

I tried uploading a php reverse shell payload but couldn't evade the filter. However, we can upload a real torrent file . I used a [random torrent](https://kali.download/base-images/kali-2021.3/kali-linux-2021.3a-installer-amd64.iso.torrent) from the [Kali Linux web site](https://www.kali.org/get-kali/).



The next step is to perform a privilege escalation from `www-data` to `root`. There are two ways to do this. The first way is to abuse a known vulnerability in Linux PAM and the second is through kernel exploitation. The next
# Privilege Escalation - PAM

We set up ssh for www-data

https://www.exploit-db.com/exploits/14273

# Privilege Escalation - Kernel Exploitation

# Bonus - Initial Shell (Hard way)