---
layout: post
title:  "Creating a Multithreaded Port Scanner in Python"
date:   2022-03-05 07:00:00 +0200
#mainTags: ["OSCP","Pentesting Tips & Tricks"]
tags: ["Demo Available","Multithreading","OSCP","Pentesting Tips & Tricks","Port Scanner","Python2","Python3","Socket Programming","Tool"]
---
{% assign assetDir="2022-03-05-Creating-a-Multithreaded-Port-Scanner-in-Python" %}

# Introduction

When performing pentests, red team engagements or hacking around in a lab environment such as the OSCP labs, one issue which might occur is that an attacker might need to leverage a compromised host to compromise another host. For example, if an attacker has compromised a host, this host might have two network interfaces. Atleast one of these interfaces must be reachable by the attacker since the host was compromised. However, the other interface could lead to an isolated subnet which could not normally be reached by the attacker. 

By pivoting through the compromised host, the attacker could attempt to compromise arbitrary hosts in the isolated subnet. However, performing port scans through port forwarding or pivoting techniques can sometimes be a quite slow process. As such, it is common for attackers to leverage tools on the compromised host, such as netcat, to perform port scans directly from the compromised host. Sometimes, however, tools like netcat are not available and the attacker thus has to use other available tools to perform port scans or install his/her own tools on the compromised machine. As the latter alternative could increase the probability of an attacker being discovered, the former might be a better option.

<video style="width: 80%; margin-left: auto;margin-right: auto;display: block; margin-bottom:15px;" controls="controls">
  <source src="/assets/{{ assetDir }}/demo.mp4" type="video/mp4">
</video>

In this post, we study how Python can be used to perform port scans by writing the multithreaded port scanner shown in the video above. Python is a good choice, as opposed to other programming languages, since it is commonly installed by default on many Linux machines. As we don't know if the compromised host uses Python 2 or Python 3, we will write the port scanner to be compatible with both versions. In addition, we don't know what Python packages are installed on the compromised host. As such, we will only use built-in modules. Finally, to keep things simple, we only implement a [connect scan](https://nmap.org/book/scan-methods-connect-scan.html). A connect scan is different from a SYN scan in the sense that it always attempts to fully establish a TCP connection by performing the entire TCP handshake for each port. A SYN scan does not send the final ACK packet in the TCP handshake and might thus be more stealthy. 

<!-- Feel free to skip the next section if you are already familiar with threads. # Background Python works on Windows.-->
<!-- Threading is used in programs to speed up a task by using multiple cores of a CPU. -->
<!-- errno: http://www.ioplex.com/%7Emiallen/errcmpp.html -->
# Writing the Code
We start by importing relevant modules as shown below. The `argparse` module is used for parsing command line arguments. The `socket` and `errno` modules are used for network communication and socket error identification respectively. Finally, the `threading` and `queue` modules are used for multithreading.
{% highlight python linenos %}
import argparse, socket, errno, threading, queue
{% endhighlight %}

Next, we initialize the argument parser as shown in the code block below. The first line provides a brief description of the script and the subsequent line defines a mandatory argument which corresponds to a target to scan. The next two lines define the `-p` and `-t` flags which enable the user to specify a set of ports to scan and the number of threads to use while scanning. Finally, line 5 parses the user provided arguments and places them in a variable named "args".
{% highlight python linenos %}
parser = argparse.ArgumentParser(description='A port scanner capable of basic TCP connect scans.')
parser.add_argument('Target', help='an ip or hostname to scan.')
parser.add_argument('-p', help='a port range specified using the \'-\' character or a comma separated list of ports to scan (Default 1-1024).')
parser.add_argument('-t', type=int, help='number of threads to use (Default 10).')
args = parser.parse_args()
{% endhighlight %}

The next step is to set our scan parameters using the parsed arguments, as performed in the code block below. We start by copying the specified target to a variable named "target" for convinience reasons. Then, at line 3 to 8, we determine the ports to scan. At line 3, we define the default ports to scan to be the first 1024 ports. Then, we check if a port range is provided (For example `1-1024`) at line 4 by checking if a string was provided with the `-p` flag and if this string contains a `-` chracter. If this is the case, we extract the two provided ports using [list comprehension](https://docs.python.org/3/tutorial/datastructures.html#list-comprehensions) at line 5. Then, we create a list of all ports between the two extracted ports using the built in `range` function and assign the list to the `ports` variable.
{% highlight python linenos %}
target = args.Target

ports = range(1,1024)
if args.p != None and "-" in args.p:
    [minPort,maxPort] = [int(i) for i in args.p.split("-")]
    ports = range(minPort,maxPort+1)
elif args.p != None:
    ports = [int(i) for i in args.p.split(",")]

threads = 10
if args.t != None:
    threads = args.t
{% endhighlight %}
If the value of the `-p` flag doesn't contain a `-` character and has been set to something, we assume that it contains a comma separated list of ports to scan and execute the command at line 8. This command uses list comprehension to create a list of the specified ports and assigns the list to the `ports` variable. The last variable to set is the `threads` variable which corresponds to the number of threads that will be used to scan the target. This variable is assigned a default value of `10` at line 10. If a value is provided for the `-t` flag, the if statement at line 11 evaluates to `True` and we assign the provided value to the `threads` variable at line 12.

The next step is to define three global variables as shown below. The first is the variable `results` which is a dictionary where each thread will store the results of the ports it has scanned. As [this data structure is not thread-safe](https://github.com/google/styleguide/blob/91d6e367e384b0d8aaaf7ce95029514fcdf38651/pyguide.md#218-threading), we create the variable `lock` which is a [mutex](https://en.wikipedia.org/wiki/Lock_(computer_science)). This mutex will be used to only allow the threads to write to the `results` variable one at a time. Finally, the last variable is `q` which will contain a queue of tuples where each tuple contains an IP address and a port to scan. This data structure is thread-safe and thus we won't need to use a mutex when interacting with it.
{% highlight python linenos %}
results = {}
lock = threading.Lock()
q = queue.Queue()
{% endhighlight %}

Next, we create a function named "connect", shown below, which simply tries to connect to a specific ip and port. It then returns the result of this attempted connection which is either that the port is "Open" if the connection was successful, "Closed" if the connection was refused and "Filtered" if no response was obtained. The body of the function contains one `try` block and two `except` blocks. If the port is open, the code in the `try` block won't cause an exception and the `status` variable will be set to "Open".
<!-- Side note: we need to use e.errno to be compatible with both python2 and python3. Note that the timeout is set to 5 seconds. By default, there is no timeout according to the [official documentation](https://docs.python.org/3/library/socket.html#socket.setdefaulttimeout). -->

{% highlight python linenos %}
def connect(ip, port):
    status = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        connection = s.connect((ip, port))
        status = "Open"
        s.close()

    except socket.timeout:
        status = "Filtered"

    except socket.error as e:
        if e.errno == errno.ECONNREFUSED:
            status = "Closed"
        else:
            raise e

    return status
{% endhighlight %}

At line 5, a timeout for the connection attempt is set to 5 seconds. If no response is obtained within 5 seconds, a `socket.timeout` exception is raised, the first `except` block is entered and the status of the port is set to "Filtered". For other socket errors, the second except block is entered. In this block, we check if the error number `errno` of the exception `e` indicates that the connection was refused. If this is the case, we set the status of the port to "Closed". Otherwise, we raise the error at line 17, meaning that other socket errors won't be suppressed. 

Once we have created the `connect` function, we proceed by defining a function named "worker", displayed below, which contain the code that each thread will execute to scan for open ports. The `worker` function contains a while loop which iterates until the queue `q` is empty. At line 3 and 4, an ip and port pair is retrieved from the queue and the `connect` function is used to get the status of the port on the specified host. Then, from line 5 to 7, we acquire the mutex `lock`, write the status of the port to the `results` dictionary and release the mutex. Finally, at line 8, we mark the task to scan this specific ip and port as done. We need to be careful here since the `task_done` function must not be called before writing to the `results` dictionary . Otherwise, a race condition would exist where all tasks could be marked as done even if the status resulting from some tasks hadn't been stored in the `results` object yet. This could in turn cause us to have incomplete results to present.

{% highlight python linenos %}
def worker():
    while not q.empty():
        (ip,port) = q.get()
        status = connect(ip,port)
        lock.acquire()
        results[port] = status
        lock.release()
        q.task_done()
{% endhighlight %}

Then, we fill the queue `q` with all of the ports we should scan as shown at line 1 and 2 below. Thereafter, at line 4 to 6, we start the threads and instruct them to execute the `worker` function. We let the user know that the scan has been started at line 8 and then we wait for the scan to finish using the `q.join` function. This function pauses the execution until the worker threads have called the `q.task_done` for each task in the queue.
{% highlight python linenos %}
for port in ports:
    q.put((target,port))

for i in range(threads):
    t = threading.Thread(target=worker)
    t.start()

print("Started a scan of " + target + "\n" + "-"*10)
q.join()
{% endhighlight %}

{% highlight python linenos %}
for port in ports:
    print("Port " + str(port) + " is " + results[port])
{% endhighlight %}
The final step is to present the results to the user. This is done by iterating over all the ports which had to be scanned and printing the scan result for each port using the `results` dictionary, as can be seen in the code block above.

# Final Code
Putting everything together, we get the code below which can be downloaded [here](/assets/{{ assetDir }}/scan.py).
{% highlight python linenos %}
import argparse, socket, errno, threading, queue

#Initialize the parser
parser = argparse.ArgumentParser(description='A port scanner capable of basic TCP connect scans.')
parser.add_argument('Target', help='an ip or hostname to scan.')
parser.add_argument('-p', help='a port range specified using the \'-\' character or a comma separated list of ports to scan (Default 1-1024).')
parser.add_argument('-t', type=int, help='number of threads to use (Default 10).')
args = parser.parse_args()

#Retrieve parameter values from the parser arguments
target = args.Target

ports = range(1,1024)
if args.p != None and "-" in args.p:
    [minPort,maxPort] = [int(i) for i in args.p.split("-")]
    ports = range(minPort,maxPort+1)
elif args.p != None:
    ports = [int(i) for i in args.p.split(",")]

threads = 10
if args.t != None:
    threads = args.t

# Define global variables
results = {}
lock = threading.Lock()
q = queue.Queue()

#connect(ip, port) - Connects to an ip address on a specified port to check if it is open
#Params:
#   ip - The ip to connect to
#   port - The port to connect to on the specified ip
#
#Returns: 'Open', 'Closed' or 'Filtered' depending on the result of connecting to the specified ip and port
def connect(ip, port):
    status = ""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        connection = s.connect((ip, port))
        status = "Open"
        s.close()

    except socket.timeout:
        status = "Filtered"

    except socket.error as e:
        if e.errno == errno.ECONNREFUSED:
            status = "Closed"
        else:
            raise e

    return status

#worker() - A function for worker threads to scan IPs and ports
def worker():
    while not q.empty():
        (ip,port) = q.get()
        status = connect(ip,port)
        lock.acquire()
        results[port] = status
        lock.release()
        q.task_done()

#Prepare queue
for port in ports:
    q.put((target,port))

#Start threads
for i in range(threads):
    t = threading.Thread(target=worker)
    t.start()

print("Started a scan of " + target + "\n" + "-"*10)
q.join()

#Present the scan results
for port in ports:
    print("Port " + str(port) + " is " + results[port])
{% endhighlight %}

