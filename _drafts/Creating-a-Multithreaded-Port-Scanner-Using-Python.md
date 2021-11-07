---
layout: post
title:  "Creating a Multithreaded Port Scanner Using Python"
date:   2000-01-01 07:00:00 +0200
tags: ["OSCP","Pentesting Tips & Tricks"]
---

# Introduction

This code will work for both python 2 and python 3. We don't know which one of these that the compromised host has.

This code performs a TCP connect scan
Only uses built in modules

Good for when we reach a host and want to scan from that host deeper into the network.

<!-- Feel free to skip the next section if you are already familiar with threads. # Background-->

Threading is used in programs to speed up a task by using multiple cores of a CPU. 

Threading is good to know for pentesters as it helps speed up things

[video]

# Writing the Code

errno: http://www.ioplex.com/%7Emiallen/errcmpp.html

Note 5 second timeout

We start by importing relevant modules. The `argparse` modules is used for parsing command line arguments. The `socket` and `errno` are used for network communication. Finally, the threading and queue modules are used for multithreading.
{% highlight python linenos %}
import argparse, socket, errno, threading, queue
{% endhighlight %}

Next, we initialize the parser. The first line provides a generic description of the script and the subsequent line defines a mandatory argument which corresponds to a target to scan. The next two lines defines the -p and -t flags which enables the specification of a set of ports to scan and the number of threads to use. Finally, line 5 parses the user provided arguments and places them in a variable named "args".
TODO: Check if we can scan hostname..
{% highlight python linenos %}
parser = argparse.ArgumentParser(description='A port scanner capable of basic TCP connect scans.')
parser.add_argument('Target', help='an ip or hostname to scan.')
parser.add_argument('-p', help='a port range specified using the \'-\' character or a comma separated list of ports to scan (Default 1-1024).')
parser.add_argument('-t', type=int, help='number of threads to use (Default 10).')
args = parser.parse_args()
{% endhighlight %}

The next step is to validate the parameters. We start by copying the specified target to a variable named "target" for convinience reasons. Then, at line x to x, we determine the ports to scan. We check if a port range is provided (For example `1-1024`) at line x by checking if the parameter value contains a `-` chracter. If this is the case,  we extract the two ports provided using list comprehension(link) at line x. Then, we assign create a list(TODO) of all ports between the two extracted ports using the built in `range` function and assign it to the `ports` variable. If the value of the `-p` flag doesn't contain a `-` character and has been set to something else, we assume that it contains a comma separated list of ports to scan and execute the command at line x. This command uses list comprehension to create a list of the specified ports and assigns the list to the `ports` variable. The last variable to set is the `threads` variable which corresponds to the number of threads that will be used to scan the target. This variable is assigned a default variable of `10` at line x. If a value is provided for the `-t` flag, the if statement at line x becocmes `True` and we assign the provided value to the `threads` variable at line x.
{% highlight python linenos %}
target = args.Target

ports = range(1,1024)
if "-" in args.p:
    [minPort,maxPort] = [int(i) for i in args.p.split("-")]
    ports = range(minPort,maxPort+1)
elif args.p != None:
    ports = [int(i) for i in args.p.split(",")]

threads = 10
if args.t != None:
    threads = args.t
{% endhighlight %}

Then, we define three global variables. The first is the variable `results` which is a dictionary where each thread will store the results of the ports it has scanned. As this datastructure is not thread-safe, we create the variable `lock` which is a mutex. This mutex will be used to only allow the threads to write to the `results` variable one at a time. Finally, the last variable is `q` which will contain a queue of tuples containing an IP address and a port. This datastructure is thread-safe and thus we won't need to use a mutex when interacting with it.
{% highlight python linenos %}
results = {}
lock = threading.Lock()
q = queue.Queue()
{% endhighlight %}

Next, we create a function named "connect" which simply tries to connect to a specified ip and port. It then returns the result of this attempted connection which is either that the port is "Open" if the connection was successful, "Closed" if the connection was refused and "Filtered" if no response was obtained.

Note that the timeout is set to 5 seconds. It defaults to 120 seconds(source)

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

Next, we define a function named "worker" which contain the code which each thread will execute to scan for open ports. This function contains a while loop which iterates until the queue `q` is empty. 
..
{% highlight python linenos %}
def worker():
    while not q.empty():
        [ip,port] = q.get()
        status = connect(ip,port)
        q.task_done()

        lock.acquire()
        results[port] = status
        lock.release()
{% endhighlight %}

Next we fill the queue `q` with all of the ports we should scan at line x to x. Then, at line x to x, we start the threads at and instruct them to execute the `worker` function. Then, we let the user know that the scan has been started at line x and then we wait for the scan to finish using the `q.join` function.
{% highlight python linenos %}
for port in ports:
    q.put([target,port])

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
The final step is to present the results to the user. This is done by iterating over all the ports which had to be scanned and printing there results using the results dictionary.

# Final Code
Putting everything together, we get the code below which can be downloaded here(link).
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
if "-" in args.p:
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
        [ip,port] = q.get()
        status = connect(ip,port)
        q.task_done()

        lock.acquire()
        results[port] = status
        lock.release()

#Prepare queue
for port in ports:
    q.put([target,port])

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

