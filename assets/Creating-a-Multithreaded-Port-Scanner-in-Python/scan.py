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
lock = threading.Lock()
q = queue.Queue()
results = {}

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

