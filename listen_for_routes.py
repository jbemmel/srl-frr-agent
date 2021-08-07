#! /usr/bin/python3

import queue
import signal
import threading

# Needs yum install python3-pyroute2 -y
from pyroute2 import IPDB
from pyroute2 import NetNS

work_queue = queue.Queue()
ip = IPDB(nl=NetNS('srbase-default'))

class Worker(threading.Thread):
    def run(self):
        while True:
            msg = work_queue.get()
            ifname = msg['attrs'][0][1]
            if msg['event'] == 'RTM_DELLINK':
                print( ifname + ' is gone' )
            else:
                operstatus = msg['attrs'][2][1]
                if operstatus == 'UNKNOWN':
                    print( ifname + ' is back' )

# POSIX signal handler to ensure we shutdown cleanly
def handler(signum, frame):
    print( "\nShutting down IPDB instance..." )
    ip.release()

# Called by the IPDB Netlink listener thread for _every_ message (route, neigh, etc,...)
def callback(ipdb, msg, action):
    if action == 'RTM_NEWLINK' or action == 'RTM_DELLINK':
        work_queue.put(msg)
    else:
        print( f"\nSkipping event:{action} msg={msg}" )
    # Skipping event:RTM_NEWNEIGH (ARP? Can learn MAC from this?)
    # Skipping event:RTM_DELROUTE (when taking down lo0.0 on peer)
    # Skipping event:RTM_NEWROUTE


def main():
    # Register our handler for keyboard interrupt and termination signals
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

    # Worker thread
    worker = Worker()
    worker.daemon = True
    worker.start()

    # Register our callback to the IPDB
    ip.register_callback(callback)

    # The process main thread does nothing but waiting for signals
    signal.pause()

main()
