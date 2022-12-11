import json
from threading import Thread
from scapy.all import *
import logging


class Sniffer(Thread):
    """Thread responsible for sniffing and detecting suspect packet."""

    def __init__(self, ruleList):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList
        self.cache = list()

        self.IP = socket.gethostbyname(socket.gethostname())  # Host address
        self.port = 8820  # Host port
        self.socket = None  # Socket
        self.HEADER_SIZE = 1024
        self.FORMAT = 'utf-8'
        self.server = (self.IP, self.port)

    def start_Sniffer(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.connect(self.server)
        except socket.error as e:
            str(e)

        print("Sniffer connected")

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def inPacket(self, pkt):
        """Directive for each received packet."""
        for rule in self.ruleList:
            # Check all rules
            # print "checking rule"
            matched = rule.match(pkt)
            if (matched):
                self.cache.append(pkt)
                self.send_update('found', {'packet': pkt})
                #logMessage = rule.getMatchedMessage(pkt)
                #logging.warning(logMessage)

                print(rule.getMatchedPrintMessage(pkt))

    def send_update(self, cmd: str, params: dict):
        self.socket.send(json.dumps({'cmd': cmd, **params}).encode())

    def run(self):
        self.start_Sniffer()
        print("Sniffing started.")
        sniff(prn=self.inPacket, filter="", store=0, stop_filter=self.stopfilter)




