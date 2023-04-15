import json
from threading import Thread
import logging
from ipaddress import *
from smtplib import SMTP
from scapy.all import *
from Utils import *
from IPNet import *
from Ports import *


class Sniffer(Thread):
    """Thread responsible for sniffing and detecting suspect packet."""

    def __init__(self, ruleList=None):
        Thread.__init__(self)
        self.stopped = False
        self.ruleList = ruleList
        self.cache = list()

    def set_ruleList(self, ruleList):
        self.ruleList = ruleList

    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped

    def inPacket(self, pkt):
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        src = '1.2.3.4'
        dst = IPAddr
        a = IP(ihl=5, tos=0, src=src, dst=dst)
        b = TCP(sport=1234, dport=25, flags='A', window=8192, dataofs=8)
        noop = b'\x90' * 11
        c = Raw(load=noop)
        pkt = a / b / c
        print(pkt.summary())
        """Directive for each received packet."""
        for rule in self.ruleList:
            # Check all rules
            # print "checking rule"
            matched = self.match(pkt, rule)
            if (matched):
                packetStr = self.getMatchedPrintMessage(pkt, rule) #readable string of the packet
                if (IP in pkt):
                    self.cache.append([str(rule.options[0].settings), str(pkt[IP].src),str(pkt)]) #msg, packet
                else:
                    self.cache.append([str(rule.options[0].settings), "0",str(pkt)]) #msg, packet
                logMessage = self.getMatchedMessage(pkt, rule)
                logging.warning(logMessage)
                with open("log.txt", "a") as f:
                    # Write the message to the file
                    f.write(packetStr)
                print("\nWrite your command: \n")
                return

    def run(self):
        print("Sniffing started.")
        sniff(prn=self.inPacket, filter="",stop_filter=self.stopfilter) #store=0 increasw buffer size to capture more at once

    def match(self, pkt, rule):
        """
        Returns True if and only if the rule is matched by given packet,
        i.e. if every part of the rule is met by the packet.
        """
        # check protocol
        if (not self.checkProtocol(pkt, rule)):
            return False

        # check IP source and destination
        if (not self.checkIps(pkt, rule)):
            return False

        # check source Port
        if (not self.checkPorts(pkt, rule)):
            return False

        # check options
        if (not self.checkOptions(pkt, rule)):
            return False

        # otherwise the rule is met
        return True

    def checkProtocol(self, pkt, rule):
        """ Returns True if and only if the rule concerns packet's protocol """
        f = False
        if (rule.protocol.upper() == "HTTP" and TCP in pkt):
            if (isHTTP(pkt)):
                f = True
        elif (rule.protocol.upper() == "DNS" and TCP in pkt):
            if(pkt[TCP].dport == 53):
                f = True
        elif (rule.protocol.upper() == "FTP" and TCP in pkt):
            if(pkt[TCP].dport == 21):
                f = True
        elif (rule.protocol == "ftp-data" and TCP in pkt):
            if(pkt[TCP].dport == 20):
                f = True
        elif (rule.protocol.upper() == "SMB" and TCP in pkt):
            if (pkt[TCP].dport == 445 or pkt[TCP].dport == 139):
                f = True
        elif (rule.protocol.upper() == "SMTP" and TCP in pkt):
            if (pkt[TCP].dport == 25):
                f = True
        elif (rule.protocol.upper() in pkt):
            f = True
        return f

    def checkIps(self, pkt, rule):
        """Returns True if and only if the rule's IPs concern the pkt IPs"""
        f = False
        if (IP not in pkt):
            f = False
        else:
            srcIp = pkt[IP].src
            dstIp = pkt[IP].dst
            ipSrc = ip_address(srcIp)
            ipDst = ip_address(dstIp)
            if (rule.src.contains(ipSrc) and rule.dst.contains(ipDst)):
                # ipSrc and ipDst match rule's source and destination ips
                f = True
            else:
                f = False
        return f


    def checkPorts(self, pkt, rule):
        """Returns True if and only if the rule's Ports concern packet's Ports"""
        f = False
        if (UDP in pkt):
            srcPort = pkt[UDP].sport
            dstPort = pkt[UDP].dport
            if (rule.src_port.contains(srcPort) and rule.dst_port.contains(dstPort)):
                f = True
        elif (TCP in pkt):
            srcPort = pkt[TCP].sport
            dstPort = pkt[TCP].dport
            if (rule.src_port.contains(srcPort) and rule.dst_port.contains(dstPort)):
                f = True
        return f

    def checkOptions(self, pkt, rule):
        """ Return True if and only if all options are matched """

        """hasattr- returns true if an object has the given named attribute and false if it does not."""
        for op in rule.options:
            if (op.keyword == "tos"):
                if (IP in pkt):
                    if (op.settings != int(pkt[IP].tos)):
                        return False
                else:
                    return False

            if (op.keyword == "len"):
                if (IP in pkt):
                    if (op.settings != int(pkt[IP].ihl)):
                        return False
                else:
                    return False

            if (op.keyword == "offset"):
                if (IP in pkt):
                    if (op.settings != int(pkt[IP].frag)):
                        return False
                else:
                    return False

            if (op.keyword == "seq"):
                if (TCP not in pkt):
                    return False
                else:
                    if (op.settings != int(pkt[TCP].seq)):
                        return False

            if (op.keyword == "ack"):
                if (TCP not in pkt):
                    return False
                else:
                    if (op.settings != int(pkt[TCP].ack)):
                        return False

            if (op.keyword == "flags"):
                # match if and only if the received packet has all the rule flags set
                if (TCP not in pkt):
                    return False
                else:
                    for c in op.settings:
                        pktFlags = pkt[TCP].underlayer.sprintf("%TCP.flags%")
                        if (c not in pktFlags):
                            return False

            if (op.keyword == "http_request"):
                if (not isHTTP(pkt)):
                    return False
                elif (TCP in pkt and pkt[TCP].payload):
                    data = str(pkt[TCP].payload)
                    words = data.split(' ')
                    if ((len(words) < 1) or (words[0].rstrip() != op.settings)):
                        return False
                else:
                    return False

            if (op.keyword == "content"):
                payload = None
                byte_sequence = op.settings
                if("|" in op.settings):
                    # Define a regex pattern to match "|hexadecimal string|"
                    pattern = re.compile(r'\|[0-9a-fA-F ]+\|')

                    # Find all matches of the pattern in the string
                    matches = re.findall(pattern,  byte_sequence)

                    # Replace each match with the equivalent byte representation
                    for match in matches:
                        hex_string = match.strip('|')
                        hex_bytes = bytes.fromhex(hex_string)
                        byte_string = ''.join('\\x{:02x}'.format(x) for x in hex_bytes)
                        byte_sequence = byte_sequence.replace(match, byte_string)

                if (TCP in pkt):
                    payload = pkt[TCP].payload
                elif (UDP in pkt):
                    payload = pkt[UDP].payload
                if (payload):
                    if (str(byte_sequence) not in str(payload)):
                        return False
                else:
                    return False
        return True

    def getMatchedMessage(self, pkt, rule):
        """Return the message to be logged when the packet triggered the rule."""
        msg = ""
        if (rule.action == "alert"):
            msg += " ALERT "
        msg += "Rule matched name: "
        msg += rule.options[0].settings + "\n"
        msg += "By packet :\n" + packetString(pkt) + "\n"

        return msg

    def getMatchedPrintMessage(self, pkt, rule):
        """Return the message to be printed in the console when the packet triggered the rule."""
        msg = "Rule matched name: "
        msg += rule.options[0].settings + "\n"

        msg += "By packet :\n" + matchedPacketString(pkt, rule) + "\n"

        return msg


