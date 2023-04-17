from enum import Enum
from scapy.all import *
import re
from ipaddress import *

from scapy.layers.inet import TCP, IP, UDP
from scapy.layers.inet6 import IPv6


HTTPcommands = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]


def isHTTP(pkt):
    if (TCP in pkt and pkt[TCP].payload):

        data = str(pkt[TCP].payload)
        words = data.split('/')
        if(len(words) >= 1 and words[0].rstrip() == "HTTP"):
            return True

        words = data.split(' ')
        if(len(words) >= 1 and words[0].rstrip() in HTTPcommands):
            return True
        else:
            return False
    else:
        return False

RED = '\033'
ENDC = '\033'
URG = 0x20


def ipString(ip):
    """ ."""

    out = "[IP HEADER]" + "\n"
    out += "\t Version: " + str(ip.version) + "\n"
    out += "\t IHL: " + str(ip.ihl * 4) + " bytes" + "\n"
    out += "\t ToS: " + str(ip.tos) + "\n"
    out += "\t Total Length: " + str(ip.len) + "\n"
    out += "\t Identification: " + str(ip.id) + "\n"
    out += "\t Flags: " + str(ip.flags) + "\n"
    out += "\t Fragment Offset: " + str(ip.frag) + "\n"
    out += "\t TTL: " + str(ip.ttl) + "\n"
    out += "\t Protocol: " + str(ip.proto) + "\n"
    out += "\t Header Checksum: " + str(ip.chksum) + "\n"
    out += "\t Source: " + str(ip.src) + "\n"
    out += "\t Destination: " + str(ip.dst) + "\n"
    if (ip.ihl > 5):
        out += "\t Options: " + str(ip.options) + "\n"
    return out

def matchedIpString(ip, rule):
    """Construct the human-readable string corresponding to the matched IP header, with matched fields in red."""
    ListAllIn = list()
    for opt in rule.options:
        ListAllIn.append(opt.keyword)
    out = "[IP HEADER]" + "\n"
    out += "\t Version: " + str(ip.version) + "\n"
    if ("len" in ListAllIn):
        out += RED + "\t IHL: " + str(ip.ihl * 4) + " bytes " + ENDC + "\n"
    else:
        out += "\t IHL: " + str(ip.ihl * 4) + " bytes" + "\n"
    if ("tos" in ListAllIn):
        out += RED + "\t ToS: " + str(ip.tos) + " " + ENDC + "\n"
    else:
        out += "\t ToS: " + str(ip.tos) + "\n"

    out += "\t Total Length: " + str(ip.len) + "\n"
    out += "\t Identification: " + str(ip.id) + "\n"
    out += "\t Flags: " + str(ip.flags) + "\n"


    if ("offset" in ListAllIn):
        out += RED + "\t Fragment Offset: " + str(ip.frag) + " " + ENDC + "\n"
    else:
        out += "\t Fragment Offset: " + str(ip.frag) + "\n"

    out += "\t TTL: " + str(ip.ttl) + "\n"
    out += "\t Protocol: " + str(ip.proto) + "\n"
    out += "\t Header Checksum: " + str(ip.chksum) + "\n"

    # If the IP was specified uniquely, out += red
    if(rule.src.ipn == "exter"):
        if(ip_network(u'0.0.0.0/0').num_addresses == 1):
            out += RED + "\t Source: " + str(ip.src) + " " + ENDC + "\n"
    elif (rule.src.ipn.num_addresses == 1):
        out += RED + "\t Source: " + str(ip.src) + " " + ENDC + "\n"
    else:
        out += "\t Source: " + str(ip.src) + "\n"

    if (rule.dst.ipn == "exter"):
        if (ip_network(u'0.0.0.0/0').num_addresses == 1):
            out += RED + "\t Destination: " + str(ip.dst) + " " + ENDC + "\n"
    elif (rule.dst.ipn.num_addresses == 1):
        out += RED + "\t Destination: " + str(ip.dst) + " " + ENDC + "\n"
    else:
        out += "\t Destination: " + str(ip.dst) + "\n"

    if (ip.ihl > 5):
        out += "\t Options : " + str(ip.options) + "\n"
    return out

def tcpString(tcp):
        """Construct the human-readable string corresponding to the TCP header."""

        out = "[TCP Header]" + "\n"
        out += "\t Source Port: " + str(tcp.sport) + "\n"
        out += "\t Destination Port: " + str(tcp.dport) + "\n"
        out += "\t Sequence Number: " + str(tcp.seq) + "\n"
        out += "\t Acknowledgment Number: " + str(tcp.ack) + "\n"
        out += "\t Data Offset: " + str(tcp.dataofs) + "\n"
        out += "\t Reserved: " + str(tcp.reserved) + "\n"
        out += "\t Flags: " + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
        out += "\t Window Size: " + str(tcp.window) + "\n"
        out += "\t Checksum: " + str(tcp.chksum) + "\n"
        if (tcp.flags & URG):
            out += "\t Urgent Pointer: " + str(tcp.window) + "\n"
        if (tcp.dataofs > 5):
            out += "\t Options: " + str(tcp.options) + "\n"
        return out

def matchedTcpString(tcp, rule):
    """Construct the human-readable string corresponding to the matched TCP header, with matched fields in red."""
    ListAllIn = list()
    for opt in rule.options:
        ListAllIn.append(opt.keyword)
    out = "[TCP Header]" + "\n"
    if (hasattr(rule.src_port, "listPorts") and len(rule.src_port.listPorts) == 1):
        out += RED + "\t Source Port: " + str(tcp.sport) + " " + ENDC + "\n"
    else:
        out += "\t Source Port: " + str(tcp.sport) + "\n"
    if (hasattr(rule.dst_port, "listPorts") and len(rule.dst_port.listPorts) == 1):
        out += RED + "\t Destination Port: " + str(tcp.dport) + " " + ENDC + "\n"
    else:
        out += "\t Destination Port: " + str(tcp.dport) + "\n"
    if ("seq" in ListAllIn):
        out += RED + "\t Sequence Number: " + str(tcp.seq) + " " + ENDC + "\n"
    else:
        out += "\t Sequence Number: " + str(tcp.seq) + "\n"
    if ("ack" in ListAllIn):
        out += RED + "\t Acknowledgment Number: " + str(tcp.ack) + " " + ENDC + "\n"
    else:
        out += "\t Acknowledgment Number: " + str(tcp.ack) + "\n"
    out += "\t Data Offset: " + str(tcp.dataofs) + "\n"
    out += "\t Reserved: " + str(tcp.reserved) + "\n"
    if ("flags" in ListAllIn):
        out += RED + "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + " " + ENDC + "\n"
    else:
        out += "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + "\n"
    out += "\t Window Size: " + str(tcp.window) + "\n"
    out += "\t Checksum: " + str(tcp.chksum) + "\n"
    if (tcp.flags & URG):
        out += "\t Urgent Pointer: " + str(tcp.window) + "\n"
    if (tcp.dataofs > 5):
        out += "\t Options: " + str(tcp.options) + "\n"
    return out

def udpString(udp):
    """Construct the human-readable string corresponding to the UDP header."""

    out = "[UDP Header]" + "\n"
    out += "\t Source Port: " + str(udp.sport) + "\n"
    out += "\t Destination Port: " + str(udp.dport) + "\n"
    out += "\t Length: " + str(udp.len) + "\n"
    out += "\t Checksum: " + str(udp.chksum) + "\n"
    return out

def matchedUdpString(udp, rule):
    """Construct the human-readable string corresponding to the UDP header, with matched fields in red."""

    out = "[UDP Header]" + "\n"
    if (hasattr(rule.src_port, "listPorts") and len(rule.src_port.listPorts) == 1):
        out += RED + "\t Source Port: " + str(udp.sport) + " " + ENDC + "\n"
    else:
        out += "\t Source Port: " + str(udp.sport) + "\n"
    if (hasattr(rule.dst_port, "listPorts") and len(rule.dst_port.listPorts) == 1):
        out += RED + "\t Destination Port: " + str(udp.dport) + " " + ENDC + "\n"
    else:
        out += "\t Destination Port: " + str(udp.dport) + "\n"
    out += "\t Length: " + str(udp.len) + "\n"
    out += "\t Checksum: " + str(udp.chksum) + "\n"
    return out


def payloadString(pkt):
    """Construct the human-readable string corresponding to the payload."""
    if (pkt.payload):
        data = str(pkt.payload)
        lines = data.splitlines()
        s = ""
        for line in lines:
            s += "\t" + line + "\n"
        out = s
        return out
    else:
        return ""

def matchedTcpPayloadString(tcp, rule):
    """Construct the human-readable string corresponding to the tcp payload, with matched fields in red."""
    ListAllIn = list()
    cont = None
    for opt in rule.options:
        ListAllIn.append(opt.keyword)
        if(opt.keyword == "content"):
            cont = opt.settings #I need the content for later

    out = "[TCP Payload]" + "\n"

    if (hasattr(rule, "http_request")):
        out += RED + "HTTP Request: " + str(rule.http_request) + " " + ENDC + "\n"

    if ("content" in ListAllIn and tcp.payload):
        data = str(tcp.payload)
        # add red color when content found in the string (I don't print it anymore so just adding ESC on the things that trigger the rule)
        data = re.sub(cont, RED + cont + ENDC, data)
        lines = data.splitlines()
        s = ""
        for line in lines:
            s += "\t" + line + "\n"
        out += s
        return out
    else:
        return out + payloadString(tcp)

def matchedUdpPayloadString(udp, rule):
    """Construct the human-readable string corresponding to the udp payload, with matched fields in red."""
    ListAllIn = list()
    cont = None
    for opt in rule.options:
        ListAllIn.append(opt.keyword)
        if (opt.keyword == "content"):
            cont = opt.settings  # I need the content for later

    out = "[UDP Payload]" + "\n"

    if ("content" in ListAllIn and udp.payload):
        data = str(udp.payload)
        # add red color when content found in the string (I don't print it anymore so just adding ESC on the things that trigger the rule)
        data = re.sub(cont, RED + cont + ENDC, data)
        lines = data.splitlines()
        s = ""
        for line in lines:
            s += "\t" + line + "\n"
        out += s
    else:
        return out + payloadString(udp)

def packetString(pkt):
    """Construct the human-readable string corresponding to the packet, from IP header to Application data."""

    out = ""
    if (IP in pkt):
        out += ipString(pkt[IP])
    elif (IPv6 in pkt):
        #need to do
        pass
    if (TCP in pkt):
        out += tcpString(pkt[TCP])
        out += "[TCP Payload]" + "\n"
        out += payloadString(pkt[TCP])
    elif (UDP in pkt):
        out += udpString(pkt[UDP])
        out += "[UDP Payload]" + "\n"
        out += payloadString(pkt[UDP])
    return out

def matchedPacketString(pkt, rule):
    """Construct the human-readable string corresponding to the matched packet, from IP header to Application data, with matched fields in red."""

    out = ""
    if (IP in pkt):
        # IP Header
        out += matchedIpString(pkt[IP], rule)
    elif (IPv6 in pkt):
        # TODO
        pass
    if (TCP in pkt):
        # TCP Header
        out += matchedTcpString(pkt[TCP], rule)
        # Payload
        out += matchedTcpPayloadString(pkt[TCP], rule)

    elif (UDP in pkt):
        out += matchedUdpString(pkt[UDP], rule)
        out += matchedUdpPayloadString(pkt[UDP], rule)
    return out
