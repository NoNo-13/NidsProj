from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


def exploitTest_capture(src, dst, iface, count):
    a = IP(ihl= 5, tos=0, src=src, dst=dst)
    b = TCP(sport=1234,dport=25, flags='A',window=8192, dataofs=8)
    noop = b'\x90'*11
    c = Raw(load=noop)
    print(raw(c))
    pkt = a/b/c
    send(pkt, count=count)

def exploitTest_send(src, dst, iface):
    a = IP(ihl=5, tos=8, src=src, dst=dst)
    b = TCP(sport=1234, dport=25, flags='A', window=8192, dataofs=8)
    noop = b'\x90' * 11
    c = Raw(load=noop)
    print(raw(c))
    pkt = a / b / c
    return pkt







