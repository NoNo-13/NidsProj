from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP


def exploitTest(src, dst, iface, count):
    Version: 4
    IHL: 20
    bytes
    ToS: 0
    Total
    Length: 1500
    Identification: 54532
    Flags: DF
    Fragment
    Offset: 0
    TTL: 58
    Protocol: 6
    Header
    Checksum: 47322

    src_ip = '192.168.1.100'
    dst_ip = '192.168.1.1'
    version = 4
    ihl = 5
    tos = 0
    tot_len = 20 + 20  # IP header length + TCP header length
    id = 54321
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 0
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dst_ip)


    a = IP(ihl= 5, tos=0, src=src, dst=dst)
    b = TCP(sport=1234,dport=25, flags='A',window=8192, dataofs=8)
    noop = b'\x90'*11
    c = Raw(load=noop)
    print(raw(c))
    pkt = a/b/c
    send(pkt, count=count)

def main():
    hostname = socket.gethostname()
    IPAddr = socket.gethostbyname(hostname)
    src = '1.2.3.4'
    dst = IPAddr
    iface = "ens33"
    count = 1000
    exploitTest(src, dst, iface, count)

if __name__ == '__main__':
    main()