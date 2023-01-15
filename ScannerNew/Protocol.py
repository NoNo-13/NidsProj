from enum import Enum

class Protocol(Enum):
    """A transport protocol or an application protocol concerning an IP packet."""

    TCP = 1
    UDP = 2
    HTTP = 3
    IP = 4
    DNS = 5
    TLS = 6
    ICMP = 7

def protocol(istr):
    """Return Protocol corresponding to the string."""
    str = istr.lower().strip()
    if (str == "tcp"):
        return Protocol.TCP
    elif (str == "udp"):
        return Protocol.UDP
    elif (str == "http"):
        return Protocol.HTTP
    elif (str == "ip"):
        return Protocol.IP
    elif (str == "dns"):
        return Protocol.DNS
    elif(str == "tls"):
        return Protocol.TLS
    elif(str == "icmp"):
        return Protocol.ICMP
    else:
        raise ValueError("Invalid rule : incorrect protocol : '" + istr + "'.")
