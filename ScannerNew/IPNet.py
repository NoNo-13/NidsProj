from ipaddress import *
import socket



class IPNet:
    """An IP network with CIDR block. Represents a set of IPs."""
    def __init__(self, string):
        """Contruct a IPNetwork from a string like 'a.b.c.d/e', 'a.b.c.d' or 'any'."""
        hostname = socket.gethostname()
        self.IPAddr = socket.gethostbyname(hostname)
        try:
            if (string == "any"):
                self.ipn = ip_network(u'0.0.0.0/0')
            elif (str(string) == "$HOME_NET"):
                self.ipn = ip_network(self.IPAddr)
            elif (str(string) == "$EXTERNAL_NET"):
                self.ipn = "exter"
            else:
                strs = string.split("/")
                if (len(strs) >= 2):
                    # CIDR Block
                    bloc = int(strs[1])
                    #bloc = 32 - bloc
                    self.ipn = ip_network(strs[0] + "/" + str(bloc))
                else:
                    self.ipn = ip_network(strs[0] + "/32")
        except:
            raise ValueError("Incorrect input string.")


    def contains(self, ip):
        """Check if input ip is in the IPNetwork, return True iff yes."""
        if (self.ipn == "exter"):
            return (ip not in ip_network(self.IPAddr))
        return (ip in self.ipn)
