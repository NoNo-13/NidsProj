import json

import logging
import threading
from ipaddress import ip_network
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP
from parsuricata import parse_rules

from Ports import *

import re

my_string = "method|22 3a 22|eth_accounts|23 45|foo|10 0a|bar"

# Define a regex pattern to match "|hexadecimal string|"
pattern = re.compile(r'\|[0-9a-fA-F ]+\|')

# Find all matches of the pattern in the string
matches = re.findall(pattern, my_string)

# Replace each match with the equivalent byte representation
for match in matches:
    hex_string = match.strip('|')
    hex_bytes = bytes.fromhex(hex_string)
    byte_string = ''.join('\\x{:02x}'.format(x) for x in hex_bytes)
    my_string = my_string.replace(match, byte_string)

print(my_string)

