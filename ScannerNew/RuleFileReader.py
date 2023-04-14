"""Functions for reading a file of rules."""
from IPNet import *
from Ports import *
from parsuricata import parse_rules

def read(filename):
    """Read the input file for rules and return the list of rules and the number of line errors."""

    text_file = open (filename, 'r')
    rules = parse_rules(text_file.read())
    for rule in rules:
        PrepareRule(rule)

    text_file.close()
    return rules

def PrepareRule(rule):
    """
        There are several options that the IP and Port will look like in each rule
        exp- any, [x, y, z] etc
    """
    rule.src = IPNet(rule.src)
    rule.src_port = Ports(rule.src_port)
    rule.dst = IPNet(rule.dst)
    rule.dst_port = Ports(rule.dst_port)

