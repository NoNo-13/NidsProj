from scapy.all import *
from sys import argv
import logging
import datetime

import RuleFileReader
from Sniffer import *

RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

class Scanner(Sniffer):
    def __init__(self):
        super(Scanner, self).__init__()
        self.ruleList = list()
    def main_Scanner(self, filename):
        """Read the rule file and start listening."""

        now = datetime.now()
        logging.basicConfig(filename="NidsProj " + str(now) + '.log', level=logging.INFO)

        print("NIDS started.")
        # Read the rule file
        print("Reading rule file...")

        self.ruleList, errorCount = RuleFileReader.read(filename)
        print("Finished reading rule file.")

        if (errorCount == 0):
            print("All (" + str(len(self.ruleList)) + ") rules have been correctly read.")
        else:
            print(str(len(self.ruleList)) + " rules have been correctly read.")
            print(str(errorCount) + " rules have errors and could not be read.")

        # Begin sniffing
        sniffer = Sniffer()
        sniffer.set_ruleList(self.ruleList)
        sniffer.run()

        # sniffer.stop()
        # print "Simple-NIDS stopped."


if __name__ == '__main__':
    scanner = Scanner()
    filename = "RulesToUse.txt"
    scanner.main_Scanner(filename)
