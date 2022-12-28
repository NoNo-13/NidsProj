import socket
from Sniffer import *
import RuleFileReader

class Client():
    def __init__(self):
        self.IP = socket.gethostbyname(socket.gethostname())  # Host address
        self.port = 8820  # Host port
        self.socket = None  # Socket
        self.HEADER_SIZE = 1024
        self.FORMAT = 'utf-8'
        self.server = (self.IP, self.port)
        self.sniffer = Sniffer()

    def start_client(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect(self.server)
        except socket.error as e:
            str(e)
        print("Client connected")

    def client_talk(self):
        filename = "RulesToUse.txt"
        self.setting_rule_list(filename)
        self.sniffer.run()
        sniffer_thread = threading.Thread(target=self.sniffer.run())
        sniffer_thread.start()
        connected = True
        while connected:
            if len(self.sniffer.cache) >= 1:
                self.send_update('found', {'packet': self.sniffer.cache})
                self.sniffer.cache.clear()
            #need to do client commands (maybe with thread for scanner and one for commands)

    def send_update(self, cmd: str, params: dict):
        self.socket.send(json.dumps({'cmd': cmd, **params}).encode())

    def setting_rule_list(self, filename):
        # Read the rule file
        print("Reading rule file...")

        self.sniffer.ruleList, errorCount = RuleFileReader.read(filename)
        print("Finished reading rule file.")

        if (errorCount == 0):
            print("All (" + str(len(self.sniffer.ruleList)) + ") rules have been correctly read.")
        else:
            print(str(len( self.sniffer.ruleList)) + " rules have been correctly read.")
            print(str(errorCount) + " rules have errors and could not be read.")


def main_Cliient():
    client = Client()
    client.start_client()
    client.client_talk()

if __name__ == '__main__':
    main_Cliient()




