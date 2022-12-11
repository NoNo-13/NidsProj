import socket
from MainScanner import *

class Client():
    def __init__(self):
        self.IP = socket.gethostbyname(socket.gethostname())  # Host address
        self.port = 8820  # Host port
        self.socket = None  # Socket
        self.HEADER_SIZE = 1024
        self.FORMAT = 'utf-8'
        self.server = (self.IP, self.port)

    def start_client(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.connect(self.server)
        except socket.error as e:
            str(e)
      
        print("Client connected")

    def client_talk(self):
        scanner = Scanner()
        filename = "RulesToUse.txt"
        scanner.main_Scanner(filename)
        connected = True
        while connected:
            if len(scanner.cache) >= 1:
                self.send_update('found', {'packet': scanner.cache})
                scanner.cache.clear()
            #need to do client commands (maybe with thread for scanner and one for commands)

    def send_update(self, cmd: str, params: dict):
        self.socket.send(json.dumps({'cmd': cmd, **params}).encode())



def main_Cliient():
    client = Client()
    client.start_client()
    client.client_talk()

if __name__ == '__main__':
    main_Cliient()




