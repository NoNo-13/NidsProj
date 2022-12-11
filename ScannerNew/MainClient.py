import socket
from MainScanner import *

class Client():
    def __init__(self):
        self.IP = socket.gethostbyname(socket.gethostname())  # Host address
        self.port = 8820  # Host port
        self.socket = None  # Socket
        self.HEADER_SIZE = 1024
        self.FORMAT = 'utf-8'
        self.Address_server = (self.IP, self.port)

    def start_client(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.connect(self.Address_server)   
        except socket.error as e:
            str(e)
      
        print("Client connected")

    def client_talk(self):
        scanner = Scanner()
        filename = "RulesToUse.txt"
        scanner.main_Scanner(filename)

        connected = True
        while connected:
            pass



def main_Cliient():
    client = Client()
    client.start_client()
    client.client_talk()

if __name__ == '__main__':
    main_Cliient()




