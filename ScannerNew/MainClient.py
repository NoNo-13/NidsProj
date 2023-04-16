import socket
from Sniffer import *
import RuleFileReader
from cryptography.fernet import Fernet


class Client:
    def __init__(self):
        self.IP = socket.gethostbyname(socket.gethostname())  # Host address
        self.port = 8820  # Host port
        self.socket = None  # Socket
        self.HEADER_SIZE = 1024
        self.FORMAT = 'utf-8'
        self.server = (self.IP, self.port)
        self.sniffer = Sniffer()
        self.keyEnc = None
        self.start_client()
        self.connected = True

    def start_client(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect(self.server)

            key = self.socket.recv(1024)
            self.keyEnc = Fernet(key)
            print(key.decode())

        except socket.error as e:
            str(e)
        print("Client connected")

    def close_client(self):
        self.socket.close()

    def decryption_data(self, data):
        decrypted_data = self.keyEnc.decrypt(data).decode()  # f is the variable that has the value of the key.
        return decrypted_data
    def send_data(self, data):
        encrypted_data = self.keyEnc.encrypt(bytes(data, 'utf-'))

        chunks = [encrypted_data[i:i + self.HEADER_SIZE] for i in range(0, len(encrypted_data), self.HEADER_SIZE)]
        # Send each chunk
        self.socket.send(str(len(chunks)).zfill(4).encode())
        for chunk in chunks:
            self.socket.send(chunk)


    def client_command_def(self):
        exit_flag = False
        while not exit_flag:
            try:
                inputCli = input("Write your command: \n")
                if(inputCli == "exit"):
                    self.sniffer.stop()
                    self.connected = False
                    exit_flag = True
                if(inputCli == "showDb"):
                    inputCli = input('Name of the rule: ')
                    if(inputCli == "all"):
                        self.send_update("showDb")
                    else:
                        self.send_update_par("showDb", {"msg": inputCli})
                    data = bytes()
                    times = self.socket.recv(4).decode()
                    times = int(times)
                    i = 0
                    while i < times:
                        data += self.socket.recv(self.HEADER_SIZE)
                        i += 1

                    data = self.decryption_data(data)
                    print(data)
                if(inputCli == "getFull"):
                    inputCli = input('Enter the id of the packet: ')
                    self.send_update_par("getFull", {"id": inputCli})
                    data = bytes()
                    times = self.socket.recv(4).decode()
                    print(times)
                    times = int(times)
                    i = 0
                    while i < times:
                        data += self.socket.recv(self.HEADER_SIZE)
                        i += 1

                    data = self.decryption_data(data)
                    print(data)


            except KeyboardInterrupt:
                exit_flag = True



    def client_talk(self):
        filename = "RulesToUse.txt"
        self.setting_rule_list(filename)

        sniffer_thread = threading.Thread(target=self.sniffer.run)
        sniffer_thread.start()

        client_command = threading.Thread(target=self.client_command_def)
        client_command.start()

        try:
            while self.connected:
                if len(self.sniffer.cache) >= 1:
                    self.send_update_par('found', {'packet': self.sniffer.cache})
                    self.sniffer.cache.clear()
            self.close_client()
        except KeyboardInterrupt:
            print("Exiting program...")
            self.sniffer.stop()



    def send_update(self, cmd):
        self.send_data(json.dumps({'cmd': cmd}))

    def send_update_par(self, cmd: str, params: dict):
        self.send_data(json.dumps({'cmd': cmd, **params}))

    def setting_rule_list(self, filename):
        # Read the rule file
        print("Reading rule file...")
        self.sniffer.ruleList = RuleFileReader.read(filename)
        print("Finished reading rule file.")


def main_Cliient():
    client = Client()
    client.client_talk()



if __name__ == '__main__':
    main_Cliient()
