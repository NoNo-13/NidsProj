import socket
from Sniffer import *
import RuleFileReader
from cryptography.fernet import Fernet


class Client:
    def __init__(self):
        self.IP = socket.gethostbyname(socket.gethostname())  # Host address
        self.port = 8820  # Host port
        self.socket = None  # Socket
        self.HEADER_SIZE = 2048
        self.FORMAT = 'utf-8'
        self.server = (self.IP, self.port)
        self.sniffer = Sniffer()
        self.keyEnc = None
        self.start_client()

    def start_client(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect(self.server)

            key = self.socket.recv(self.HEADER_SIZE)
            self.keyEnc = Fernet(key)
            print(key.decode())

        except socket.error as e:
            str(e)
        print("Client connected")

    def decryption_data(self, data):
        decrypted_data = self.keyEnc.decrypt(data).decode()  # f is the variable that has the value of the key.
        return decrypted_data
    def send_data(self, data):
        encrypted_data = self.keyEnc.encrypt(bytes(data, 'utf-'))
        self.socket.send(encrypted_data)

    def client_command_def(self):
        exit_flag = False
        while not exit_flag:
            try:
                inputCli = input("Write your command: \n")
                if(inputCli == "showDB"):
                    inputCli = input('Name of the rule: ')
                    if(inputCli == "all"):
                        self.send_update("showDb")
                    else:
                        self.send_update_par("showDb", {"msg": inputCli})
                    data = self.socket.recv()
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

        connected = True
        try:
            while connected:
                if len(self.sniffer.cache) >= 1:
                    self.send_update_par('found', {'packet': self.sniffer.cache})
                    self.sniffer.cache.clear()
                # need to do client commands (maybe with thread for scanner and one for commands)
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
