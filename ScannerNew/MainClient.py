import socket
from Sniffer import *
import RuleFileReader
from cryptography.fernet import Fernet
from TestMal import *
import sys
from PyQt5.QtWidgets import QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout, QTextEdit, QHBoxLayout, \
    QInputDialog



class GUI(QWidget):

    def __init__(self, Client):
        super().__init__()
        self.title = 'Client GUI'
        self.left = 600
        self.top = 300
        self.width = 700
        self.height = 500
        self.initUI(Client)

    def initUI(self, client):
        self.setWindowTitle(self.title)
        self.setGeometry(self.left, self.top, self.width, self.height)

        self.static_label = QLabel("\nCommands:\nexit, showDb:(all, msg name), getFull: (id name), test: (capture, send)")
        self.static_label.setStyleSheet("font-weight: bold; font-size: 14px;")

        # create input field and label
        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)
        self.text_edit.move(50, 50)
        self.text_edit.resize(200, 60)

        self.input = QLineEdit(self)
        self.input.move(50, 120)
        self.input.resize(200, 20)

        # create button to get input
        self.button = QPushButton('Command', self)
        self.button.move(110, 110)
        self.button.clicked.connect(lambda: self.on_click(client))

        # create layout with static label
        top_layout = QHBoxLayout()
        top_layout.addWidget(self.static_label)
        top_layout.addStretch()

        # create layout with input and button
        layout = QVBoxLayout()
        layout.addWidget(self.text_edit)
        layout.addWidget(self.input)
        layout.addWidget(self.button)

        # create main layout with both layouts
        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addLayout(layout)

        self.setLayout(main_layout)


        self.show()

    def on_click(self, client):
        # get text from input field and display in label
        message = self.input.text()

        print(message)
        if(message == "exit"):
            client.connected = False
            client.sniffer.stop()
            self.close()

        if (message == "showDb"):
            message, ok = QInputDialog.getText(None, 'Input Dialog', 'Name of the rule')
            if(message == "all"):
                client.send_update("showDb")
            else:
                client.send_update_par("showDb", {"msg": message})
            data = bytes()
            times = client.socket.recv(4).decode()
            times = int(times)
            i = 0
            while i < times:
                data += client.socket.recv(client.HEADER_SIZE)
                i += 1

            data = client.decryption_data(data)
            print(data)
            self.text_edit.append(data)

        elif (message == "getFull"):
            message, ok = QInputDialog.getText(None, 'Input Dialog', 'Enter the id of the packet')
            client.send_update_par("getFull", {"id": message})
            data = bytes()
            times = client.socket.recv(4).decode()
            times = int(times)
            i = 0
            while i < times:
                data += client.socket.recv(client.HEADER_SIZE)
                i += 1

            data = client.decryption_data(data)
            print(data)
            self.text_edit.append(data)

        elif (message == "test"):
            hostname = socket.gethostname()
            dst = socket.gethostbyname(hostname)
            src = '1.2.3.4'
            iface = "ens33"
            count = 1000
            message, ok = QInputDialog.getText(None, 'Input Dialog', 'Enter test capture or send')
            if(message == "capture"):
                exploitTest_capture(src, dst, iface, count)
            if(message == "send"):
                pkt = exploitTest_send(src, dst, iface)
                client.sniffer.inPacket(pkt)

        self.input.clear()



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



    def client_talk(self):
        filename = "RulesToUse.txt"
        self.setting_rule_list(filename)

        sniffer_thread = threading.Thread(target=self.sniffer.run)
        sniffer_thread.start()

        try:
            while self.connected:
                if len(self.sniffer.cache) >= 1:
                    self.send_update_par('found', {'packet': self.sniffer.cache})
                    self.sniffer.cache.clear()

            self.send_update("disconnect")
            self.close_client()
            print("Exiting program...")
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


def GuiScreen(client):
    app = QApplication(sys.argv)
    ex = GUI(client)
    app.exec_()
    ex.close()

def main_Cliient():
    import warnings
    warnings.filterwarnings('error')

    client = Client()
    client_command = threading.Thread(target=GuiScreen, args=(client,))
    client_command.start()
    client.client_talk()



if __name__ == '__main__':
    main_Cliient()
