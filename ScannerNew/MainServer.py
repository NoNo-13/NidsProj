import json
import logging
import socket
import threading

from DB import *
from cryptography.fernet import Fernet


class TCPServer:
    def __init__(self):
        self.IP = "0.0.0.0" #socket.gethostbyname(socket.gethostname())  Host address
        self.port = 8820  # Host port
        self.socket = None  # Socket
        self.HEADER_SIZE = 1024
        self.FORMAT = 'utf-8'
        self.Address_server = (self.IP, self.port)
        self.database = DB()
        self.addresses = list() #all the addresses that connect to server
        self.keyEnc, self.key = self.encryption_gen()
        self.start_server()


    def start_server(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.bind((self.IP, self.port))
        except socket.error as e:
            str(e)
        self.socket.listen()
        print("server started")

    def encryption_gen(self):
        key = Fernet.generate_key()
        print(key.decode())
        fer = Fernet(key)
        return fer, key

    def decryption_data(self, data):
        print(data)
        decrypted_data = self.keyEnc.decrypt(data).decode()
        print(decrypted_data)
        return decrypted_data
    def send_data(self, data, client_socket):
        encrypted_data = self.keyEnc.encrypt(bytes(data, 'utf-'))
        chunks = [encrypted_data[i:i + self.HEADER_SIZE] for i in range(0, len(encrypted_data), self.HEADER_SIZE)]
        # Send each chunk
        client_socket.send(str(len(chunks)).zfill(4).encode())
        for chunk in chunks:
            client_socket.send(chunk)

    def threaded_client(self, client_socket, addr):
        print("New Connection")
        client_socket.send(self.key)
        connected = True
        while connected:

            data = bytes()
            times = client_socket.recv(4).decode()
            times = int(times)
            i = 0
            while i < times:
                data += client_socket.recv(self.HEADER_SIZE)
                i += 1

            data = self.decryption_data(data)
            data = json.loads(data)
            if data["cmd"] == "disconnect":
                connected = False
            if data["cmd"] == "found":
                self.database.store_packet(data)
            if data["cmd"] == "showDb":
                dbData = self.database.showData(data)
                self.send_data(dbData, client_socket)
            if data["cmd"] == "getFull":
                dbData = self.database.showData(data)
                if (dbData == ""):
                    dbData = "Id not found"
                self.send_data(dbData, client_socket)


        client_socket.close()

    def new_connect(self, addr):
        self.addresses.append(addr)


    def wait_for_client(self):
        while True:
            try:
                (client_socket, addr) = self.socket.accept()
                self.new_connect(addr)
                client_thread = threading.Thread(target=self.threaded_client, args=(client_socket, addr))
                client_thread.start()
            except:
                print("Couldn't accept Client")

def main_Server():
    server = TCPServer()
    server.wait_for_client()

if __name__ == '__main__':
    main_Server()
