import json
import logging
import socket
import threading


class TCPServer:
    def __init__(self):
        self.IP = socket.gethostbyname(socket.gethostname())  # Host address
        self.port = 8820  # Host port
        self.socket = None  # Socket
        self.HEADER_SIZE = 1024
        self.FORMAT = 'utf-8'
        self.Address_server = (self.IP, self.port)
        self.founds = list() #It will be database with Mysql

    def start_server(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.bind((self.IP, self.port))
        except socket.error as e:
            str(e)
        self.socket.listen()
        print("server started")

    def threaded_client(self, client_socket, addr):
        print("New Connection")
        connected = True
        while connected:
            data = client_socket.recv(self.HEADER_SIZE).decode(self.FORMAT)
            data = json.loads(data)
            if data["cmd"] == "disconnect":
                connected = False
            else:
                self.handle_update(data=data, addr=addr)
        client_socket.close()

    def handle_update(self, data, addr):
        if data["cmd"] == "found":
            try:
                self.founds.append(data["packet"])
            except:
                print("Wrong data: packet")




    def wait_for_client(self):
        while True:
            (client_socket, addr) = self.socket.accept()
            client_thread = threading.Thread(target=self.threaded_client, args=(client_socket, addr))
            client_thread.start()

def main_Server():

    server = TCPServer()
    server.start_server()
    server.wait_for_client()

if __name__ == '__main__':
    main_Server()
