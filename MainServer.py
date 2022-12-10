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
        self.Address_server = [(self.IP, self.port)]

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
        pass


        self.socket.sendto(str.encode(self.make_pos_str(self.pos[player])), addr)
        reply = ""
        self.pos[player] = data
        player = 0
        for addres in self.Addresses:
            if addres[0] != addr[0]:
                reply += self.make_pos_str(self.pos[player])
            player += 1
        print("Received", data)
        if reply != "":
            print("sending: ", reply)
            self.socket.sendto(str.encode(self.make_pos_str(reply)), addr)
        print("lost connection")

    def wait_for_client(self):
        while True:
            (client_socket, addr) = self.socket.accept()
            client_thread = threading.Thread(target=self.threaded_client, args=(client_socket, addr))
            client_thread.start()

def main_Server():

    server = TCPServer()
    server.start_server()
    server.wait_for_client()
    receive_thread = threading.Thread(target=server.wait_for_client)
    receive_thread.start()

if __name__ == '__main__':
    main_Server()
