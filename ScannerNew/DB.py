import logging
import os

import mysql.connector
import parsuricata

#cursor.execute("DESCRIBE packets")- all the collums
#cursor.execute("SELECT * FROM packets")- get all the data
#cursor.execute("SELECT * FROM packets WHERE protocol = "http"")- get all the data that the protocol is http
#cursor.execute("SELECT msg FROM packets")- get all the msg data
#cursor.execute("CREATE TABLE XXX")- creating new table called XXX
#cursor.execute(sql, values)- adding
#cursor.execute("DELETE FROM packets WHERE condition") - delete


#TABLE packets(


class DB:
    def __init__(self):
        self.connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Noam13132",
            database="malicious_packets")
        self.cursor = self.connection.cursor()
        self.create_db()

    def create_db(self):
        try:
            self.cursor.execute('CREATE DATABASE IF NOT EXISTS malicious_packets')
            self.cursor.execute('USE malicious_packets')
            self.cursor.execute('CREATE TABLE IF NOT EXISTS packets(id INT AUTO_INCREMENT PRIMARY KEY, msg VARCHAR(255), src VARCHAR(255), pkt VARCHAR(4096))')
        except Exception:
            logging.exception('db exception')
            self.close()

    def close(self):
        # Close the cursor and database connection
        self.cursor.close()
        self.connection.close()

    def store_packet(self, data):
        try:
            listPkt = data['packet']
            for each in listPkt:
                sql = "INSERT INTO packets (msg, src, pkt) VALUES (%s, %s, %s)"
                values = (each[0], each[1], each[2])
                self.cursor.execute(sql, values)
                self.connection.commit()
        except Exception:
            logging.exception('db exception')
            self.close()

    def showData(self, data):
        if "msg" in data:
            self.cursor.execute("SELECT id, msg FROM packets WHERE msg =  %(msg)s", {'msg': data["msg"]})
        elif "id" in data:
            self.cursor.execute("SELECT * FROM packets WHERE id =  %(id)s", {'id': data["id"]})
        else:
            self.cursor.execute("SELECT id, msg FROM packets")
        string = ""
        for each in self.cursor:
            for col in each:
                if(col != None):
                    string += str(col) + ", "
                else:
                    string += "None, "
            string += "\n"
        return string

