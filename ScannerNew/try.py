import json

import logging
import threading
from ipaddress import ip_network

import mysql.connector
from DB import *
import parsuricata
from parsuricata import parse_rules, Option
import json
from cryptography.fernet import Fernet

connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Noam13132",
            database="malicious_packets")
cursor = connection.cursor()

cursor.execute("SELECT * FROM packets")
for x in cursor:
    print(x)
