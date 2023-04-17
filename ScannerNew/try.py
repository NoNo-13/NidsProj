import mysql.connector


connection = mysql.connector.connect(
            host="localhost",
            user="root",
            password="Noam13132",
            database="malicious_packets")
cursor = connection.cursor()

#cursor.execute("ALTER TABLE packets AUTO_INCREMENT = 2")
#connection.commit()

cursor.execute("SELECT * FROM packets")

for x in cursor:
    print(x)