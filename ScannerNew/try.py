import mysql.connector

a = '16, "TThreatHunter Rule - sameip Keyword Test Rule", "192.168.1.107", b"\\x98\\x93\\xcc\\xa9\\xc5!t\\xd8>4\\xabW\\x08\\x00E\\x00\\x00\\x96Z\\x95@\\x00\\x80\\x06\\x00\\x00\\xc0\\xa8\\x01k\\xc0\\xa8\\x01f\\xe7\\x06\\x1fIJ\\x9c\\x1e1\\x91\\xdcq\\x01P\\x18\\x00\\xfb\\x84\\xaa\\x00\\x00\\x17\\x03\\x03\\x00i\\xf8\\xcd\\x13w\\xbc\\xe5\\xa8\\x8a\\x9b(/\\xaf]\\x81K}\\xc6N2?\\xd8\\x1c@Q/b\\t\\x9b\\xad!\\x82\\x99\\xc9\\xfe\\xf0\\xea\\x98\\xdd\\x8b\\x83\\xfb\\x94\\x92\\x9fS\\x1f+\\xd73E\\x00\\xb3\\xeb\\xfbPq\\xb6T\\xd6N\\xb4x\\x81\\xbb\\x06\\x0f\\xdd\\xc3m\\x89\\x88\\xe9\\x98>\\xdb\\xc4\\xd3\\xb6\\xc8\\xbf46p\\x91=/sc\\x95\\xb1#\\xfd#;I\'\\x90V,\\x83M\\x8c\\x90\\xc9\\x9a"'

print(type(a))
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