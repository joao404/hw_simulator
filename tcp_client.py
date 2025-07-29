import socket

clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientsocket.connect(('192.168.178.61', 13181))
data = str.encode('<SimCmd cmd=\"set\" pin=\"PB0\" value=\"high\"/>')
clientsocket.sendall(data)