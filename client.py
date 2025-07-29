#!/usr/bin/env python

import socket

SERVER_IP = "192.168.178.30"
SERVER_PORT = 3005

address = (SERVER_IP ,SERVER_PORT)

socket_client=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

while True:
	message = input("Enter your message > ")
	if message=="quit":
		break
	socket_client.sendto(bytes(message,encoding='utf8'),address)
	#response_server,addr = socket_client.recvfrom(4096)
	#print("Response from the server => %s" % response_server)

socket_client.close()
