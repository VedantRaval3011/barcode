import socket

HOST = "127.0.0.1"
PORT = 9100

message = "TEST_BARCODE_12345678\n"

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((HOST, PORT))

sock.sendall(message.encode("ascii"))

print("Packet sent!")

sock.close()