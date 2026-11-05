import socket
# sending a fake attack string
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(('127.0.0.1', 2222))
print(s.recv(1024)) # receiving fake SSH banner
s.sendall(b"USER root\r\n") #sending a mock payload
s.close() 