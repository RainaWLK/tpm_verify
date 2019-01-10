import socket               # 导入 socket 模块
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = socket.gethostname() # 获取本地主机名
port = 8889                # 设置端口号

s.connect((host, port))

fo = open("quote.data", "rb")
data = fo.read()
print ("Read data is : ", data)
fo.close()

fo = open("quote.sig", "rb")
sig = fo.read()
print ("Read sig is : ", sig)
fo.close()

buf = data + b'\r\n\r\n\r\n\r\n' + sig

s.send(buf)
print(s.recv(1024))
s.close()  