import socket               # 导入 socket 模块
import sys

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
host = socket.gethostname() # 获取本地主机名
port = 8889                # 设置端口号

s.connect((host, port))

fo = open("quote.data", "rb")
str = fo.read()
print ("Read String is : ", str)

#msg = "\r\n\r\ncccc"

s.send(str)
print(s.recv(1024))
s.close()  