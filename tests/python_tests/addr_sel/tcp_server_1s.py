#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque

BACKLOG=10

ARG_LEN = 4
argc = len(sys.argv)
if (argc < ARG_LEN):
    print "Needs ", x - 1, " arguments [family, bind-addr, bind-port]"
    exit

myFamily = AF_INET
myFamilyStr = sys.argv[1]
if (myFamilyStr == "inet6"):
    myFamily = AF_INET6

myHost = sys.argv[2]
myPort = int(sys.argv[3])

addrinfo = getaddrinfo(myHost, myPort, myFamily, SOCK_STREAM)

listensock = socket(myFamily, SOCK_STREAM) # create a UDP socket
listensock.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
print "Binding to: ", addrinfo[0][4]
listensock.bind(addrinfo[0][4])
listensock.listen(BACKLOG)

sock, addr = listensock.accept()

print "Waiting in recv 1 ..."
bytes = sock.recv(16)
print "Received ", len(bytes), " bytes: ", bytes

print "Waiting in recv 2 ..."
bytes = sock.recv(16)
print "Received ", len(bytes), " bytes: ", bytes

sock.close()
