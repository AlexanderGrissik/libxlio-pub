#!/usr/bin/python
from socket import *
import fcntl, os, sys
import time
from collections import deque

ARG_LEN = 5
argc = len(sys.argv)
if (argc < ARG_LEN):
    print "Needs ", x - 1, " arguments [family, dst-addr, dst-port, send-sleep-sec]"
    exit

myFamily = AF_INET
myFamilyStr = sys.argv[1]
if (myFamilyStr == "inet6"):
    myFamily = AF_INET6

myDstHost = sys.argv[2]
myDstPort = int(sys.argv[3])
mySleepSec = int(sys.argv[4])

sock = socket(myFamily, SOCK_STREAM) # create a UDP socket

addrinfo = getaddrinfo(myDstHost, myDstPort, myFamily, SOCK_STREAM)
print "Connecting to: ", addrinfo[0][4]
sock.connect(addrinfo[0][4])

print "Sending 1"
bytes = sock.send("hello1hello1____")
print "Sent ", bytes, " bytes"

time.sleep(mySleepSec)

print "Sending 2"
bytes = sock.send("hello2hello2____")
print "Sent ", bytes, " bytes"

sock.close()
