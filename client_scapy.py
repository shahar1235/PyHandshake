from socket import *
import sys
import thread
import threading
import time


global tcpCliSock
global leave

def output_server(ip_dst):#thread that run to allow the client send and recieve messages at the same time
    global tcpCliSock
    while not leave:
        data = tcpCliSock.recv(BUFSIZ)

        if data[0]=="e":#check if the data is echo and if yes print it
            if (not data == "echo... "):
                print "\n" + data
        else:#if it dosent echo is the port probaly
            ADDR = (ip_dst, int(data))#buld new adress with the new port
            tcpCliSock.close()#close the socket
            tcpCliSock = socket(AF_INET, SOCK_STREAM)#build him from scratch
            tcpCliSock.connect(ADDR)#connect to the new port
    return 0


HOST = '172.16.12.195'
PORT = 50012
BUFSIZ = 1024
ADDR = (HOST, PORT)
tcpCliSock = socket(AF_INET, SOCK_STREAM)
tcpCliSock.connect(ADDR)


leave=False
thread.start_new_thread(output_server, (ADDR[0],))#start the thread that recieve data

while (1):
    data_to_send=raw_input("ENTER:")#take a pelet from the user
   
    tcpCliSock.send(data_to_send)
    time.sleep(1.1)#sleep to organize the data in the cmd(1."echo..." 2."ENTER:")
    if data=="quit":
        leave=True        
        break
    


tcpCliSock.close()
