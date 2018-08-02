import socket
import threading
import thread
import sys
import time

from scapy.all import *

if sys.stdout !=sys.__stdout__:
    sys.stdout =sys.__stdout__

global PORT
global attack


def new_port():#looking for free port to socket in case of attacl
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind(('',0))
    s.listen(1)
    port=s.getsockname()[1]
    s.close()
    return port



def handler(addr):
    global PORT,attack
    print 'begining'
    normal_port=PORT#save the port in case of changing port in order to allow the server send the new port
    while 1:
        pkt=sniff(1,filter = 'dst port %i and ip src host %s'%(PORT,addr[0]),timeout=1)#sniff to the ip of the client and wait just 1 second to check all the the if the attack is false 
        print pkt
        if not len(pkt)==0:#Initializing the seq and ack
            data = pkt[0].getlayer(Raw).load
            size_seq=pkt[0].getlayer(TCP).ack
            size_ack=pkt[0].getlayer(TCP).seq+len(data)

            
            if data=="quit":
                pkt_RA=IP(dst=addr[0])/TCP(flags='RA',sport=normal_port,dport=addr[1],seq=size_seq,ack=size_ack)#send reset to kick out the client
                send(pkt_RA)
                break

            echo="echo..."+data#buld and send the eco packet
            pkt_ack=IP(dst=addr[0])/TCP(flags='A',sport=PORT,dport=addr[1],seq=size_seq,ack=size_ack)/echo
            pkt=sr1(pkt_ack)
            
            size_seq=pkt[0].getlayer(TCP).ack#Initializing the seq and ack because of the ack packet of the client
            size_ack=pkt[0].getlayer(TCP).seq+len(data)-1
            
        if attack:#if attack:
            message_port=str(PORT)#send to the lient packet with the new port and than reset
            pkt_pa=IP(dst=addr[0])/TCP(flags='PA',sport=normal_port,dport=addr[1],seq=size_seq,ack=size_ack)/message_port
            send(pkt_pa)
            pkt_RA=IP(dst=addr[0])/TCP(flags='RA',sport=normal_port,dport=addr[1],seq=size_seq,ack=size_ack)
            send(pkt_RA)
            break



def handshake(ADDR):
    global PORT,attack

    black_list_file=open("black_list.txt","rb")#take the bad ipies
    black_list=black_list_file.readlines()

    SYN = 0x002#to check which kind of packet is
    ACK = 0x010

    filter_getClient='ip dst host '+ADDR[0]+' and tcp dst port '+str(ADDR[1])
    pkt=sniff(count=1,filter =filter_getClient)#sniff for tcp packetes of the server's port and ip
    flag= pkt[0].getlayer(TCP).flags#take the flags for the tcp packet
    
    ip=pkt[0].getlayer(IP)#take the source ip from the packet 
    tcp=pkt[0].getlayer(TCP)#take the source port from the packet
    source_ip=ip.src
    source_port=tcp.sport

    if(not (source_ip in black_list)):#check if the ip is alredy bad(check the flags, check if the syn flag is on the the ack isn't)
        if (flag & SYN) and not(flag & ACK):#check if the packet is syn packet
            synAck_pkt=IP(dst=source_ip)/TCP(sport=PORT,dport=source_port, flags='SA',ack=tcp.seq+1,seq=tcp.seq)#build syn_ack packet
            pkt=sr1(synAck_pkt)
            flag= pkt[0].getlayer(TCP).flags
            if (flag & SYN) and not(flag & ACK):#check if the reciving packet is again syn packet
                print "got here"#if yes this is a syn attack:
                attack=True#Declares attack

                tcp=pkt[0].getlayer(TCP)                
                pkt_RA=IP(dst=source_ip)/TCP(flags='RA',sport=PORT,dport=source_port,ack=tcp.seq+1,seq=tcp.seq)#build a reset packet and send her to the evil client
                send(pkt_RA)
                
                PORT=new_port()#change the port of the sockett
                black_list_file=open("black_list.txt","wb")#enter the evil ip to the black list
                black_list_file.write("\n" + source_ip)
                black_list_file.close()
                time.sleep(1.5)#wait 1.5 seconds to allow to the server send to the connect clients the new port
                return 0#send 0 to avoid the connection of the evil client
            addr = (source_ip,source_port)#if no send the details about the client and connect him
            return addr
        else:#if no send 0 to avoid the connection of the client he is evil or already connection
            return 0
    else:#if yes send 0 to avoid the connection of the evil client
        return 0


def main():
    global PORT,attack

    HOST = '172.16.12.195'
    ADDR = (HOST, PORT)

    print 'waiting for connection...'

    while not attack:#as long there is not attack is running 
        addr=handshake(ADDR)

        if not (addr==0):#check if every thing is ok if yes connect the client
            print '...connected from:', addr
            thread.start_new_thread(handler, (addr,))



    if(attack):#if there is attack start all over againg just with new port
        attack=False
        main()


attack=False
clients=[]

PORT=50012
if __name__=='__main__':
    main()








