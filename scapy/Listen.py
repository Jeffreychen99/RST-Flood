import sys
from scapy.all import *
import Scapy_Spoof


def listen(packet):
	print(packet.summary)
	ip = packet[0][1]
	tcp = packet[0][1][1]
	
	#Scapy_Spoof.spoof(ip.src, ip.dst, tcp.sport, tcp.dport)
	Scapy_Spoof.spoof(ip.src, '185.230.61.161', tcp.sport, tcp.dport)


print("Got here")
sniff(filter='tcp and src 10.31.25.125', count=1, prn=listen)