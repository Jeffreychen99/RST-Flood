import requests
import socket
import sys
from struct import *

from IP_Header import IP_Header
from TCP_Header import TCP_Header

selfIP = ""
try:
	selfIP = requests.get(url="https://ifconfig.me").text
except:
	print("Could not connect to https://ifconfig.me")

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

payload = '12345'

#source_ip = selfIP
source_ip = '192.168.5.140'
#source_ip = '10.31.25.237'
#dest_ip = socket.gethostbyname('www.google.com')
dest_ip = '172.217.6.164'
ip_head = IP_Header(source_ip, dest_ip)
ip_header = ip_head.assemble()

source_port = 80
dest_port = 443
tcp_head = TCP_Header(source_ip, dest_ip, source_port, dest_port)
tcp_head.create_flags(rst=1)
tcp_header = tcp_head.assemble(payload)

# if using socket.IPPROTO_TCP, you can't use ip_header because it gets auto-added
packet = tcp_header + bytearray(payload, 'utf-8')
#packet = ip_header + tcp_header + bytearray(payload, 'utf-8')

# AS IT IS NOW, CAN'T SEND WITH SPOOFED IP, NEED TO IMPLEMENT IP HEADER TO DO THIS

for i in range(len(packet)):
	if i % 4 == 0:
		print()
	if i == 20 or i == 40:
		print()
	hexstring = '0x' + hex(packet[i])[2:].zfill(2)
	print(hexstring, end="\\")
print("\n")

print("SOURCE IP:      " + source_ip)
print("DESTINATION IP: " + dest_ip)

import time
while True:
	s.sendto(packet, (dest_ip, 0))
	time.sleep(0.05)

















