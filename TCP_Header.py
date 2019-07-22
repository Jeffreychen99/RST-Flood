import struct
import socket

class TCP_Header:
	def __init__(self, source_ip, dest_ip, sport, dport):
		self.saddr = socket.inet_aton( source_ip )
		self.daddr = socket.inet_aton( dest_ip )

		self.src_port = sport
		self.dst_port = dport

		hdr_len = 5
		self.data_offset = hdr_len << 4

		self.seq = 0
		self.ack_seq = 0

		self.wdw = socket.htons(5840)
		self.urg_ptr = 0

		self.chksum = 0
		self.tcp_flags = 0


	def create_flags(self, rsv=0, noc=0, cwr=0, ecn=0, urg=0, ack=0, psh=0, rst=0, syn=1, fin=0):
		self.tcp_flags = 0

		self.tcp_flags += (rsv << 9)
		self.tcp_flags += (noc << 8)
		self.tcp_flags += (cwr << 7)
		self.tcp_flags += (ecn << 6)
		self.tcp_flags += (urg << 5)
		self.tcp_flags += (ack << 4)
		self.tcp_flags += (psh << 3)
		self.tcp_flags += (rst << 2)
		self.tcp_flags += (syn << 1)
		self.tcp_flags += (fin)

	def assemble(self, payload):
		placeholder = 0
		protocol = socket.IPPROTO_TCP

		tcp_preheader = struct.pack('!HHLLBBHHH',
			self.src_port,
			self.dst_port,
			self.seq,
			self.ack_seq,
			self.data_offset,
			self.tcp_flags,
			self.wdw,
			0,
			self.urg_ptr
		)

		tcp_length = len(tcp_preheader) + len(payload)

		checkinput = struct.pack('!4s4sBBH', self.saddr, self.daddr, placeholder, protocol, tcp_length)
		checkinput += tcp_preheader + bytearray(payload, 'utf-8')
		checksum = self.checksum(checkinput)

		self.raw = struct.pack('!HHLLBBHHH',
			self.src_port,
			self.dst_port,
			self.seq,
			self.ack_seq,
			self.data_offset,
			self.tcp_flags,
			self.wdw,
			checksum,
			self.urg_ptr
		)
		return self.raw

	def checksum(self, msg):
		s = 0
		for i in range(0, len(msg), 2):
			if i + 1 < len(msg):
				s += msg[i] + (msg[i + 1] << 8)
			elif i < len(msg):
				s += msg[i]
		s += (s >> 16)

		#return (0x6a89c - (s & 0xffff)) & 0xffff
		#print(hex((0x6a89c - (s & 0xffff)) & 0xffff))

		#return 0xb9e4	#145
		#return 0xb9e9	#140

		return ~s & 0xffff






