import socket, struct

class IP_Header:
	def __init__(self, src_ip, dst_ip):
		self.saddr = socket.inet_aton( src_ip )
		self.daddr = socket.inet_aton( dst_ip )

		ihl = 5
		ver = 4
		self.ihl_ver = (ver << 4) + ihl

		self.tos = 0
		self.tot_len = 0
		self.id = 54321
		self.frag_off = 0
		self.ttl = 255
		self.proto = socket.IPPROTO_TCP
		self.check = 0

	def assemble(self):
		self.raw = struct.pack('!BBHHHBBH4s4s',
			self.ihl_ver,
			self.tos,
			self.tot_len,
			self.id,
			self.frag_off,
			self.ttl,
			self.proto,
			self.check,
			self.saddr,
			self.daddr
		)
		return self.raw








