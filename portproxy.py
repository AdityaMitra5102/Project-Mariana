import socket
import logging
import threading

from portutils import *

proxyhost='localhost'
class PortProxy:
	def __init__(self, hostport, guestport, nac, mode, servermode, ephemeral, first_payload):
		if not servermode:
			self.hostport=hostport
			self.host=int.from_bytes(hostport)

		self.guestport=guestport
		self.guestnac=nac


		self.opt=None
		if mode=='TCP':
			self.opt=socket.SOCK_STREAM
		if mode=='UDP':
			self.opt=socket.SOCK_DGRAM
		self.sock=socket.socket(socket.AF_INET, self.opt)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.ephemeral=ephemeral
		if ephemeral==0:
			self.ephemeral=random.randint(49152, 65535)
		self.sock.bind(('', self.ephemeral))
		self.servermode=servermode
		self.sessionkey=sessionkey
		self.est=False
		self.first_payload=first_payload
		
	def guest_to_host(self, payload):
		self.connobj.sendall(payload)
		
	def host_to_guest(self):
		data=self.connobj.recv(1024)
		if data:
			payload=make_port_payload(self.mode, self.servermode, self.hostport, self.guestport, data)
			send_payload(self.guestnac, payload)
		else:
			self.est=False
		
	def listen_loop(self):
		while self.est:
			try:
				self.host_to_guest()
			except:
				logging.warn('Couldnt read from socket')
		logging.info(f'Socket closed')
		port_destroyed(self)
		if self.servermode:
			init_port_thread()
		
	def get_port_proxy_id(self):
		return get_socket_id(self.guestnac, self.guestport)
		
	def init_port(self):
		if self.servermode:
			self.sock.listen()
			conn, addr=s.accept()
			self.connobj=conn
			hostip, port=addr
			self.host=port
			self.hostport=uuid_bytes(str(uuid.uuid4()))
		else:
			self.sock.connect((proxyhost, self.host))
			self.connobj=self.sock
		self.est=True
		proxy_thread=threading.Thread(target=self.listen_loop)
		proxy_thread.start()
		port_established(self)
		self.guest_to_host(self.first_payload)
		self.first_payload=None
		
	def init_port_thread(self):
		init_port_thread=threading.Thread(target=self.init_port)
		init_port.start()
		
		
		
