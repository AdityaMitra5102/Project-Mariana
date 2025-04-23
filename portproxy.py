import socket
import logging
import threading
import random

from portutils import *

proxyhost='127.0.0.1'

class ConnectionObject:
	def __init__(self, sendobj, recvobj):
		self.recv=recvobj
		self.sendall=sendobj

class PortProxy:
	def __init__(self, hostport, guestport, nac, mode, servermode, ephemeral, first_payload, send_payload):
		if not servermode:
			self.hostport=hostport
			self.host=int.from_bytes(hostport)

		self.guestport=guestport
		self.guestnac=nac


		self.opt=None
		if mode:
			self.opt=socket.SOCK_STREAM
		else:
			self.opt=socket.SOCK_DGRAM
		self.sock=socket.socket(socket.AF_INET, self.opt)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.ephemeral=ephemeral
		if ephemeral==0:
			self.ephemeral=random.randint(49152, 65535)
		if servermode:
			self.sock.bind(('0.0.0.0', self.ephemeral))
		self.servermode=servermode
		self.est=False
		self.first_payload=first_payload
		self.mode=mode
		self.send_payload=send_payload
		
	def guest_to_host(self, payload):
		#print(f'Sending to socket port {self.hostport} data {payload}')
		print(f'Verifying socket {self.sock}')
		self.connobj.sendall(payload)
		
	def host_to_guest(self):
		data=self.connobj.recv(1024)
		print(f'DATA RECEIVED {data}')
		if data is not None:
			payload=make_port_payload(self.mode, self.servermode, self.hostport, self.guestport, data)
			print(f'Sending payload to {self.guestnac} port {self.guestport}')
			self.send_payload(self.guestnac, payload)
		else:
			self.est=False
		
	def listen_loop(self):
		while self.est:
			try:
				self.host_to_guest()
			except Exception as e:
				logging.warn(f'Couldnt read from socket {e}')
				self.sock.close()
				port_destroyed(self)
				if self.servermode:
					init_port_thread()
				return
		logging.info(f'Socket closed')
		self.sock.close()
		port_destroyed(self)
		if self.servermode:
			init_port_thread()
		
	def get_port_proxy_id(self):
		return get_socket_id(self.guestnac, self.guestport)
		
	def udp_send(self, payload):
		self.sock.sendto(payload, (proxyhost, self.host))
		
	def udp_recv(self, buffer):
		data, addr=self.sock.recvfrom(buffer)
		hostip, port=addr
		self.host=port
		if not self.hostport:
			self.hostport=uuid_bytes(str(uuid.uuid4()))
		return data
		
	def init_port(self):
		print(f'SERVER MODE {self.servermode}')
		if self.mode:
			if self.servermode:
				self.sock.listen()
				conn, addr=self.sock.accept()
				self.connobj=conn
				hostip, port=addr
				print(f'Connection active to {hostip}, {port}')
				self.host=port
				self.hostport=uuid_bytes(str(uuid.uuid4()))
			else:
				self.sock.connect((proxyhost, self.host))
				self.connobj=self.sock
				print(f'Connected {self.connobj}')
				
		else:
			
			self.connobj=ConnectionObject(self.udp_send, self.udp_recv)
			if self.servermode:
				self.hostport=None
				data=self.udp_recv(1)
				payload=make_port_payload(self.mode, self.servermode, self.hostport, self.guestport, data)
				self.send_payload(self.guestnac, payload)
		
		self.est=True
		proxy_thread=threading.Thread(target=self.listen_loop)
		proxy_thread.start()
		port_established(self)
		self.guest_to_host(self.first_payload)
		self.first_payload=None
		
	def init_port_thread(self):
		init_port_thread=threading.Thread(target=self.init_port)
		init_port_thread.start()
		
