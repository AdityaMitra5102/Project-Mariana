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
		self.ephemeral=ephemeral
		if ephemeral==0:
			self.ephemeral=random.randint(49152, 65535)
		self.servermode=servermode
		self.est=False
		self.first_payload=first_payload
		self.mode=mode
		self.send_payload=send_payload
		
		self.sendptr=255
		self.recvptr=255		
		self.sbuf=[]
		self.port_lock=threading.Lock()
		
	def guest_to_host(self, seqnum, payload):
		if seqnum==(self.recvptr+1) % 256:
			self.connobj.sendall(payload)
			self.recvptr=(self.recvptr+1) % 256
			self.send_ack()
		
	def host_to_guest(self):
		data=self.connobj.recv(1024)
		if data is not None:
			with self.port_lock:
				self.sendptr=(self.sendptr+1) % 256
				payload=make_port_payload(self.mode, self.servermode, self.hostport, self.guestport, self.sendptr, True, data)
				logging.info(f'Sending payload to {self.guestnac} port {self.guestport}')
				self.sbuf.append({'data':payload, 'time': get_timestamp()})
				self.send_curr_payload()
		else:
			self.est=False
		
	def listen_loop(self):
		while self.est:
			try:
				self.host_to_guest()
			except Exception as e:
				print(f'Couldnt read from socket {e}')
				self.sock.close()
				port_destroyed(self)
				if self.servermode:
					self.init_port_thread()
				return
		logging.info(f'Socket closed')
		self.sock.close()
		port_destroyed(self)
		if self.servermode:
			init_port_thread()
		
	def print_state(self):
		print(f'Send ptr {self.sendptr}\n recv ptr {self.recvptr} \n sbuf {self.sbuf}')
		
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
		
	def send_ack(self):
		if self.est:
			payload=make_port_payload(self.mode, self.servermode, self.hostport, self.guestport, self.recvptr, False, b'')
			self.send_payload(self.guestnac, payload)
			
	def process_ack(self, seqnum):
		mode, servermode, sourceport, destport, currseqnum, payloadpack, data=process_payload(self.sbuf[0]['data'])

		if seqnum==currseqnum:
			self.sbuf.pop(0)
			send_curr_payload()
			
	def send_curr_payload(self):
		if self.est and self.sbuf is not None and len(self.sbuf)>0:
			self.send_payload(self.guestnac, self.sbuf[0]['data'])
			
		self.print_state()
			
	def retry_loop(self):
		while self.est:
			try:
				with self.port_lock:
					self.send_ack()
					self.send_curr_payload()
					
			except Exception as e:
				logging.info(f'Error in port retry loop proxy {e}')
			time.sleep(0.8)
			
	def cleanup_loop(self):
		while self.est:
			try:
				if len(self.sbuf)>0:
					lastsend=self.sbuf[0]['time']
					if not check_valid_entry(lastsend, expiry=10):
						self.sbuf=[]
						self.est=False
			except Exception as e:
				logs.error(f'Error in port proxy cleanup {e}')
		
	def init_port(self):
		self.sock=socket.socket(socket.AF_INET, self.opt)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		if self.mode:
			if self.servermode:
				self.sock.bind(('0.0.0.0', self.ephemeral))
				self.sock.listen()
				conn, addr=self.sock.accept()
				self.connobj=conn
				hostip, port=addr
				logging.info(f'Connection active to {hostip}, {port}')
				self.host=port
				self.hostport=uuid_bytes(str(uuid.uuid4()))
			else:
				self.sock.connect((proxyhost, self.host))
				self.connobj=self.sock
				logging.info(f'Connected {self.connobj}')
				
		else:
			self.sock.bind(('0.0.0.0', self.ephemeral))			
			self.connobj=ConnectionObject(self.udp_send, self.udp_recv)
			if self.servermode:
				self.hostport=None
				data=self.udp_recv(1024)
				payload=make_port_payload(self.mode, self.servermode, self.hostport, self.guestport, data)
				self.send_payload(self.guestnac, payload)
				
		
		self.est=True
		proxy_thread=threading.Thread(target=self.listen_loop)
		proxy_thread.start()
		port_established(self)
		if self.first_payload and len(self.first_payload)>0:
			self.guest_to_host(0, self.first_payload)
		self.first_payload=None
		proxy_retry_thread=threading.Thread(target=self.retry_loop)
		proxy_retry_thread.start()
		proxy_cleanup_thread=threading.Thread(target=self.cleanup_loop)
		proxy_cleanup_thread.start()
		
	def init_port_thread(self):
		init_port_thread=threading.Thread(target=self.init_port)
		init_port_thread.start()
		
