from utils import *
import logging
header='portproxy:'

buflim=0xffffffff

socket_list={}

def port_established(port):
	global socket_list
	socket_list[port.get_port_proxy_id()]=port
	logging.info('Port established')
	
def port_destroyed(port):
	global socket_list
	port.sbuf={}
	port.dummybuf={}
	socket_list.pop(port.get_port_proxy_id())
	logging.info('Port destroyed')

def get_socket_from_list(id):
	return socket_list[id]
	
def check_socket_exists(id):
	return id in socket_list

def make_proxy_flag(mode, servermode, payloadpack):
	return (int.from_bytes(bytes([payloadpack]))*4+int.from_bytes(bytes([mode]))*2+int.from_bytes(bytes([servermode]))).to_bytes(1)
	
def make_port_bytes(port):
	return port.to_bytes(16)

def make_port_payload(mode, servermode, sourceport, destport, seqnum, flag, data):
	payload=header.encode()
	payload+=make_proxy_flag(mode, servermode, flag)
	payload+=sourceport
	payload+=destport
	payload+=seqnum.to_bytes(4, 'big')
	payload+=data
	return payload
	
def process_payload(payload):
	if not payload.startswith(header.encode()):
		return None
	
	payload=payload[len(header.encode()):]
	flag=payload[0]
	servermode=(flag%2)==1
	mode=(flag//2)==1
	payloadpack=(flag//4)==1
	sourceport=payload[1:17]
	destport=payload[17:33]
	seqnum=int.from_bytes(payload[33:37])
	data=payload[37:]
	
	return mode, servermode, sourceport, destport, seqnum, payloadpack, data
	
def get_socket_id(nac, port):
	return uuid_bytes(nac)+port
