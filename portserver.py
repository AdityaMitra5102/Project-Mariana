from portutils import *
from portproxy import *
import logging

socket_list={}

def port_established(port):
	global socket_list
	socket_list[port.get_port_proxy_id()]=port
	logging.info('Port established')
	
def port_destroyed(port):
	global socket_list
	socket_list.pop(port.get_port_proxy_id())
	logging.info('Port destroyed')

def process_port_payload_from_tunnel(nac, payload):
	global socket_list
	mode, servermode, sourceport, destport, data=process_payload(payload)
	socketid=get_socket_id(nac, sourceport)
	if socketid not in socket_list:
		port_socket=PortProxy(destport, sourceport, nac, mode, not serverport, 0, data)
		port_socket.init_port_thread()
	else:
		port_socket[socketid].guest_to_host(data)
		
def create_proxy_port(listenport, destport, destnac):
	mode=True
	serverport=True
	port_socket=PortProxy(b'', destport, destnac, mode, serverport, listenport, b'')
	port_socket.init_port_thread()