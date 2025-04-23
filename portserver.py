from portutils import *
from portproxy import *
import logging


def process_port_payload_from_tunnel(nac, payload):
	global socket_list
	mode, servermode, sourceport, destport, data=process_payload(payload)
	socketid=get_socket_id(nac, sourceport)
	if not check_socket_exists(socketid):
		port_socket=PortProxy(destport, sourceport, nac, mode, not serverport, 0, data)
		port_socket.init_port_thread()
	else:
		get_socket_from_list(socketid).guest_to_host(data)
		
def create_proxy_port(listenport, destport, destnac):
	mode=True
	serverport=True
	port_socket=PortProxy(b'', destport, destnac, mode, serverport, listenport, b'')
	port_socket.init_port_thread()