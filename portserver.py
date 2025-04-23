from portutils import *
from portproxy import *
import logging


def process_port_payload_from_tunnel(nac, payload, send_payload):
	global socket_list
	mode, servermode, sourceport, destport, data=process_payload(payload)
	socketid=get_socket_id(nac, sourceport)
	if not check_socket_exists(socketid):
		port_socket=PortProxy(destport, sourceport, nac, mode, not serverport, 0, data, send_payload)
		port_socket.init_port_thread()
	else:
		get_socket_from_list(socketid).guest_to_host(data)
		
def create_proxy_port(listenport, destport, destnac, send_payload):
	mode=True
	serverport=True
	port_socket=PortProxy(b'', make_port_bytes(destport), destnac, mode, serverport, listenport, b'', send_payload)
	port_socket.init_port_thread()