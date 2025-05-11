from portutils import *
from portproxy import *
import logging


def process_port_payload_from_tunnel(nac, payload, send_payload, securityconfig):
	global socket_list
	mode, servermode, sourceport, destport, seqnum, payloadpack, data=process_payload(payload)
	try:
		destportint= int.from_bytes(destport)
		if not (destportint in securityconfig['port_fw_allow'] or '*' in securityconfig['port_fw_allow']):
			logging.info('Port blocked. Packet dropped.')
			return
	except:
		pass
	socketid=get_socket_id(nac, sourceport)
	if not check_socket_exists(socketid):
		port_socket=PortProxy(destport, sourceport, nac, mode, not servermode, 0, data, send_payload)
		port_socket.init_port_thread()
	else:
		currsock=get_socket_from_list(socketid)
		if payloadpack:
			currsock.guest_to_host(seqnum, data)
		else:
			currsock.process_ack(seqnum)
		
		
def create_proxy_port(listenport, destport, destnac, mode, send_payload):
	serverport=True
	port_socket=PortProxy(b'', make_port_bytes(destport), destnac, mode, serverport, listenport, b'', send_payload)
	port_socket.init_port_thread()
