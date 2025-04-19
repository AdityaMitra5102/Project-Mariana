import random
import uuid
import socket
import json
import logging
import os
import time
import base64
import threading

from crypto import *
from utils import *
from userops import *
from packets import *
from nodediscoveryutils import *

############################# INIT SYSTEMS #############################

filepath=os.getcwd()

trackerfile='trackers.json'
configfile='config.json'
knownsys='knownsys.json'
privkeyfile='privatekey.pem'

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s') #, filename='pqi.log', filemode='a')
logs=logging.getLogger('mariana')

routerstart='routinginfo:'
trackerstart='trackerinfo:'

cam_table={}
cam_table_lock=threading.Lock()

routing_table={}
routing_table_lock=threading.Lock()

trackers=[]
trackers_lock=threading.Lock()

known_machines={}

packet_buffer={}
packet_buffer_lock=threading.Lock()

privkey=None

sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

config={'nac':'', 'port':0}

try:
	fl=open(os.path.join(filepath, configfile), 'r')
	fileconf=json.load(fl)
	fl.close()
	config['nac']=fileconf['nac']
	config['port']=fileconf['port']
	sock.bind(('0.0.0.0', config['port']))
except:
	logs.warning('Config file not found or port unavailable. Creating...')
	if config['nac']=='':
		config['nac']=str(uuid.uuid4())
	port_create_fail=True
	port=0
	while port_create_fail:
		port=random.randint(1024, 2048)
		try:
			sock.bind(('0.0.0.0', port))
			port_create_fail=False
			config['port']=port
		except:
			logs.warning(f'Port {port} unavailable. Retrying with another.')
	fl=open(os.path.join(filepath, configfile), 'w')
	fl.write(json.dumps(config))
	fl.close()
	logs.info('Config file written')
	
			
logs.info(f'Binded to port {config['port']}')

try:
	fl=open(os.path.join(filepath, knownsys), 'r')
	known_machines=json.load(fl)
	fl.close()
	logs.info('Known machines list loaded')
except:
	logs.info('Known machines list not found. Client will learn new machines.')
	
try:
	fl=open(os.path.join(filepath, trackerfile), 'r')
	trackers=json.load(fl)
	fl.close()
	logs.info('Trackers loaded')
except:
	logs.info('Trackers not found. May not be able to connect to network.')
	
try:
	fl=open(os.path.join(filepath, privkeyfile), 'rb')
	privkey=fl.read()
	fl.close()
	logs.info('Private key loaded')
except:
	logs.warning('Private key not found. Generating keypair.')
	privkey=generate_keypair()
	fl=open(os.path.join(filepath, privkeyfile), 'wb')
	fl.write(privkey)
	fl.close()
	logs.info('Private key generated')

selfpubkey=get_pub_key(privkey)
self_tracker_state=str(uuid.uuid4())
self_public=False

############################# Layer 2 Transfers #############################

def add_to_cam(nac, ip, port):
	currtime=get_timestamp()
	if nac==config['nac']:
		logs.warning('Not adding self NAC to CAM Table.')
		return
		
	if nac in cam_table:
		logs.warning(f'NAC {nac} Already exists in CAM Table. Overwriting.')
	with cam_table_lock:
		cam_table[nac]={}
		cam_table[nac]['ip']=ip
		cam_table[nac]['port']=port
		cam_table[nac]['time']=currtime
	
def send_to_host(msg, nac):
	if nac not in cam_table:
		logs.error('NAC not in CAM Table. Packet dropped')
	ip=cam_table[nac]['ip']
	port=cam_table[nac]['port']
	sock.sendto(msg, (ip, port))
	
############################# Layer 3 Transfers #############################
	
def add_to_routing(nac, hopcount, next_nac, pubkey):
	if nac==config['nac']:
		logs.warning('Not adding own NAC to routing table')
		return
	currtime=get_timestamp()
	if nac in routing_table:
		logs.warning(f'NAC {nac} Already exists in Routing Table.')
		if check_valid_entry(routing_table[nac]['time']) and routing_table[nac]['hop_count']<hopcount:
			logs.info('Shorter path exists. Route unchanged. If this route is invalid, it will expire in 60 seconds')
			return
	with routing_table_lock:
		routing_table[nac]={}
		routing_table[nac]['hop_count']=hopcount
		routing_table[nac]['next_hop']=next_nac
		routing_table[nac]['pubkey']=pubkey
		routing_table[nac]['time']=currtime
	
def send(msg, nac, retry=0):
	
	if retry>3:
		logs.error("Max retry reached. Dropping packet.")
	if nac not in routing_table:
		logs.warning(f'Node {nac} not found in Routing table. Packet will be dropped after 3 retries after 30 seconds each. Retry {retry}')
		time.sleep(30)
		send(msg, nac, retry=retry+1)
		return
		
	if routing_table[nac]['hop_count']==0:
		logs.info('Hop count zero, forwarding to Layer 2 functions. Node directly connected.')
		send_to_host(msg, nac)
	else:
		if nac!=config['nac']:
			logs.info('Forwarding to next hop relay node')
			send(msg, routing_table[nac]['next_hop'])
			
############################# Tracker management #############################

def add_to_tracker(ip, port):
	trackerid=f'{ip}:{port}'
	if trackerid in trackers:
		logs.info('Tracker already present. Not adding')
		return False
	tracker={'ip': ip, 'port': port}
	with trackers_lock:
		trackers[trackerid]=tracker
	save_tracker_list()
	send_conn_req(ip, port)
	return True
	
def save_tracker_list():
	try:
		fl=open(os.path.join(filepath, trackerfile), 'w')
		fl.write(json.dumps(trackers))
		fl.close()
		logs.info('Trackers saved')
	except:
		logs.info('Trackers not saved. Trackers may be reset during system restart.')

		
############################# Process received packet #############################

def process_packet(packet, ip, port):
	try:
		source_nac=uuid_str(packet[:16])
		flag=packet[16]
		logs.info(f'Packet from {source_nac} flag {flag}')
		if flag==3: #Payload packet
			dest_nac=uuid_str(packet[17:33])
			if dest_nac == config['nac']: #Packet for me
				logs.info(f'Received packet for f{dest_nac}. Self processing.')
				process_self_packet(packet)
			else:
				logs.info(f'Received packet for f{dest_nac}. Forwarding')
				send(packet, dest_nac) #Forward to destination
		else:
			process_special_packet(packet, ip, port)
	except:
		logs.warn('Packet out of format. Ignoring')
		
def process_special_packet(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	flag=packet[16]
	if flag==0:
		process_conn_req(packet, ip, port)
	if flag==1:
		process_conn_accept(packet, ip, port)
	if flag==2:
		process_conn_reject(packet, ip, port)
	if flag==9:
		process_self_discovery(packet, ip, port)
		
def process_self_discovery(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	flag=packet[16]
	temp_state=uuid_str(packet[17:])
	if tempstate==self_tracker_state:
		logging.info('This system is routable. Promoting to tracker.')
		add_to_tracker(get_public_ip, config['port'])
		self_public=True
		
def process_conn_req(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	if source_nac==config['nac']:
		return
	flag=packet[16]
	if not check_valid_conn(source_nac, ip, port):
		logs.warn(f'Connection initiated by blacklisted machine {source_nac} {ip}:{port}. Rejected.')
		send_conn_reject(nac, ip, port)
		return
	logs.info(f'Connection inititated from {source_nac} {ip}:{port}. Accepting.')
	src_pubkey=packet[17:]
	add_to_cam(source_nac, ip, port)
	add_to_routing(source_nac, 0, None, src_pubkey)
	send_conn_accept(source_nac)
		
def process_conn_accept(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	logs.info(f'Connection accepted by node {source_nac} at {ip}:{port}')
	src_pubkey=packet[17:]
	add_to_cam(source_nac, ip, port)
	add_to_routing(source_nac, 0, None, src_pubkey)
	
def process_conn_reject(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	if source_nac in cam_table and cam_table[source_nac]['ip']==ip and cam_table[source_nac]['port']==port:
		logs.warn(f'Connection terminated by {source_nac}')
		cam_table.pop(source_nac)
		routing_table.pop(source_nac)
	else:
		logs.warn(f'Connection not made to {source_nac} at {ip}:{port}')
		
def process_self_packet(packet):
	source_nac=uuid_str(packet[:16])
	flag=packet[16]
	dest_nac=uuid_str(packet[17:33])
	seqbytes=packet[33:37]
	seqnum=int.from_bytes(seqbytes, 'big')
	maxseqbytes=packet[37:41]
	maxseq=int.from_bytes(maxseqbytes, 'big')
	sessionbytes=packet[41:57]
	sess=uuid_str(sessionbytes)
	payload=packet[57:]
	
	with packet_buffer_lock:
		if sess not in packet_buffer:
			packet_buffer[sess]={}
			packet_buffer[sess]['source_nac']=source_nac
			packet_buffer[sess]['maxseq']=maxseq
			packet_buffer[sess]['received']=0
			logs.info(f'Receiving for session {sess} from {source_nac}')
		
		packet_buffer[sess][seqnum]=payload
		packet_buffer[sess]['received']=packet_buffer[sess]['received']+1
		logs.info(f'Received packet {seqnum} of {maxseq} for session {sess}')
		
	if packet_buffer[sess]['received']==packet_buffer[sess]['maxseq']+1:
		process_encrypted_payload(sess)
		
def process_encrypted_payload(sess):
	logs.info(f'Received full packet for {sess}')
	payload_buffer=packet_buffer[sess][0]
	for ctr in range(1, packet_buffer[sess]['maxseq']+1):
		payload_buffer=payload_buffer+packet_buffer[sess][ctr]
	payload=payload_decrypt(payload_buffer, privkey)
	source_nac=packet_buffer[sess]['source_nac']
	process_payload(source_nac, payload)

def process_incoming_routing(source_nac, payload):
	logs.info(f'Received routing information from {source_nac}')
	payload=payload[len(routerstart):].decode()
	routinginfo=json.loads(payload)
	for nac in routinginfo:
		add_to_routing(nac, routinginfo[nac]['hop_count']+1, source_nac, base64.b64decode(routinginfo[nac]['pubkey'].encode()))

def process_incoming_tracker(source_nac, payload):
	logs.info(f'Received tracker information from {source_nac}')
	payload=payload[len(trackerstart):].decode()
	trackerinfo=json.loads(payload)
	for tracker in trackerinfo:
		add_to_tracker(tracker['ip'], tracker['port'])

	
def process_payload(source_nac, payload):
	logs.info(f'Received communication from {source_nac} payload.')
	if payload.startswith(routerstart.encode()):
		process_incoming_routing(source_nac, payload)
		return
	if payload.startswith(trackerstart.encode()):
		process_incoming_tracker(source_nac, payload)
		return
	try:
		resp=user_response(source_nac, payload)
		if resp is not None:
			send_payload(source_nac, resp)
	except:
		logs.info('Some error occured while processing output')

############################# Send packets #############################
def send_conn_accept(nac):
	packet=gen_conn_accept(config['nac'], selfpubkey)
	send_to_host(packet, nac)
	
def send_conn_reject(nac, ip, port):
	packet=get_conn_reject(config['nac'])
	sock.sendto(packet, (ip, port))

def send_conn_req(ip, port):
	#logs.info(f'Sending connection request to node at {ip}:{port}')
	packet=gen_conn_req(config['nac'], selfpubkey)
	sock.sendto(packet, (ip, port))
	
def send_payload(nac, payload, retry=0):
	if nac not in routing_table:
		if retry>=3:
			logs.error(f'Node {nac} not found. Dropping packet.')
			return
		logs.error(f'Node {nac} not known. Wait for routing table updates. Retrying 3 times in 30 secs.')
		send_payload(nac, payload, retry=retry+1)
		return
	packet_frags=gen_payload_seq(config['nac'], nac, payload, routing_table[nac]['pubkey'])
	for frag in packet_frags:
		send(frag, nac)
		
def send_routing():
	routinginfo={}
	for nac in routing_table:
		routinginfo[nac]={}
		routinginfo[nac]['hop_count']=routing_table[nac]['hop_count']
		routinginfo[nac]['pubkey']=base64.b64encode(routing_table[nac]['pubkey']).decode()
		
	payload=routerstart+json.dumps(routinginfo)
	for nac in cam_table:
		send_payload(nac, payload.encode())

def send_tracker():
	trackerinfo={}
	for tracker in trackers:
		trackerinfo[tracker]={}
		trackerinfo[tracker]['ip']=trackerinfo[tracker]['ip']
		trackerinfo[tracker]['port']=trackerinfo[tracker]['port']
				
	payload=trackerstart+json.dumps(trackerinfo)
	for nac in cam_table:
		send_payload(nac, payload.encode())


############################# Local node discovery #############################		
		
def local_node_discovery():
	logs.info('Attempting local node discovery')
	baddrs=get_baddr()
	for bcast in baddrs:
		for port in range(1024, 2048):
			try:
				send_conn_req(bcast, port)

			except:
				pass

############################# Tracker discovery #############################		

def perform_self_discovery():
	pub_ip=get_public_ip()
	self_tracker_state=str(uuid.uuid4())
	packet=gen_tracker_discovery(config['nac'], self_tracker_state)
	sock.sendto(packet, (pub_ip, config['port']))

		
############################# Threading loops #############################		
		
def self_discovery_loop():
	while not self_public:
		try:
			logs.info('Trying self discovery')
			perform_self_discovery()
		except:
			logs.error('Self discovery failed')
		time.sleep(90)
		
def send_routing_loop():
	while True:
		try:
			logs.info('Sharing routing information with immediate nodes')
			send_routing()
		except:
			logs.error('Error occurred while sending routing information')
		time.sleep(40)

def send_tracker_loop():
	while True:
		try:
			logs.info('Sharing tracker information with immediate nodes')
			send_tracker()
		except:
			logs.error('Error occurred while sending tracker information')
		time.sleep(70)

		
def receive_packet_loop():
	while True:
		try:
			data, addr=sock.recvfrom(1500)
			src_ip, src_port=addr
			logs.info(f'Received packet from {src_ip}:{src_port}')
			#process_packet(data, src_ip, src_port)
			process_packet_thread=threading.Thread(target=process_packet, args=(data, src_ip, src_port,))
			process_packet_thread.start()
		except Exception as e:
			logs.error(f'Error occurred while receiving packet {e}')
		
def conn_keepalive_loop():
	while True:
		try:
			for tracker in trackers:
				tracker_ip=tracker['ip']
				tracker_port=tracker['port']
				send_conn_req(tracker_ip, tracker_port)
		except Exception as e:
			logs.error("Error occurred while opening tracker {e}")
		time.sleep(15)	

def local_node_discovery_loop():
	while True:
		try:
			local_node_discovery()
		except:
			logs.error('Local node discovery failed')
		time.sleep(15)
			
		
def init_threads():
	routing_thread=threading.Thread(target=send_routing_loop)
	tracker_thread=threading.Thread(target=send_tracker_loop)
	receive_thread=threading.Thread(target=receive_packet_loop)
	keepalive_thread=threading.Thread(target=conn_keepalive_loop)
	discovery_thread=threading.Thread(target=local_node_discovery_loop)
	self_discovery_thread=threading.Thread(target=self_discovery_loop)
	routing_thread.start()
	tracker_thread.start()
	receive_thread.start()
	keepalive_thread.start()
	discovery_thread.start()
	self_discovery_thread.start()
		
if __name__=='__main__':
	init_threads()