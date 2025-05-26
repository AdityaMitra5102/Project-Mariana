########################### Marianas Qubit ##########################
# The Internet of Freedom
# Marianas Qubit is an alternate internet stack built on top of the internet
# with the mindset of counter surveilliance
# "Ultimately, saying that you don't care about privacy because you have nothing to hide is no different from saying you don't care about freedom of speech because you have nothing to say." - Ed. Snowden
#####################################################################


import random
import uuid
import socket
import json
import logging
import os
import time
import base64
import threading
import pathlib

from gitutils import *
from crypto import *
from utils import *
from userops import *
from packets import *
from cargoship import *
from nodediscoveryutils import *

############################# INIT SYSTEMS #############################

filepath = os.path.join(os.getenv('APPDATA') if os.name == 'nt' else os.path.expanduser('~/.config'), 'Mariana')

pathlib.Path(filepath).mkdir(parents=True, exist_ok=True)

trackerfile='trackers.json'
configfile='config.json'
knownsys='knownsys.json'
privkeyfile='privatekey.pem'
phonebookfile='phonebook.json'
phonebooksecurityfile='phonebooksec.json'
securityconfigfile='security.json'

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s') #, filename='pqi.log', filemode='a')
logs=logging.getLogger('mariana')

routerstart='routinginfo:'
trackerstart='trackerinfo:'

securityconfigdefault={'web_server_allow': False, 'clearnet_exit_proxy': True, 'port_fw_allow':[], 'cargo_ship_allow_exec':True, 'allow_mismatch_contact':False, 'allow_unknown_nac':True, 'desc': 'Mariana Node'}
securityconfig=securityconfigdefault

stat={'packets_sent':0, 'packets_received':0, 'packets_relayed':0, 'payloads_sent':0, 'payloads_received':0, 'routing_sent':0, 'routing_received':0, 'total_connected_nodes':0, 'directly_connected_nodes':0, 'known_public_nodes':0, 'memory_used_bytes':0, 'uptime_seconds':0}

boot_time=get_timestamp()

unverified_neighbors_table={}
unverified_neighbors_table_lock=threading.Lock()

cam_table={}
cam_table_lock=threading.Lock()

routing_table={}
routing_table_lock=threading.Lock()

trackers={}
trackers_lock=threading.Lock()

packet_buffer={}
packet_buffer_lock=threading.Lock()

sending_buffer={}
sending_buffer_lock=threading.Lock()

phonebook={}
phonebookpub={}

privkey=None

sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

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
			
	if is_persist():
		fl=open(os.path.join(filepath, configfile), 'w')
		fl.write(json.dumps(config))
		fl.close()
		logs.info('Config file written')
	
			
logs.info(f'Binded to port {config["port"]}')

try:
	fl=open(os.path.join(filepath, securityconfigfile), 'r')
	securityconfig=json.load(fl)
	for tempx in securityconfigdefault:
		if tempx not in securityconfig:
			securityconfig[tempx]=securityconfigdefault[tempx]
			save_securityconfig(securityconfig)
			
	fl.close()
	logs.info('Security config loaded')
except:
	if is_persist():
		fl=open(os.path.join(filepath, securityconfigfile), 'w')
		fl.write(json.dumps(securityconfig, indent=4))
		fl.close()
	logs.info('Security config not found. Writing defaults')

try:
	fl=open(os.path.join(filepath, phonebookfile), 'r')
	phonebook=json.load(fl)
	fl.close()
	logs.info('Phonebook loaded')
except:
	logs.info('Phonebook not found.')
	
try:
	fl=open(os.path.join(filepath, phonebooksecurityfile), 'r')
	temp_pb=json.load(fl)
	fl.close()
	for nac in temp_pb:
		phonebookpub[nac]=bytes.fromhex(temp_pb[nac])
	logs.info('Phonebook public keys loaded')
except:
	logs.info('Phonebook public key file not found')

	
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
	if is_persist():
		fl=open(os.path.join(filepath, privkeyfile), 'wb')
		fl.write(privkey)
		fl.close()
	logs.info('Private key generated')

selfpubkey=get_pub_key(privkey)
self_tracker_state=str(uuid.uuid4())
self_public=False

trackers=get_trackers_git(trackers)

l2retry=10
l2retrydelay=0.001
############################# Security Config #############################

def save_securityconfig(updatedconfig):
	global securityconfig
	securityconfig=updatedconfig
	if is_persist():
		fl=open(os.path.join(filepath, securityconfigfile), 'w')
		fl.write(json.dumps(securityconfig, indent=4))
		fl.close()
		logs.info('Writing security config')



############################# Phonebook #############################

phonebook_rev_cache={}
pubkey_match_cache={}

def is_nac_saved(nac):
	rev_nac=phone_book_reverse_lookup(nac)
	return nac!=rev_nac

def get_contact(humanalias):
	if humanalias in phonebook:
		return phonebook[humanalias]
	else:
		return None
		
def phone_book_reverse_lookup(nac):
	if nac in phonebook_rev_cache:
		return phonebook_rev_cache[nac]
	for humanalias in phonebook:
		if phonebook[humanalias]==nac:
			phonebook_rev_cache[nac]=humanalias
			return humanalias
	return nac
		
def save_contact(humanalias, nac):
	if humanalias in phonebook:
		logs.error(f'{humanalias} already exists in phonebook. Not saved')
		return False
	phonebook[humanalias]=nac
	phonebookpub[humanalias]=routing_table[nac]['pubkey']
	logs.info(f'{humanalias} saved')
	save_phonebook_file()
	write_phonebook_pub()
	return True
	
def check_phonebook_saved_nac(nac):
	return nac!=phone_book_reverse_lookup(nac)
	
def update_contact_pub(humanalias):
	if humanalias not in phonebook:
		return False
	nac=get_contact(humanalias)
	delete_contact(humanalias)
	
	save_contact(humanalias, nac)
	return True
	
def delete_contact(humanalias):
	if humanalias not in phonebook:
		return False
	nac=phonebook[humanalias]
	if nac in phonebook_rev_cache:
		phonebook_rev_cache.pop(nac)
	phonebook.pop(humanalias)
	phonebookpub.pop(humanalias)
	logs.info(f'{humanalias} deleted')
	save_phonebook_file()
	write_phonebook_pub()
	return True
	
def save_phonebook_file():
	if is_persist():
		fl=open(os.path.join(filepath, phonebookfile), 'w')
		fl.write(json.dumps(phonebook))
		fl.close()
	logs.info('Phonebook saved')	

def get_whole_phonebook():
	return phonebook
	
	
def write_phonebook_pub():
	temp={}
	for name in phonebookpub:
		temp[name]=phonebookpub[name].hex()
	if is_persist():		
		fl=open(os.path.join(filepath, phonebooksecurityfile), 'w')
		fl.write(json.dumps(temp))
		fl.close()
	
def check_contacts_pubkey_match(humanalias):
	nac=get_contact(humanalias)
	if nac not in routing_table:
		return True
	pubkey_match_cache[nac]=phonebookpub[humanalias]==routing_table[nac]['pubkey']
	return pubkey_match_cache[nac]
	
def get_contacts_verif():
	temp={}
	for humanalias in phonebook:
		temp[humanalias]=check_contacts_pubkey_match(humanalias)
		
	return temp

############################# Stats #############################

def gen_stats():
	stat['total_connected_nodes']=len(routing_table)
	stat['directly_connected_nodes']=len(cam_table)
	stat['known_public_nodes']=len(trackers)
	stat['memory_used_bytes']=psutil.Process().memory_info().rss
	stat['uptime_seconds']=get_timestamp()-boot_time

def get_stats():
	gen_stats()
	return stat

############################# Layer 1 Transfers #############################

def l1sendto(data, addr, tempsock=None):
	data=data+crc32(data)
	if tempsock is None:
		sock.sendto(data, addr)
	else:
		tempsock.sendto(data,addr)

def l1recvfrom(n):
	data, addr=sock.recvfrom(n)
	crc=data[-4:]
	data=data[:-4]
	if crc32(data)==crc:
		return data, addr
	logs.info(f'CRC Mismatch, packet dropped from {addr}')
	return None, None

############################# Neighbor verification #############################

def add_to_unverified_neighbor(nac, ip, port, pubkey, desc):
	if nac in cam_table and nac in routing_table:
		if ip==cam_table[nac]['ip'] and port==cam_table[nac]['port'] and pubkey==routing_table[nac]['pubkey']:
			add_neighbor(nac, ip, port, pubkey, desc)

	with unverified_neighbors_table_lock:
		logs.info(f'Adding unverified neighbor {nac}. Verifying.')
		if nac not in unverified_neighbors_table:
			unverified_neighbors_table[nac]={}
		unverified_neighbors_table[nac]['ip']=ip
		unverified_neighbors_table[nac]['port']=port
		unverified_neighbors_table[nac]['pubkey']=pubkey
		shared_secret, ciphertext=encaps(pubkey)
		unverified_neighbors_table[nac]['challenge']=shared_secret
		unverified_neighbors_table[nac]['time']=get_timestamp()
		unverified_neighbors_table[nac]['desc']=desc
		packet=gen_verif_init(config['nac'], ciphertext)
		for xx in range(l2retry):
			time.sleep(l2retrydelay)
			l1sendto(packet, (ip, port))
		
def verify_neighbor(nac, secret):
	if nac not in unverified_neighbors_table:
		return
	if secret==unverified_neighbors_table[nac]['challenge']:
			logs.info(f'Verified neighbor {nac}.')
			with unverified_neighbors_table_lock:
				add_neighbor(nac, unverified_neighbors_table[nac]['ip'],unverified_neighbors_table[nac]['port'],unverified_neighbors_table[nac]['pubkey'], unverified_neighbors_table[nac]['desc'])
		
def verify_self_as_neighbor(nac, ciphertext):
	if nac not in unverified_neighbors_table:
		return
	logs.info(f'Verifying myself to {nac}')
	resp=decaps(privkey, ciphertext)
	packet=gen_verif_complete(config['nac'], resp)
	for xx in range(l2retry):
		time.sleep(l2retrydelay)
		l1sendto(packet, (unverified_neighbors_table[nac]['ip'], unverified_neighbors_table[nac]['port']))
			
		

############################# Layer 2 Transfers #############################

def add_neighbor(nac, ip, port, pubkey, desc):
	add_to_cam(nac,ip, port)
	add_to_routing(nac, 0, None, pubkey, desc)

def add_to_cam(nac, ip, port):
	global cam_table
	currtime=get_timestamp()
	if nac==config['nac']:
		logs.warning('Not adding self NAC to CAM Table.')
		return
		
	if nac in cam_table:
		logs.warning(f'NAC {nac} Already exists in CAM Table. Overwriting.')
	else:
		with cam_table_lock:
			cam_table[nac]={}
			cam_table[nac]['lastrouting']=0
		
	with cam_table_lock:
		cam_table[nac]['ip']=ip
		cam_table[nac]['port']=port
		cam_table[nac]['time']=currtime
	
def send_to_host(msg, nac):
	if nac not in cam_table:
		logs.error('NAC not in CAM Table. Packet dropped')
	ip=cam_table[nac]['ip']
	port=cam_table[nac]['port']
	l1sendto(msg, (ip, port))
	stat['packets_sent']+=1
	
	
############################# Layer 3 Transfers #############################
	
def add_to_routing(nac, hopcount, next_nac, pubkey, desc):
	global routing_table
	if hopcount>20:
		if nac in routing_table:
			if routing_table[nac]['hop_count']>15:
				routing_table.pop(nac)
		return
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
		routing_table[nac]['desc']=desc
	logs.info(f'{nac} added to routing table')
	send_routing()
	
	
def send(msg, nac, retry=0):
	if retry>3:
		logs.error("Max retry reached. Dropping packet.")
		return
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

def add_to_tracker(ip, port, gitannounce=False):
	global trackers
	trackerid=f'{ip}:{port}'
	if trackerid in trackers:
		logs.info('Tracker already present. Not adding')
		return False
	trackers=get_trackers_git(trackers)
	if trackerid in trackers:
		logs.info('Tracker already present. Not adding')
		return False
	tracker={'ip': ip, 'port': port}
	with trackers_lock:
		trackers[trackerid]=tracker
		if gitannounce:
			post_comment(json.dumps(tracker))
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
	if True:
		source_nac=uuid_str(packet[:16])
		flag=packet[16]
		logs.info(f'Packet from {source_nac} flag {flag}')
		stat['packets_received']+=1
		if flag>=3 and flag<7: #Payload packet
			dest_nac=uuid_str(packet[17:33])
			if dest_nac == config['nac']: #Packet for me
				logs.info(f'Received packet for f{dest_nac}. Self processing.')
				process_self_packet(packet)
			else:
				logs.info(f'Received packet for f{dest_nac}. Forwarding')
				stat['packets_relayed']+=1
				send(packet, dest_nac) #Forward to destination
		
		process_special_packet(packet, ip, port)
	#except Exception as e:
	#	logs.warn(f'Packet out of format. Ignoring {e}')
		
def process_special_packet(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	flag=packet[16]
	if flag==0:
		process_conn_req(packet, ip, port)
	if flag==1:
		process_conn_accept(packet, ip, port)
	if flag==2:
		process_conn_reject(packet, ip, port)
	if flag==7:
		process_verif_init(packet, ip, port)
	if flag==8:
		process_verif_complete(packet, ip, port)
	if flag==9:
		process_self_discovery(packet, ip, port)
		
def process_self_discovery(packet, ip, port):
	global self_tracker_state
	global self_public
	source_nac=uuid_str(packet[:16])
	flag=packet[16]
	temp_state=uuid_str(packet[17:])
	if temp_state==self_tracker_state:
		logging.info('This system is routable. Promoting to tracker.')
		add_to_tracker(get_public_ip(), config['port'], True)
		self_public=True
		
def process_retransmission(packet):
	source_nac=uuid_str(packet[:16])
	flag=packet[16]
	dest_nac=uuid_str(packet[17:33])
	sess=uuid_str(packet[33:49])
	req=int.from_bytes(packet[49:], 'big')
	if sess in sending_buffer:
		pack=sending_buffer[sess]['packets'][req]
		send(pack, source_nac)
	
def process_full_ack(packet):
	source_nac=uuid_str(packet[:16])
	flag=packet[16]
	dest_nac=uuid_str(packet[17:33])
	sess=uuid_str(packet[33:49])
	with sending_buffer_lock:
		if sess in sending_buffer:
			sending_buffer.pop(sess)
			
def process_verif_init(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	if source_nac==config['nac']:
		return
	flag=packet[16]
	ciphertext=packet[17:]
	verify_self_as_neighbor(source_nac, ciphertext)
	
def process_verif_complete(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	if source_nac==config['nac']:
		return
	flag=packet[16]
	secret=packet[17:]
	verify_neighbor(source_nac, secret)
	
		
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
	src_pubkey=packet[17:817]
	src_desc=packet[817:]
	add_to_unverified_neighbor(source_nac, ip, port, src_pubkey, src_desc)
	send_conn_accept(source_nac)
		
def process_conn_accept(packet, ip, port):
	source_nac=uuid_str(packet[:16])
	logs.info(f'Connection accepted by node {source_nac} at {ip}:{port}')
	src_pubkey=packet[17:817]
	src_desc=packet[817:]
	add_to_unverified_neighbor(source_nac, ip, port, src_pubkey, src_desc)
		
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
	if flag==4:
		process_retransmission(packet)
		return
	if flag==5:
		process_full_ack(packet)
		return
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
			packet_buffer[sess]['time']=get_timestamp()
			packet_buffer[sess]['retry']=0
			
			logs.info(f'Receiving for session {sess} from {source_nac}')

		if seqnum not in packet_buffer[sess]:
			packet_buffer[sess][seqnum]=payload
			packet_buffer[sess]['received']=packet_buffer[sess]['received']+1
		logs.info(f'Received packet {seqnum} of {maxseq} for session {sess}')
		
	if packet_buffer[sess]['received']==packet_buffer[sess]['maxseq']+1:
		stat['payloads_received']+=1
		process_encrypted_payload(sess)
				
def process_encrypted_payload(sess):
	logs.info(f'Received full packet for {sess}')
	send_packet_ack(packet_buffer[sess]['source_nac'], sess)
	logs.info(f'Sending ACK for {sess}')
	
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
	routeadded=False
	for nac in routinginfo:
		if routinginfo[nac]['next_hop'] != config['nac']:
			if not check_valid_entry(cam_table[source_nac]['lastrouting'], expiry=20) or nac not in routing_table:
				add_to_routing(nac, routinginfo[nac]['hop_count']+1, source_nac, base64.b64decode(routinginfo[nac]['pubkey'].encode()), base64.b64decode(routinginfo[nac]['desc'].encode()))
				routeadded=True
		else:
			logging.info('Cyclic routing entry not added.')
	
	if routeadded:
		cam_table[source_nac]['lastrouting']=get_timestamp()
	else:
		logs.warn(f'Possible sybil attack. Announcement from {source_nac} dropped')

			
	stat['routing_received']+=1

def process_incoming_tracker(source_nac, payload):
	logs.info(f'Received tracker information from {source_nac}')
	payload=payload[len(trackerstart):].decode()
	trackerinfo=json.loads(payload)
	for tracker in trackerinfo:
		add_to_tracker(trackerinfo[tracker]['ip'], trackerinfo[tracker]['port'])

	
def process_payload(source_nac, payload):
	logs.info(f'Received communication from {source_nac} payload.')
	if payload.startswith(routerstart.encode()):
		process_incoming_routing(source_nac, payload)
		return
	if payload.startswith(trackerstart.encode()):
		process_incoming_tracker(source_nac, payload)
		return
	try:
		if not check_no_mitm(source_nac):
			logs.info(f'Possible MITM. Packet from {source_nac} dropped.')
			return
			
		if not securityconfig['allow_unknown_nac']:
			if not check_phonebook_saved_nac(nac):
				logs.info(f'Unknown NAC {nac} not allowed. Packet dropped.')
				return

			
		resp=user_response(source_nac, payload, send_payload, phone_book_reverse_lookup, securityconfig)
		if resp is not None:
			send_payload(source_nac, resp)
	except Exception as e:
		logs.info(f'Some error occured while processing output {e} ')

############################# Send packets #############################

def check_no_mitm(nac):
	if securityconfig['allow_mismatch_contact']:
		logs.info('Checking MITM bypassed by security policy.')
		return True
	if is_nac_saved(nac):
		humanalias=phone_book_reverse_lookup(nac)
		if not check_contacts_pubkey_match(humanalias):
			return False
		return True
	return True


def send_conn_accept(nac):
	packet=gen_conn_accept(config['nac'], selfpubkey, securityconfig['desc'])
	ip=unverified_neighbors_table[nac]['ip']
	port=unverified_neighbors_table[nac]['port']
	for xx in range(l2retry):
		time.sleep(l2retrydelay)
		l1sendto(packet, (ip, port))
	
def send_conn_reject(nac, ip, port):
	packet=get_conn_reject(config['nac'])
	for xx in range(l2retry):
		time.sleep(l2retrydelay)
		l1sendto(packet, (ip, port))

def send_conn_req(ip, port):
	#logs.info(f'Sending connection request to node at {ip}:{port}')
	packet=gen_conn_req(config['nac'], selfpubkey, securityconfig['desc'])
	for xx in range(l2retry):
		time.sleep(l2retrydelay)
		l1sendto(packet, (ip, port))
	
def send_payload(nac, payload, retry=0, core_data=False):
	if not core_data:
		if not check_no_mitm(nac):
			logs.info(f'Possible MITM to {nac}. Payload not sent.')
			return
			
		if not securityconfig['allow_unknown_nac']:
			if not check_phonebook_saved_nac(nac):
				logs.info(f'Unknown NAC {nac} not allowed. Payload not sent.')
				return
			
	if nac not in routing_table:
		if retry>=3:
			logs.error(f'Node {nac} not found. Dropping packet.')
			return
		logs.error(f'Node {nac} not known. Wait for routing table updates. Retrying 3 times in 30 secs.')
		send_payload(nac, payload, retry=retry+1, core_data=core_data)
		return
	packet_frags, sess=gen_payload_seq(config['nac'], nac, payload, routing_table[nac]['pubkey'])
	with sending_buffer_lock:
		sending_buffer[sess]={}
		sending_buffer[sess]['packets']=packet_frags
		sending_buffer[sess]['time']=get_timestamp()
	logs.info(f'Sending payload to {nac}')
	send(packet_frags[0], nac)
	for frag in packet_frags:
		send(frag, nac)
	stat['payloads_sent']+=1
		
def send_packet_ack(nac, session):
	packet=gen_full_ack(config['nac'], nac, session)
	send(packet, nac)
	
def send_retry_req(nac, sess, pack):
	packet=gen_retransmission_req(config['nac'], nac, sess, pack)
	send(packet, nac)
		
def send_routing():
	routinginfo={}
	for nac in routing_table:
		routinginfo[nac]={}
		routinginfo[nac]['hop_count']=routing_table[nac]['hop_count']
		routinginfo[nac]['pubkey']=base64.b64encode(routing_table[nac]['pubkey']).decode()
		routinginfo[nac]['next_hop']=routing_table[nac]['next_hop']
		routinginfo[nac]['desc']=base64.b64encode(routing_table[nac]['desc']).decode()
		
	payload=routerstart+json.dumps(routinginfo)
	for nac in cam_table:
		send_payload(nac, payload.encode(), core_data=True)
		stat['routing_sent']+=1

def send_tracker():
	trackerinfo={}
	for tracker in trackers:
		trackerinfo[tracker]={}
		trackerinfo[tracker]['ip']=trackers[tracker]['ip']
		trackerinfo[tracker]['port']=trackers[tracker]['port']
				
	payload=trackerstart+json.dumps(trackerinfo)
	for nac in cam_table:
		send_payload(nac, payload.encode(), core_data=True)


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
	global self_tracker_state
	pub_ip=get_public_ip()
	self_tracker_state=str(uuid.uuid4())
	packet=gen_tracker_discovery(config['nac'], self_tracker_state)
	tempsock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	l1sendto(packet, (pub_ip, config['port']), tempsock)

############################# Cleanup #############################

def unverified_neighbors_table_cleanup():
	temp=list(unverified_neighbors_table.keys())
	for nac in temp:
		if not check_valid_entry(unverified_neighbors_table[nac]['time']):
			with unverified_neighbors_table_lock:
				logs.info(f'Removing expired entry from Unverif neighbor table {nac}')
				unverified_neighbors_table.pop(nac)

def cam_table_cleanup():
	temp=list(cam_table.keys())
	for nac in temp:
		if not check_valid_entry(cam_table[nac]['time']):
			with cam_table_lock:
				logs.info(f'Removing expired entry from CAM table {nac}')
				cam_table.pop(nac)
				if nac in routing_table and not check_valid_entry(routing_table[nac]['time']):
					with routing_table_lock:
						logs.info(f'Removing expired entry from Routing table {nac}')
						routing_table.pop(nac)
				
def routing_table_cleanup():
	temp=list(routing_table.keys())
	for nac in temp:
		if not check_valid_entry(routing_table[nac]['time']):
			with routing_table_lock:
				logs.info(f'Removing expired entry from Routing table {nac}')
				routing_table.pop(nac)
				if nac in cam_table and not check_valid_entry(cam_table[nac]['time']):
					with cam_table_lock:
						logs.info(f'Removing expired entry from CAM table {nac}')
						cam_table.pop(nac)
				
def sending_buffer_cleanup():
	temp=list(sending_buffer.keys())
	for sess in temp:
		if not check_valid_entry(sending_buffer[sess]['time'], expiry=180):
			with sending_buffer_lock:
				sending_buffer.pop(sess)

############################# Retransmission #############################		

def find_missing_packets(sess):
	maxseq=packet_buffer[sess]['maxseq']
	missing_packs=[]
	packetnos=list(packet_buffer[sess].keys())
	to_remove=['source_nac', 'maxseq', 'received', 'time', 'retry']
	for r in to_remove:
		try:
			packetnos.remove(r)
		except:
			pass
	
	packetnos=sorted(packetnos)
	
	exp=0
	curr=0
	size=maxseq+1
	while exp<size and curr < len(packetnos):
		if packetnos[curr]==exp:
			exp+=1
			curr+=1
		else:
			missing_packs.append(exp)
			exp+=1
		
	while exp<size:
		missing_packs.append(exp)
		exp+=1
	return missing_packs 

def request_retransmission():
	temp=list(packet_buffer.keys())
	for sess in temp:
		if packet_buffer[sess]['retry']>100:
			with packet_buffer_lock:
				packet_buffer.pop(sess)
				return
		if not check_valid_entry(packet_buffer[sess]['time'], expiry=3):
			missing_packs=find_missing_packets(sess)
			for m in missing_packs:
				send_retry_req(packet_buffer[sess]['source_nac'], sess, m)
			packet_buffer[sess]['retry']+=1
			packet_buffer[sess]['time']=get_timestamp()			
				
			
		
############################# Threading loops #############################		
		
def self_discovery_loop():
	while not self_public:
		if not is_persist():
			break
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
		time.sleep(30)

		
def receive_packet_loop():
	while True:
		try:
			data, addr=l1recvfrom(1500)
			if data is None:
				continue
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
				tracker_ip=trackers[tracker]['ip']
				tracker_port=trackers[tracker]['port']
				send_conn_req(tracker_ip, tracker_port)
		except Exception as e:
			logs.error(f'Error occurred while opening tracker {e}')
		time.sleep(15)	

def local_node_discovery_loop():
	while True:
		try:
			local_node_discovery()
		except:
			logs.error('Local node discovery failed')
		time.sleep(15)
		
def retransmission_loop():
	while True:
		try:
			request_retransmission()
		except Exception as e:
			logs.error(f'Couldnt request retransmission {e}')
		time.sleep(3)
		
def cargoship_loop():
	while True:
		try:
			attempt_cargo_send(send_payload)
		except Exception as e:
			logs.error(f'Cargoship thread error {e}')
		time.sleep(5)
			
def cleanup_loop():
	while True:
		unverified_neighbors_table_cleanup()
		cam_table_cleanup()
		routing_table_cleanup()
		sending_buffer_cleanup()
		time.sleep(60)
		
def init_threads():
	save_tracker_list()
	routing_thread=threading.Thread(target=send_routing_loop)
	tracker_thread=threading.Thread(target=send_tracker_loop)
	receive_thread=threading.Thread(target=receive_packet_loop)
	keepalive_thread=threading.Thread(target=conn_keepalive_loop)
	discovery_thread=threading.Thread(target=local_node_discovery_loop)
	retransmission_thread=threading.Thread(target=retransmission_loop)
	self_discovery_thread=threading.Thread(target=self_discovery_loop)
	cargoship_thread=threading.Thread(target=cargoship_loop)
	cleanup_thread=threading.Thread(target=cleanup_loop)
	routing_thread.start()
	tracker_thread.start()
	receive_thread.start()
	keepalive_thread.start()
	discovery_thread.start()
	self_discovery_thread.start()
	retransmission_thread.start()
	cargoship_thread.start()
	cleanup_thread.start()
		
		
if __name__=='__main__':
	init_threads()
