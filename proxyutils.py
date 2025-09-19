from utils import *
from portserver import *
from cargoship import *
from internals import *
import userops
import requests
import uuid
import json
import logging
import os
import time
import threading

header='mariana'
portheader='portproxy:'
trenchheader='trenchtalk'
cargoshipheader='cargo'

hostend='.mariana'

webpackets={}
trenchmsg=[]

serverhost='localhost'

def make_trench_payload(msg):
	return trenchheader.encode()+os.urandom(8)+msg.encode()
	
def get_trench_packet(payload):
	try:
		payload= payload[len(trenchheader):]
		uniqueid=payload[:8]
		payload=payload[8:].decode()
		return payload, uniqueid
	except Exception as e:
		logging.info('Error decoding Trench talk message')
		return 'Error decoding Trench talk message'
		

def make_payload_packet(session, flag, payload):
	packet=header.encode()
	packet=packet+uuid_bytes(session)
	packet=packet+flag_bytes(flag)
	packet=packet+payload.encode()
	return packet
	
def get_packet_payload(payload):
	payload=payload[len(header):]
	session=payload[:16]
	flag=payload[16]
	payload=payload[17:].decode()
	session=uuid_str(session)
	return session, flag, payload
	
def rewrite_content(content):
	content_bytes=content.replace(b'https:', b'http:')
	return content_bytes
	
def user_response(source_nac, payload, send_payload, phone_book_reverse_lookup, securityconfig):
	if payload.startswith(header.encode()):
		session, flag, payload=get_packet_payload(payload)
		if flag==1:
			webpackets[session]=payload
			return None
		else:
			if not securityconfig['web_server_allow']:
				logging.warning('Web server not allowed. Packet dropped.')
				return None
			params=json.loads(payload)
			url=requests.urllib3.util.parse_url(params['target_url'])
			tempscheme=url.scheme
			check_host=url.host
			tempserverhost=serverhost
			if not check_host.endswith(hostend):
				if not securityconfig['clearnet_exit_proxy']:
					logging.warning('Clearnet exit proxy not allowed. Dropping packet')
					return
				tempserverhost=check_host
				try:
					respx=requests.get(f'https://{tempserverhost}', timeout=3,  proxies={'http':None, 'https':None})
					tempscheme='https'
				except:
					tempscheme='http'
				if 'Referer' in params['headers']:
					params['headers']['Referer']=f'http://{serverhost}'
					
			params['headers']['mariana-src-nac']=source_nac+'.mariana'
			params['headers']['mariana-src-id']=make_id_string(routing_table[source_nac]['pubkey'])
				
			newurl=requests.urllib3.util.Url(scheme=tempscheme, auth=url.auth, host=tempserverhost, path=url.path, query=url.query, fragment=url.fragment)
			target_url=str(newurl)
			
			data=bytes.fromhex(params['data'])
			
			resp=requests.request(method=params['method'].lower(), url=newurl, headers=params['headers'], params=params['args'], data=data,  proxies={'http':None, 'https':None})
			logging.info(f'Got headers {resp.headers}')
			dummyheaders={}
			
			for key, value in resp.headers.items():
				if key.lower() not in ('transfer-encoding', 'content-encoding', 'content-length'):
					dummyheaders[key] = value

			
			respdict={}
			respdict['content']=resp.content.hex()
			respdict['status_code']=resp.status_code
			respdict['headers']=dummyheaders
			payload=json.dumps(respdict)
			
			packet=make_payload_packet(session, 1, payload)
			return packet
			
	elif payload.startswith(portheader.encode()):
		process_port_payload_from_tunnel(source_nac, payload, send_payload, securityconfig)
		
	elif payload.startswith(trenchheader.encode()):
		msg, uniqueid=get_trench_packet(payload)
		add_trench_message(source_nac, msg, phone_book_reverse_lookup, uniqueid)
		
	elif payload.startswith(cargoshipheader.encode()):
		handle_cargo_incoming_packet(source_nac, payload, send_payload, securityconfig)
		
	else:
		return None
		
delivereduid={}
		
def add_trench_message(nac, msg, phone_book_reverse_lookup, uniqueid):
	global trenchmsg, delivereduid
	if uniqueid in delivereduid:
		return	
	nac=phone_book_reverse_lookup(nac)
	textmsg={'NAC': nac+hostend, 'message': msg}
	delivereduid[uniqueid]=get_timestamp()
	trenchmsg.append(textmsg)
		
def get_trench_messages():
	global trenchmsg
	temp=trenchmsg
	trenchmsg=[]
	return temp
		
userops.user_response=user_response

def check_referrer(referer, selfnac, get_contact):
	url=requests.urllib3.util.parse_url(referer)
	host=url.host
	validity, nac= check_mariana_host(host, selfnac, get_contact)
	return validity, nac


def check_mariana_host(host, selfnac, get_contact):
	if not host.endswith(hostend):
		return False, None
	nac=host[:-len(hostend)]

	internalhosts=['local', 'hosts', selfnac, 'my', 'myid', 'createproxy', 'trenchtalk', 'cargoship', 'phonebook', 'security', 'viz', 'stats']
	
	if nac in internalhosts:
		return True, None	
	tempnac=get_contact(nac)
	if tempnac is not None:
		return True, tempnac	
		
	try:
		nacbytes=uuid_bytes(nac)
		return True, nac
	except:
		return False, None

def delivereduid_cleanup():
	while True:
		topop=[]
		for x in delivereduid:
			if check_valid_entry(delivereduid[x], expiry=300):
				topop.append(x)
			
		for y in topop:
			delivereduid.pop(y)
		
		time.sleep(60)
		

def start_delivereduid_cleanup():
	proxythread=threading.Thread(target=delivereduid_cleanup, daemon=True)

	proxythread.start()
