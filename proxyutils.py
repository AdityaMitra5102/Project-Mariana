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
			webpackets[session]={}
			webpackets[session]['content']=payload
			webpackets[session]['time']=get_timestamp()
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

	internalhosts=['local', 'hosts', selfnac, 'my', 'myid', 'createproxy', 'trenchtalk', 'cargoship', 'phonebook', 'security', 'viz', 'stats', 'relay']
	
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
			try:
				delivereduid.pop(y)
			except:
				pass
			
			
		expwebpackets=[]
		for x in webpackets:
			if check_valid_entry(webpackets[x]['time'], expiry=30):
				expwebpackets.append(x)
				
		for y in expwebpackets:
			try:
				webpackets.pop(x)
			except:
				pass
		
		time.sleep(60)
		

def start_delivereduid_cleanup():
	proxythread=threading.Thread(target=delivereduid_cleanup, daemon=True)

	proxythread.start()
	
	
	
iconb64='''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'''	
