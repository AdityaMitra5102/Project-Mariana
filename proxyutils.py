from utils import *
from portserver import *
from cargoship import *

import userops
import requests
import uuid
import json

header='mariana'
portheader='portproxy:'
trenchheader='trenchtalk'
cargoshipheader='cargo'

hostend='.mariana'

webpackets={}
trenchmsg=[]

serverhost='localhost'

def make_trench_payload(msg):
	return trenchheader.encode()+msg.encode()
	
def get_trench_packet(payload):
	try:
		return payload[len(trenchheader):].decode()
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
	
def user_response(source_nac, payload, send_payload, phone_book_reverse_lookup):
	if payload.startswith(header.encode()):
		session, flag, payload=get_packet_payload(payload)
		if flag==1:
			webpackets[session]=payload
			return None
		else:
			params=json.loads(payload)
			url=requests.urllib3.util.parse_url(params['target_url'])
			tempscheme=url.scheme
			check_host=url.host
			tempserverhost=serverhost
			if not check_host.endswith(hostend):
				tempserverhost=check_host
				try:
					respx=requests.get(f'https://{tempserverhost}', timeout=3)
					tempscheme='https'
				except:
					tempscheme='http'
					
				
			newurl=requests.urllib3.util.Url(scheme=tempscheme, auth=url.auth, host=tempserverhost, path=url.path, query=url.query, fragment=url.fragment)
			target_url=str(newurl)
			
			data=bytes.fromhex(params['data'])
			
			resp=requests.request(method=params['method'].lower(), url=newurl, headers=params['headers'], data=data)
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
		process_port_payload_from_tunnel(source_nac, payload, send_payload)
		
	elif payload.startswith(trenchheader.encode()):
		msg=get_trench_packet(payload)
		add_trench_message(source_nac, msg, phone_book_reverse_lookup)
		
	elif payload.startswith(cargoshipheader.encode()):
		handle_cargo_incoming_packet(source_nac, payload, send_payload)
		
	else:
		return None
		
def add_trench_message(nac, msg, phone_book_reverse_lookup):
	global trenchmsg
	nac=phone_book_reverse_lookup(nac)
	textmsg={'NAC': nac+hostend, 'message': msg}
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
	if nac=='local':
		return True, None
	if nac=='hosts':
		return True, None
	if nac==selfnac:
		return True, nac
	if nac=='my':
		return True, None
	if nac=='createproxy':
		return True, None
	if nac=='trenchtalk':
		return True, None
	if nac=='cargoship':
		return True, None
	if nac=='phonebook':
		return True, None
	
	tempnac=get_contact(nac)
	if tempnac is not None:
		return True, tempnac	
		
	try:
		nacbytes=uuid_bytes(nac)
		return True, nac
	except:
		return False, None
