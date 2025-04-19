from utils import *

import userops
import requests
import uuid
import json

header='mariana'

webpackets={}

serverhost='localhost'

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
	
def user_response(source_nac, payload):
	if payload.startswith(header.encode()):
		session, flag, payload=get_packet_payload(payload)
		if flag==1:
			webpackets[session]=payload
			return None
		else:
			params=json.loads(payload)
			url=requests.urllib3.util.parse_url(params['target_url'])
			newurl=requests.urllib3.util.Url(scheme=url.scheme, auth=url.auth, host=serverhost, path=url.path, query=url.query, fragment=url.fragment)
			target_url=str(newurl)
			resp=requests.get(newurl, headers=params['headers'], params=params['params'], cookies=params['cookies'])
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
	else:
		return None
		
userops.user_response=user_response

hostend='.mariana'

def check_mariana_host(host, selfnac):
	if not host.endswith(hostend):
		return False, None
	nac=host[:-len(hostend)]
	if nac=='local':
		return True, None
	if nac==selfnac:
		return True, nac
	try:
		nacbytes=uuid_bytes(nac)
		return True, nac
	except:
		return False, None
