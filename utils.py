import pathlib
import requests
import time
import uuid
import socket
import os
import math

def get_timestamp():
	return int(time.time())
	
def check_valid_entry(timestamp, expiry=60):
	return get_timestamp()-timestamp<expiry
	
def uuid_bytes(id):
	uuid_obj=uuid.UUID(id)
	return uuid_obj.bytes
	
def uuid_str(b):
	return str(uuid.UUID(bytes=b))
	
def flag_bytes(flag):
	return flag.to_bytes(1, 'big')
	
def check_valid_conn(nac, ip, port):
	return True #Modify this function to blacklist machines
	
def segment_payload(payload, maxsize=800):
	total_packets=math.ceil(len(payload)/maxsize)
	fragments=[]
	for i in range(total_packets):
		fragments.append(payload[maxsize*i:maxsize*(i+1)])
	return fragments

def list_ip_addresses():
	iplist=[]
	try:
		hostname = socket.gethostname()
		ip_addresses = socket.getaddrinfo(hostname, None, socket.AF_INET)
		for ip_info in ip_addresses:
			ip = ip_info[4][0]
			iplist.append(ip)
	except socket.gaierror as e:
		pass
	return iplist

def check_valid_tracker(tracker):
	tracker_ip=tracker['ip']
	tracker_port=tracker['port']
	iplist=list_ip_addresses()
	return tracker_ip not in iplist
	
def get_public_ip():
	resp=requests.get('http://api.ipify.org')
	return resp.text

def is_stick():
	try:
		stickpath='/etc/mar/stickmode'
		return os.path.exists(stickpath)
	except:
		return False
		
def delete_existing():
	filelist=['config.json', 'privatekey.pem', 'phonebook.json', 'phonebooksec.json', 'security.json']
	filepath = os.path.join(os.getenv('APPDATA') if os.name == 'nt' else os.path.expanduser('~/.config'), 'Mariana')
	for x in filelist:
		try:
			finpath=os.path.join(filepath, x)
			os.remove(finpath)
		except:
			pass	

		
def is_ephemeral():
	try:
		ephpath=['/etc/mar/ephemeral', f'{os.getenv('appdata')}/mareph']
		for x in ephpath:
			if os.path.exists(x):
				delete_existing()
				return True
		return False
	except:
		return False
	
		
def is_persist():
	return not is_ephemeral()