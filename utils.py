import pathlib
import requests
import time
import uuid
import socket
import os
import math
import random

from crypto import *

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
	
def segment_payload(payload, maxsize=812):
	total_packets=math.ceil(len(payload)/maxsize)
	fragments=[]
	for i in range(total_packets):
		fragments.append(payload[maxsize*i:maxsize*(i+1)])
	return fragments

def xor_16b(x, y):
	a=int.from_bytes(x)
	b=int.from_bytes(y)
	c=a^b
	return c.to_bytes(16)

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
	resp=requests.get('http://api.ipify.org', proxies={'http':None, 'https':None})
	return resp.text
	
def make_id_string(pubkey):
	x=crc32(pubkey).hex().upper()
	x = x[:4] + '-' + x[4:]
	return x
	

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

def get_random_from_list(x):
	if not x or len(x)==0:
		return None
	return random.choice(x)
		
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
	
def get_cargodowndir():
	ephpath=['/etc/mar/downdir', f'{os.getenv('appdata')}/downdir']
	for x in ephpath:
		if os.path.exists(x):
			fl=open(x, 'r')
			cont=fl.read()
			fl.close()
			return cont
	return None
		
def is_persist():
	return not is_ephemeral()