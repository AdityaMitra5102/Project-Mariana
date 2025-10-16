from utils import *
from internals import *

def get_self_as_tracker():
	x=list_ip_addresses()
	try:
		pub_ip=get_public_ip()
		x.append(pub_ip)
	except:
		pass
		
	port=config['port']
	
		
	selftr={}
	for ip in x:
		selftr[f"{ip}:{str(port)}"]={"ip": ip, "port": port}
		
	return selftr
	
def get_current_tracker():
	return trackers
	
def parse_trackers(trackers):
	for tracker in trackers:
		try:
			logging.info(f'Processing uploaded tracker {tracker}')
			add_to_tracker(tracker[ip], tracker[port])
		except:
			pass