from utils import *
from crypto import *
import pathlib
import os
import threading
import logging

def get_savepath():
	downdir=None
	try:
		downdir=get_cargodowndir()
	except:
		downdir=None
	if downdir is None or downdir=='':
		downdir=(next((d for d in [os.path.join(os.path.expanduser('~'), name) for name in ['Downloads', 'downloads', 'Download', 'download']] if os.path.isdir(d)), os.path.join(os.path.expanduser('~'), 'Downloads')))
	savepath='CargoShip'
	savepath=os.path.join(downdir, savepath)
	pathlib.Path(savepath).mkdir(parents=True, exist_ok=True)
	return savepath

get_savepath()

cargoshipheader='cargo'

sendbuf={}
receivebuf={}
cargostatus={}


def make_send_data(dest_nac, filedata, filename, send_payload):
	global sendbuf
	global cargostatus
	filehash=crypto_hash(filedata)
	identifier=filehash+uuid_bytes(dest_nac)
	if identifier in sendbuf:
		return
	if identifier in cargostatus:
		return
	cargostatus[identifier]={'nac': dest_nac, 'process': 'Upload', 'status': 'Processing file', 'total_packs': 1, 'current_pack': 0, 'name':filename, 'hash': filehash, 'time': get_timestamp()}
	metadata=(0).to_bytes(4)
	metadata+=flag_bytes(0)
	metadata+=filehash
	file_frags=segment_payload(filedata, maxsize=400)
	metadata+=(len(file_frags)+1).to_bytes(4)
	metadata+=filename.encode()
	
	sendbuf[identifier]=[]
	sendbuf[identifier].append(metadata)
	
	for i in range(len(file_frags)):
		pack=(i+1).to_bytes(4)
		pack+=flag_bytes(0)
		pack+=filehash
		pack+=file_frags[i]
		sendbuf[identifier].append(pack)
		
	cargostatus[identifier]['total_packs']=len(sendbuf[identifier])
	cargostatus[identifier]['status']='Sending'
	
	metapack=cargoshipheader.encode()+metadata
	send_payload(dest_nac, metapack)

def cargo_send(dest_nac, filedata, filename, send_payload):
	cargo_meta_thread=threading.Thread(target=make_send_data, args=(dest_nac, filedata, filename, send_payload,), daemon=True)
	cargo_meta_thread.start()
	
def attempt_cargo_send(send_payload):
	global sendbuf
	for identifier in cargostatus:
		nac=cargostatus[identifier]['nac']	
		status=cargostatus[identifier]['status']
		timestamp=cargostatus[identifier]['time']
		filehash=cargostatus[identifier]['hash']
		if not check_valid_entry(timestamp, expiry=7200):
			if status=='Sending':
				cargostatus[identifier]['status']='Sending failed'
				if identifier in sendbuf:
					sendbuf.pop(identifier)
			if status=='Receiving':
				cargostatus[identifier]['status']='Receiving failed'

		if not check_valid_entry(timestamp, expiry=5):
			curr=cargostatus[identifier]['current_pack']
			if status=='Sending':
				send_payload(nac, cargoshipheader.encode()+sendbuf[identifier][curr])
			if status=='Receiving':
				ackpack=cargoshipheader.encode()+curr.to_bytes(4)+flag_bytes(1)+filehash
				send_payload(nac, ackpack)
		
def get_cargo_status(phone_book_reverse_lookup):
	global cargostatus

	currstatus=[]
	for identifier in cargostatus:
		currtrans=cargostatus[identifier]
		completeperc=0
		if currtrans['current_pack']!=0:
			completeperc=round(100.0*currtrans['current_pack']/(currtrans['total_packs']-1),2)
			
		completeperc=min(100, completeperc)
		
		x={'NAC':phone_book_reverse_lookup(currtrans['nac'])+'.mariana', 'filename':currtrans['name'], 'percentage': str(completeperc), 'status': currtrans['status']}
		currstatus.append(x)
		
	return currstatus

executable_list=['exe', 'com', 'bat', 'sh', 'ps1', 'app']

def check_file_executable(filename):
	for extension in executable_list:
		if filename.endswith(extension):
			return True
	return False

def handle_cargo_incoming_packet(src_nac,payload, send_payload, securityconfig):
	global sendbuf
	global cargostatus
	global recvbuf
	hashlength=len(crypto_hash(b'00'))
	if not payload.startswith(cargoshipheader.encode()):
		return
	payload=payload[len(cargoshipheader):]
	seqnum=int.from_bytes(payload[0:4])
	flag=payload[4]
	filehash=payload[5:5+hashlength]
	identifier=filehash+uuid_bytes(src_nac)
	if flag==0:
		if seqnum==0:
			if identifier in cargostatus:
				return
			total_fragments=int.from_bytes(payload[5+hashlength:9+hashlength])
			filename=payload[9+hashlength:].decode()
			if not securityconfig['cargo_ship_allow_exec']:
				if check_file_executable(filename):
					logging.info('Executable file not allowed in security config. Dropped')
					return
			cargostatus[identifier]={'nac': src_nac, 'process': 'Download', 'status': 'Receiving', 'total_packs': total_fragments, 'current_pack': 0, 'name': filename, 'hash': filehash, 'time': get_timestamp()}
			receivebuf[identifier]=[b'']*(total_fragments-1)
		
		else:
			
			if identifier not in cargostatus:
				return
			data=payload[5+hashlength:]
			if seqnum != cargostatus[identifier]['current_pack']+1:
				return
			receivebuf[identifier][seqnum-1]=data

			
		ackpack=cargoshipheader.encode()+seqnum.to_bytes(4)+flag_bytes(1)+filehash

		cargostatus[identifier]['current_pack']=seqnum
		cargostatus[identifier]['time']=get_timestamp()			
		if (seqnum+1)==cargostatus[identifier]['total_packs']:
			savepath=get_savepath()
			cargostatus[identifier]['status']='Writing.'
			tempfilename=cargostatus[identifier]['name']
			while pathlib.Path(os.path.join(savepath, tempfilename)).is_file():
				tempfilename='new_'+tempfilename
			filepath=os.path.join(savepath, tempfilename)
			fptr=open(filepath, 'wb')
			tempdata=b''
			fragtemp=0
			for frag in receivebuf[identifier]:
				tempdata+=frag
				cargostatus[identifier]['status']=f'Writing {fragtemp} of {cargostatus[identifier]['total_packs']}'
				fragtemp+=1
			fptr.write(tempdata)
			fptr.close()
			hashstatus='Hash mismatch'
			if crypto_hash(tempdata)==cargostatus[identifier]['hash']:
				hashstatus='Hash verified.'
			receivebuf.pop(identifier)
			cargostatus[identifier]['status']=f'Receive complete. {hashstatus}\n Saved as {filepath}'	
			
			
		send_payload(src_nac, ackpack)
	else:
		if identifier not in cargostatus:
			return
		
		cargostatus[identifier]['current_pack']=seqnum+1
		cargostatus[identifier]['time']=get_timestamp()
		sendbuf[identifier][seqnum]=b''
		
		if cargostatus[identifier]['current_pack']==cargostatus[identifier]['total_packs'] and cargostatus[identifier]['total_packs']>1:
			cargostatus[identifier]['status']='Sending complete'
			cargostatus[identifier]['current_pack']=seqnum+1
			sendbuf.pop(identifier)
			return
		

		
		packet=sendbuf[identifier][seqnum+1]
		dest_nac=cargostatus[identifier]['nac']
		packet=cargoshipheader.encode()+packet
		send_payload(dest_nac, packet)
		
		
		
