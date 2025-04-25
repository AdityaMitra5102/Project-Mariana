from utils import *
from crypto import *
import pathlib
import os
import threading


savepath='cargoshipdownloads'

pathlib.Path(savepath).mkdir(parents=True, exist_ok=True)

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
	metadata+=len(file_frags).to_bytes(4)
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
	print(f'Sending metadata {metapack}')
	send_payload(dest_nac, metapack)

def cargo_send(dest_nac, filedata, filename, send_payload):
	cargo_meta_thread=threading.Thread(target=make_send_data, args=(dest_nac, filedata, filename, send_payload,))
	cargo_meta_thread.start()
	
def attempt_cargo_send(send_payload):
	global sendbuf
	for identifier in cargostatus:
		print(f'Status {cargostatus[identifier]}')
		nac=cargostatus[identifier]['nac']	
		status=cargostatus[identifier]['status']
		timestamp=cargostatus[identifier]['time']
		filehash=cargostatus[identifier]['hash']
		if not check_valid_entry(timestamp, expiry=10):
			curr=cargostatus[identifier]['current_pack']
			if status=='Sending':
				print(f'Sending data for seq {curr}')
				send_payload(nac, cargoshipheader.encode()+sendbuf[identifier][curr])
			if status=='Receiving':
				ackpack=cargoshipheader.encode()+curr.to_bytes(4)+flag_bytes(1)+filehash
				print(f'Sending ack for seq {curr}')
				send_payload(nac, ackpack)
		
def get_cargo_status():
	global cargostatus

	currstatus=[]
	for identifier in cargostatus:
		currtrans=cargostatus[identifier]
		completeperc=0
		if currtrans['current_pack']!=0:
			completeperc=int(100.0*currtrans['total_packs']/currtrans['current_pack'])
		
		x={'NAC':currtrans['nac'], 'filename':currtrans['name'], 'percentage': str(completeperc), 'status': currtrans['status']}
		currstatus.append(x)
		
	return currstatus

def handle_cargo_incoming_packet(src_nac,payload, send_payload):
	global sendbuf
	global cargostatus
	print(f'Got payload')
	hashlength=len(crypto_hash(b'00'))
	if not payload.startswith(cargoshipheader.encode()):
		return
	payload=payload[len(cargoshipheader):]
	seqnum=int.from_bytes(payload[0:4])
	flag=payload[4]
	filehash=payload[5:5+hashlength]
	identifier=filehash+uuid_bytes(src_nac)
	print(f'Seqnum {seqnum} Flag {flag}')

	if flag==0:
		if seqnum==0:
			if identifier in cargostatus:
				return
			total_fragments=int.from_bytes(payload[5+hashlength:9+hashlength])
			filename=payload[9+hashlength:].decode()
			cargostatus[identifier]={'nac': src_nac, 'process': 'Download', 'status': 'Receiving', 'total_packs': total_fragments, 'current_pack': 0, 'name': filename, 'hash': filehash, 'time': get_timestamp()}
		else:
			if identifier not in cargostatus:
				return
			data=payload[5+hashlength:]
			if seqnum != cargostatus[identifier]['current_pack']+1:
				return
			filepath=os.path.join(savepath, cargostatus[identifier]['name'])
			fptr=open(filepath, 'ab')
			fptr.write(data)
			fptr.close()
			
		ackpack=cargoshipheader.encode()+seqnum.to_bytes(4)+flag_bytes(1)+filehash
		print(f'Sending ACK for {seqnum} {filehash}')
		send_payload(src_nac, ackpack)
		cargostatus[identifier]['current_pack']=seqnum
		cargostatus[identifier]['time']=get_timestamp()
			
		if seqnum+1==cargostatus[identifier]['total_packs']:
			cargostatus[identifier][status]='Receive complete'

	else:
		if identifier not in cargostatus:
			return
		
		cargostatus[identifier]['current_pack']=seqnum+1
		cargostatus[identifier]['time']=get_timestamp()
		sendbuf[identifier][seqnum]=b''
		
		print(f'Will send {seqnum+1}')
		
		if cargostatus[identifier]['current_pack']==cargostatus[identifier]['total_packs']:
			print('Send complete')
			cargostatus[identifier]['status']='Sending complete'
			sendbuf.pop(identifier)
			return
		

		
		packet=sendbuf[identifier][seqnum+1]
		dest_nac=cargostatus[identifier]['nac']
		packet=cargoshipheader.encode()+packet
		send_payload(dest_nac, packet)
		
		
		