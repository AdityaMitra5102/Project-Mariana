from utils import *
from crypto import *

def gen_conn_accept(src_nac, pubkey):
	packet=uuid_bytes(src_nac)
	packet+=flag_bytes(1)
	packet+=pubkey
	return packet
	
def gen_conn_reject(src_nac):
	packet=uuid_bytes(src_nac)
	packet+=flag_bytes(2)
	return packet

def gen_conn_req(src_nac, pubkey):
	packet=uuid_bytes(src_nac)
	packet+=flag_bytes(0)
	packet+=pubkey
	return packet

def gen_payload_seq(src_nac, dest_nac, payload, dest_pubkey):
	packet=uuid_bytes(src_nac)
	packet=packet+flag_bytes(3)
	packet=packet+uuid_bytes(dest_nac)
	

	
	session=str(uuid.uuid4())
	sessionbytes=uuid_bytes(session)
	
	encr_payload=payload_encrypt(payload, dest_pubkey)
	fragments=segment_payload(encr_payload)
	
	maxseq=len(fragments)-1
	maxseqbytes=maxseq.to_bytes(4, 'big')

	packets=[]
	for seq in range(maxseq+1):
		seqnum=seq.to_bytes(4, 'big')
		currentpacket=packet+seqnum+maxseqbytes+sessionbytes+fragments[seq]
		packets.append(currentpacket)
		
	return packets