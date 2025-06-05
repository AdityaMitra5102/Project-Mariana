from utils import *
from crypto import *
import os

def gen_conn_accept(src_nac, pubkey, desc):
	packet=uuid_bytes(src_nac)
	packet+=flag_bytes(1)
	packet+=pubkey
	packet+=desc.encode()
	return packet
	
def gen_conn_reject(src_nac):
	packet=uuid_bytes(src_nac)
	packet+=flag_bytes(2)
	return packet

def gen_conn_req(src_nac, pubkey, desc):
	packet=uuid_bytes(src_nac)
	packet+=flag_bytes(0)
	packet+=pubkey
	packet+=desc.encode()
	return packet
	
def gen_verif_init(src_nac, ciphertext):
	packet=uuid_bytes(src_nac)
	packet+=flag_bytes(7)
	packet+=ciphertext
	return packet
	
def gen_verif_complete(src_nac, resp):
	packet=uuid_bytes(src_nac)
	packet+=flag_bytes(8)
	packet+=resp
	return packet
	

def gen_payload_seq(src_nac, dest_nac, payload, dest_pubkey):

	packet=flag_bytes(3)
	packet=packet+uuid_bytes(dest_nac)
	session=str(uuid.uuid4())
	sessionbytes=uuid_bytes(session)
	
	encr_payload, authkey=payload_encrypt(payload, dest_pubkey, uuid_bytes(src_nac))
	fragments=segment_payload(encr_payload)
	
	maxseq=len(fragments)-1
	maxseqbytes=maxseq.to_bytes(4, 'big')

	packets=[]
	for seq in range(maxseq+1):
		dummypacket=os.urandom(16)+packet
		seqnum=seq.to_bytes(4, 'big')
		currentpacket=dummypacket+seqnum+maxseqbytes+sessionbytes+fragments[seq]
		packets.append(currentpacket)
		
	return packets, session, authkey
	
def gen_tracker_discovery(nac, state):
	packet=uuid_bytes(nac)
	packet+=flag_bytes(9)
	packet+=uuid_bytes(state)
	return packet

def gen_retransmission_req(src_nac, dest_nac, session, req, authkey):
	packet=os.urandom(16)
	packet+=flag_bytes(4)
	packet+=uuid_bytes(dest_nac)
	packet+=uuid_bytes(session)
	packet+=req.to_bytes(4, 'big')
	packet+=authkey
	return packet
	
def gen_full_ack(src_nac, dest_nac, session, authkey):
	packet=os.urandom(16)
	packet+=flag_bytes(5)
	packet+=uuid_bytes(dest_nac)
	packet+=uuid_bytes(session)
	packet+=authkey
	return packet
