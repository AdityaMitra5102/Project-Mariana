from kyber_py.kyber import Kyber512
from kyber_py.kyber import Kyber768
from kyber_py.kyber import Kyber1024
import os
import base64
import json

class Kyber:
	def __init__(self, algorithm=Kyber512, pk=None, sk=None, pkb64=None):
		self.algorithm=algorithm
		self.pk=None
		if pkb64 is not None:
			self.pk=base64.urlsafe_b64decode(pkb64.encode())
		if pk is not None:
			self.pk=pk
		self.sk=sk
		self.inputblock=32
		self.outputblock=0
		if self.pk is not None:
			self.encrypt(os.urandom(32))
		
	def keygen(self):
		pk, sk= self.algorithm._cpapke_keygen()
		self.pk=pk
		self.sk=sk
		self.encrypt(os.urandom(32))
		
	def partition(self,msg,block=1):
		msg1=bytearray(msg)
		while len(msg1) % block !=0:
			msg1.extend(bytes(1))
		data=bytes(msg1)
		arr=[data[i:i + block] for i in range(0, len(data), block)]
		return arr
		
	def unpad(self, msg):
		ptr=len(msg)-1
		while ptr>0:
			if msg[ptr] != 0:
				break
			ptr=ptr-1
		return msg[:ptr+1]
	
	def encrypt(self, msg):
		arr=self.partition(msg, self.inputblock)
		res=bytearray()
		for x in arr:
			out=self.algorithm._cpapke_enc(self.pk, x, os.urandom(32))
			self.outputblock=len(out)
			res.extend(out)
		
		return bytes(res)
		
	def decrypt(self, cipher):
		arr=self.partition(cipher, self.outputblock)
		res=bytearray()
		for x in arr:
			out=self.algorithm._cpapke_dec(self.sk, x)
			res.extend(out)
		return self.unpad(bytes(res))
		
	def get_pk(self):
		return self.pk
		
	def get_pk_b64(self):
		return base64.urlsafe_b64encode(self.get_pk()).decode()
		
	def get_sk(self):
		sklen=len(self.sk).to_bytes(3,'big')
		total=sklen+self.sk+self.pk
		return total
		
	def from_sk(self, sk):
		sklenbytes=sk[0:3]
		sklen=integer.from_bytes(sklen)
		self.sk=sk[3:3+sklen]
		self.pk=sk[3+sklen:]
		self.encrypt(os.urandom(32)
		
	def from_pk(self, pk):
		self.pk=pk
		self.encrypt(os.urandom(32))
		
	def to_file(self, filename='secret.kyberpvt'):
		keys={}
		keys['pk']=base64.urlsafe_b64encode(self.pk).decode()
		keys['sk']=base64.urlsafe_b64encode(self.sk).decode()
		fl=open(filename, 'w')
		fl.write(json.dumps(keys))
		fl.close()
		
	def from_file(self, filename='secret.kyberpvt'):
		fl=open(filename,'r')
		keys=json.loads(fl.read())
		fl.close()
		self.pk=base64.urlsafe_b64decode(keys['pk'].encode())
		self.sk=base64.urlsafe_b64decode(keys['sk'].encode())
		self.encrypt(os.urandom(32))
		
	def to_pub_file(self, filename='public.kyberpub'):
		keys={}
		keys['pk']=base64.urlsafe_b64encode(self.pk).decode()
		fl=open(filename, 'w')
		fl.write(json.dumps(keys))
		fl.close()
	
	def from_pub_file(self, filename='public.kyberub'):
		fl=open(filename,'r')
		keys=json.loads(fl.read())
		fl.close()
		self.pk=base64.urlsafe_b64decode(keys['pk'].encode())
		self.encrypt(os.urandom(32))
	