from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import base64
import os
import hashlib
import binascii

from Kyber import Kyber
from kyber_py.pyaes import *

def generate_keypair():
	cr=Kyber()
	cr.keygen()
	return cr.get_sk()

	#private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
	#private_key_bytes = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())
	#return private_key_bytes
	
def get_pub_key(priv):
	cr=Kyber()
	cr.from_sk(priv)
	return cr.get_pk()
	
	#privkeybytes=priv
	#privkey = serialization.load_pem_private_key(privkeybytes, password=None)
	#pubkey=privkey.public_key()
	#public_key_bytes = pubkey.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
	#return public_key_bytes

def encrypt(msg, pub):
	cr=Kyber()
	cr.from_pk(pub)
	return cr.encrypt(msg)
	
	#pubkeybytes=pub
	#pubkey = serialization.load_pem_public_key(pubkeybytes)
	#encrypted = pubkey.encrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	#return encrypted	
	
def decrypt(msg, priv):
	cr=Kyber()
	cr.from_sk(priv)
	return cr.decrypt(msg)
	
	#privkeybytes=priv
	#privkey = serialization.load_pem_private_key(privkeybytes, password=None)
	#decrypted = privkey.decrypt(msg, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None))
	#return decrypted

def encaps(pub):
	cr=Kyber()
	cr.from_pk(pub)
	return cr.encaps()
	
def decaps(pvt, ct):
	cr=Kyber()
	cr.from_sk(pvt)
	return cr.decaps(ct)

def aes_keygen():
	key = AESGCM.generate_key(bit_length=256)
	return key
	
def aes_encrypt(msg, key):
	nonce=os.urandom(12)
	aesgcm=AESGCM(key)
	ciphertext=aesgcm.encrypt(nonce, msg, associated_data=None)
	ciphertext=nonce+ciphertext
	return ciphertext
	
def aes_decrypt(msg, key):
	nonce=msg[:12]
	msg=msg[12:]
	aesgcm=AESGCM(key)
	cleartext=aesgcm.decrypt(nonce, msg, associated_data=None)
	return cleartext
	
def payload_encrypt(payload, pubkey, nac):
	aeskey, encaeskey=encaps(pubkey)
	encpayload=aes_encrypt(payload, aeskey)
	encnac=aes_encrypt(nac, aeskey)
	finalpayload=encnac+encaeskey+encpayload
	
	keychecksum=crypto_hash(aeskey)
	
	return finalpayload, keychecksum
	
def payload_decrypt(payload_buffer, privkey):
	aessize=768
	aeskey=payload_buffer[:aessize]
	encrpayload=payload_buffer[aessize:]
	if aessize==0:
		return encrpayload #not encrypted
	
	aeskeydec=decaps(privkey, aeskey)
	decpayload=aes_decrypt(encrpayload, aeskeydec)
	keychecksum=crypto_hash(aeskeydec)
	return decpayload, keychecksum
	
def crypto_hash(data):
	return hashlib.md5(data).digest()

def crc32(data):
	return binascii.crc32(data).to_bytes(4)
	
	
	