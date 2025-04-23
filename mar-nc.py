import argparse
import uuid
import re
import requests
import sys

def validate_nac(nac):
	if not nac.endswith(".mariana"):
		raise argparse.ArgumentTypeError("NAC must end with '.mariana'")
	try:
		uuid.UUID(nac.split(".mariana")[0])
	except ValueError:
		raise argparse.ArgumentTypeError("NAC prefix must be a valid UUID4 string")
	return nac

def validate_port(port):
	p = int(port)
	if not (1 <= p <= 65535):
		raise argparse.ArgumentTypeError("Port must be in range 1-65535")
	return p

def validate_proto(proto):
	proto = proto.upper()
	if proto not in {"TCP", "UDP"}:
		raise argparse.ArgumentTypeError("Protocol must be TCP or UDP")
	return proto

def main():
	parser = argparse.ArgumentParser(description="mariana-netcat: initiate a tunnel via Mariana.")
	parser.add_argument("source_port", type=validate_port, help="Source (listen) port on localhost")
	parser.add_argument("dest_port", type=validate_port, help="Destination port on NAC")
	parser.add_argument("protocol", type=validate_proto, help="Protocol: TCP or UDP")
	parser.add_argument("nac", type=validate_nac, help="Destination NAC in the format <uuid>.mariana")

	args = parser.parse_args()

	nac_uuid = args.nac.split(".mariana")[0]
	url = f"http://localhost:8000?listenport={args.source_port}&destport={args.dest_port}&proto={args.protocol}&destnac={nac_uuid}"
	headers = {"Host": "createproxy.mariana"}

	print(f"[+] Sending request to initiate tunnel...")
	try:
		r = requests.get(url, headers=headers)
		print(r.text)
	except Exception as e:
		print(f"[!] Failed to connect to local tunnel service: {e}")
		sys.exit(1)

if __name__ == "__main__":
	main()
