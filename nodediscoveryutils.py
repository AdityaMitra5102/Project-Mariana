import socket
import psutil
import ipaddress

def calc_broadcast(ip, netmask):
	ip_int=int(ipaddress.IPv4Address(ip))
	netmask_int=int(ipaddress.IPv4Address(netmask))
	broadcast_int = ip_int | ~netmask_int & 0xFFFFFFFF
	broadcast_address = str(ipaddress.IPv4Address(broadcast_int))
	return broadcast_address

def get_baddr():
	baddr=[]
	for iface, addrs in psutil.net_if_addrs().items():
		for addr in addrs:
			if addr.family==socket.AF_INET:
				brd=calc_broadcast(addr.address, addr.netmask)
				#print(addr.address,' ',addr.netmask,' ',brd)
				baddr.append(brd)
				
	return [bcast for bcast in baddr if bcast]
	
