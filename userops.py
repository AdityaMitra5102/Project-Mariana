import proxyutils
def user_response(source_nac, payload, send_payload, phone_book_reverse_lookup, securityconfig):
	#print(f'{source_nac}>>> {payload.decode()}')
	return proxyutils.user_response(source_nac, payload, send_payload, phone_book_reverse_lookup, securityconfig)
	
	
def user_input():
	nac=input("Enter NAC")
	msg=input("Enter msg")
	
	return nac, msg.encode()
	