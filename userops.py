
def user_response(source_nac, payload, send_payload, phone_book_reverse_lookup):
	print(f'{source_nac}>>> {payload.decode()}')
	return None #No reply
	
	
def user_input():
	nac=input("Enter NAC")
	msg=input("Enter msg")
	
	return nac, msg.encode()
	