
def user_response(source_nac, payload):
	print(f'{source_nac}>>> {payload.decode()}')
	return None #No reply
	
	
def user_input():
	nac=input("Enter NAC")
	msg=input("Enter msg")
	
	return nac, msg.encode()
	