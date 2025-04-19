from internals import *
from userops import *

if __name__=='__main__':
	init_threads()
	
	while True:
		nac, msg=user_input()
		send_payload(nac, msg)