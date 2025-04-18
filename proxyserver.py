from flask import Flask, request, Response, render_template
import requests
import logging
import json
import uuid
from proxyutils import *

from utils import *
app = Flask(__name__)

from internals import *
init_threads()
def get_response(dest_nac, payload):
	session=str(uuid.uuid4())
	packet=make_payload_packet(session, 0, payload)
	print(f'SENDING {packet} to {dest_nac}')
	send_payload(dest_nac, packet)
	print(f'DONE SENDING {packet} to {dest_nac}')
	while session not in webpackets:
		logging.info(f'Waiting for response to session {session}')
		time.sleep(1)
	resp=webpackets[session]
	return resp
	

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
	host=str(request.headers.get('Host')).strip()
	print(host)
	ismar, nac=check_mariana_host(host)
	if not ismar:
		respcont='Not in Mariana. Use standard web browser.'.encode()
		return Response(respcont, 400)

	if host=='local.mariana':
		return render_template('home.html')

	with routing_table_lock:
		if host[:-len(hostend)] not in routing_table:
			print(f'HOST {host} NOT IN ROUTING TABLE {routing_table}.')
			respcont='Host not in routing table.'.encode()
			return Response(respcont, 400)

	target_url = host
	if path:
		target_url = f"{target_url}/{path}"
	target_url=f'http://{target_url}'
	logging.info(f"Proxying request to: {target_url}")
	headers = {key: value for key, value in request.headers}
	try:
		if True:
			reqparam={}
			reqparam['target_url']=target_url
			reqparam['headers']=headers
			reqparam['params']=dict(request.args)
			reqparam['cookies']=dict(request.cookies)
			reqparamstr=json.dumps(reqparam)
			print(reqparamstr)
			
			resp=get_response(nac, reqparamstr)
			
						
			respdict=json.loads(resp)
			content=bytes.fromhex(respdict['content'])
			status_code=respdict['status_code']
			dummyheaders=respdict['headers']

 			
			response = Response(content, status_code)
			response.headers=dummyheaders
			return response
			
	except requests.exceptions.RequestException as e:
		logging.error(f"Error proxying request: {e}")
		return f"Error proxying request: {str(e)}", 500

if __name__ == '__main__':

	logging.info("Starting proxy server on port 8000")
	app.run(host='0.0.0.0', port=8000)