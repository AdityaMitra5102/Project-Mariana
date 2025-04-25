from flask import Flask, request, Response, render_template
import requests
import logging
import json
import uuid
from proxyutils import *
from cargoship import *
from flask_cors import CORS


from utils import *
app = Flask(__name__, static_folder=None)
CORS(app)
from internals import *
init_threads()
def get_response(dest_nac, payload):
	session=str(uuid.uuid4())
	packet=make_payload_packet(session, 0, payload)
	send_payload(dest_nac, packet)
	while session not in webpackets:
		logging.info(f'Waiting for response to session {session}')
		time.sleep(1)
	resp=webpackets[session]
	return resp

def known_hosts():
	resp='<HTML><head><title>Nodes</title></head><body><H1>Known nodes</H1><br>'
	for nac in routing_table:
		resp=resp+f'{nac}.mariana <a href="http://{nac}.mariana">Open</a> <br>'
	resp+='</body></HTML>'
	return resp

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
	host=str(request.headers.get('Host')).strip()
	ismar, nac=check_mariana_host(host, config['nac'])
	if not ismar:
		respcont='Not in Mariana. Use standard web browser.'.encode()
		return Response(respcont, 400)

	if host=='local.mariana':
		return render_template('home.html', nac=f'{config["nac"]}.mariana')

	if host=='hosts.mariana':
		return known_hosts()
		
	if host=='my.mariana':
		resp= Response(f'{config["nac"]}.mariana')
		return resp
		
	if host=='trenchtalk.mariana':
		if request.method=='GET':
			if request.path=='/messages':
				return json.dumps(get_trench_messages())
			if request.path=='/':
				return render_template('trenchtalk.html')
		if request.method=='POST' and request.path=='/send':
			msg=request.form.get('message')
			tosend=request.form.get('dest')
			dest_nac_list = [word for part in tosend.split(',') for word in part.strip().split()]
			trench_payload=make_trench_payload(msg)
			for dest_nac_send in dest_nac_list:
				dest_nac_check, dest_nac=check_mariana_host(dest_nac_send, config['nac'])
				if dest_nac_send and dest_nac in routing_table:
					send_payload(dest_nac, trench_payload)
			return f'Sent to {tosend} if exists in routing table'

	if host=='cargoship.mariana':
		if request.method=='GET':
			if request.path=='/cargostatus':
				restemp=get_cargo_status()
				return json.dumps(restemp)
			if request.path=='/':
				return render_template('cargoship.html')
		if request.method=='POST' and request.path=='/send':
			tosend=request.form.get('dest')
			file=request.files['file']
			dest_nac_list = [word for part in tosend.split(',') for word in part.strip().split()]
			file_bytes=file.read()
			filename=file.filename
			print('File uploaded {filename} {file_bytes}')
			for dest_nac_send in dest_nac_list:
				dest_nac_check, dest_nac=check_mariana_host(dest_nac_send, config['nac'])
				if dest_nac_send and dest_nac in routing_table:
					cargo_send(dest_nac, file_bytes, filename, send_payload)		
			

			return f'Sent to {tosend} if exists in routing table'

			
		
	if host=='createproxy.mariana':
		listenport=int(request.args.get('listenport'))
		destport=int(request.args.get('destport'))
		destnac=request.args.get('destnac')
		proto=request.args.get('proto', 'TCP')
		mode=proto=='TCP'
		if destnac not in routing_table:
			return 'NAC not found. Not starting proxy'
		create_proxy_port(listenport, destport, destnac, mode, send_payload)
		return 'Starting proxy'

	with routing_table_lock:
		if host[:-len(hostend)] not in routing_table:
			logging.warning(f'HOST {host} NOT IN ROUTING TABLE {routing_table}.')
			respcont='Host not in routing table.'.encode()
			return Response(respcont, 400)

	target_url = host
	if path:
		target_url = f"{target_url}/{path}"
	target_url=f'http://{target_url}'
	logging.info(f"Proxying request to: {target_url}")
	headers = {key: value for key, value in request.headers}
	headers['Access-Control-Allow-Origin'] = "*"
	
	try:
		if True:
			reqparam={}
			reqparam['target_url']=target_url
			reqparam['headers']=headers
			reqparam['params']=dict(request.args)
			reqparam['cookies']=dict(request.cookies)
			reqparamstr=json.dumps(reqparam)
		
			resp=get_response(nac, reqparamstr)
			
						
			respdict=json.loads(resp)
			content=bytes.fromhex(respdict['content'])
			status_code=respdict['status_code']
			dummyheaders=respdict['headers']
			dummyheaders['Host']=host

 			
			response = Response(content, status_code)
			response.headers=dummyheaders
			return response
			
	except requests.exceptions.RequestException as e:
		logging.error(f"Error proxying request: {e}")
		return f"Error proxying request: {str(e)}", 500

if __name__ == '__main__':

	logging.info("Starting proxy server on port 8000")
	app.run(host='0.0.0.0', port=8000)
