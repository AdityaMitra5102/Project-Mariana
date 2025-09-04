import threading
from flask import Flask, request, Response, render_template, jsonify
import requests
import logging
import json
import re
import uuid
from proxyutils import *
from cargoship import *
from flask_cors import CORS


from utils import *
app = Flask(__name__, static_folder=None)
CORS(app)

def to_js_object(obj):
	def format_key(k):
		if re.match(r'^[A-Za-z_$][A-Za-z0-9_$]*$', k):
			return k
		else:
			return f'"{k}"'

	def format_value(v):
		if isinstance(v, dict):
			return to_js_object(v)
		elif isinstance(v, str):
			return f'"{v}"'
		elif v is None:
			return 'null'
		else:
			return str(v)
        
	items = [f"{format_key(k)}: {format_value(v)}" for k, v in obj.items()]
	return '{' + ', '.join(items) + '}'

app.jinja_env.filters['to_js_object'] = to_js_object

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
	webpackets.pop(session)
	return resp

def known_hosts():
	resp='<HTML><head><title>Nodes</title></head><body><H1>Known nodes</H1><br>'
	for nac in routing_table:
		resp=resp+f'{nac}.mariana <a href="http://{nac}.mariana">Open</a> <br>'
	resp+='</body></HTML>'
	return resp
	
def get_self_id():
	return make_id_string(selfpubkey)

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST'])
@app.route('/<path:path>', methods=['GET', 'POST'])
def proxy(path):
	global securityconfig
	iseph=is_ephemeral()
	ephwarn=''
	if iseph:
		ephwarn='Running in ephemeral mode. Any changes made will not persist.'
	host=str(request.headers.get('Host')).strip()
	if host=='localhost:8000' or host=='127.0.0.1:8000':
		if request.path=='/active':
			if len(routing_table)>0:
				return 'true'
			return 'false'
		if request.path=='/checkstatus':
			return render_template('statuschecker.html')
		return render_template('marbrowser.html')
		
	exit_node_proxy=False
	ismar, nac=check_mariana_host(host, config['nac'], get_contact)
	if not ismar:
		if 'Referer' not in request.headers:
			respcont='Not in Mariana. Use standard web browser.'.encode()
			return Response(respcont, 400)
		referer=request.headers.get('Referer')
		refvalid, refnac=check_referrer(referer, config['nac'], get_contact)
		if not refvalid:
			respcont='Not in Mariana. Use standard web browser.'.encode()
			return Response(respcont, 400)
		exit_node_proxy=True
		nac=refnac

		

	if host=='local.mariana':
		if request.path=='/active':
			if len(routing_table)>0:
				return 'true'
			return 'false'
		if request.path=='/checkstatus':
			return render_template('statuschecker.html')
		
		if len(routing_table)>0:
			return render_template('home.html', nac=f'{config["nac"]}.mariana', id=get_self_id())
		return render_template('notconnected.html')

	if host=='hosts.mariana':
		return known_hosts()
		
	if host=='my.mariana':
		resp= Response(f'{config["nac"]}.mariana')
		return resp
		
	if host=='myid.mariana':
		return jsonify({'nac': f'{config["nac"]}.mariana', 'id': get_self_id()})
		
	if host=='stats.mariana':
		if request.path=='/':
			return render_template('metrics.html', mynac=f'{config["nac"]}.mariana')
		if request.path=='/stat':
			return get_stats()
		
	if host=='viz.mariana':
		if request.path=='/':
			node_table={}
								
			for tempnac in routing_table:
				contact=tempnac
				contact_nac=tempnac
				contactx=contact+'.mariana'
				node_table[contactx]={}
				if routing_table[contact_nac]['hop_count']>4:
					continue
				node_table[contactx]['hop_count']=routing_table[contact_nac]['hop_count']+1
				if routing_table[contact_nac]['hop_count'] ==0:
					node_table[contactx]['next_hop']=f'{config["nac"]}.mariana'
				else:
					node_table[contactx]['next_hop']=f'{routing_table[contact_nac]["next_hop"]}.mariana'
					
				node_table[contactx]['description']=f'{contact_nac}.mariana: {routing_table[contact_nac]["desc"].decode("utf-8", "ignore")}'
				
			json_data=node_table #json.dumps(node_table)
			
			return render_template('vizualizer.html', mynac=f'{config["nac"]}.mariana', mydesc=f'This node: {securityconfig["desc"]}', json_data=json_data)
		
					
					

			
		
	if host=='phonebook.mariana':
		if request.method=='GET':
			if request.path=='/':
				return render_template('phonebook.html', ephwarn=ephwarn)
			if request.path=='/phonebook':
				temp_phonebook= get_whole_phonebook()
				temp_active_phonebook={}
				for contact in temp_phonebook:
					curr_temp_nac=temp_phonebook[contact]
					temp_active_phonebook[f'{contact}.mariana']={}
					temp_active_phonebook[f'{contact}.mariana']['nac']=f'{temp_phonebook[contact]}.mariana'
					if curr_temp_nac in routing_table:
						temp_active_phonebook[f'{contact}.mariana']['desc']=routing_table[curr_temp_nac]['desc'].decode('utf-8', 'ignore')
					else:
						temp_active_phonebook[f'{contact}.mariana']['desc']='Node offline'
				return json.dumps(temp_active_phonebook)
				
			if request.path=='/pubkeyverif':
				temp_phonebook= get_contacts_verif()
				temp_active_phonebook={}
				for contact in temp_phonebook:
					temp_active_phonebook[f'{contact}.mariana']=temp_phonebook[contact]
				return json.dumps(temp_active_phonebook)

			if request.path=='/activenodes':
				temp_active={}
				for tempnac in routing_table:
					temp_active[f'{tempnac}.mariana']={}
					temp_active[f'{tempnac}.mariana']['desc']=routing_table[tempnac]['desc'].decode('utf-8', 'ignore')
					temp_active[f'{tempnac}.mariana']['next_hop']=f'{routing_table[tempnac]["next_hop"]}.mariana'
					temp_active[f'{tempnac}.mariana']['hop_count']=routing_table[tempnac]['hop_count']
					temp_active[f'{tempnac}.mariana']['id']=make_id_string(routing_table[tempnac]['pubkey'])
					if routing_table[tempnac]['hop_count']==0:
						temp_active[f'{tempnac}.mariana']['next_hop']=f'{cam_table[tempnac]["ip"]}:{cam_table[tempnac]["port"]}'
				return json.dumps(temp_active)
				
		if request.method=='POST':
			if request.path=='/save':
				halias=request.form.get('alias')
				if not halias.endswith('.mariana'):
					return 'Invalid alias.'
				halias=halias[:-len('.mariana')]
				dest_nac=request.form.get('contact')
				nac_valid, nac_code=check_mariana_host(dest_nac, config['nac'], get_contact)
				if not nac_valid:
					return 'Invalid NAC.'
				if save_contact(halias, nac_code):
					return 'Contact saved'
				else:
					return 'Contact exists. Not saved'
			if request.path=='/delete':
				halias=request.form.get('alias')
				if not halias.endswith('.mariana'):
					return 'Invalid alias.'
				halias=halias[:-len('.mariana')]
				if delete_contact(halias):
					return 'Deleted'				
				else:
					return 'Delete failed'
			if request.path=='/reverify':
				halias=request.form.get('alias')
				if not halias.endswith('.mariana'):
					return 'Invalid alias.'
				halias=halias[:-len('.mariana')]
				if update_contact_pub(halias):
					return 'Contact reverified'
				else:
					return 'Contact reverification failed'
		
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
				dest_nac_check, dest_nac=check_mariana_host(dest_nac_send, config['nac'], get_contact)
				if dest_nac_send and dest_nac in routing_table:
					send_payload(dest_nac, trench_payload)
			return f'Sent to {tosend} if exists in routing table'

	if host=='cargoship.mariana':
		if request.method=='GET':
			if request.path=='/cargostatus':
				restemp=get_cargo_status(phone_book_reverse_lookup)
				return json.dumps(restemp)
			if request.path=='/':
				return render_template('cargoship.html')
		if request.method=='POST' and request.path=='/send':
			tosend=request.form.get('dest')
			file=request.files['file']
			dest_nac_list = [word for part in tosend.split(',') for word in part.strip().split()]
			file_bytes=file.read()
			filename=file.filename
			for dest_nac_send in dest_nac_list:
				dest_nac_check, dest_nac=check_mariana_host(dest_nac_send, config['nac'], get_contact)
				if dest_nac_send and dest_nac in routing_table:
					cargo_send(dest_nac, file_bytes, filename, send_payload)		
			

			return f'Sent to {tosend} if exists in routing table'

			
		
	if host=='createproxy.mariana':
		if 'destnac' not in request.args:
			return render_template('marnc.html')
		listenport=int(request.args.get('listenport'))
		destport=int(request.args.get('destport'))
		destnac=request.args.get('destnac')
		proto=request.args.get('proto', 'TCP')
		mode=proto=='TCP'
		nac_valid, destnac=check_mariana_host(destnac, config['nac'], get_contact)
		if not nac_valid:
			return 'Invalid NAC'
		if destnac not in routing_table:
			return 'NAC not found. Not starting proxy'
		create_proxy_port(listenport, destport, destnac, mode, send_payload)
		return 'Starting proxy'

	if host=='security.mariana':
		if request.method=='GET':
			if request.path=='/':
				if is_stick():
					return render_template('security.html', stickwarn='You are on stick mode. Unable to enable Web Server or Port Proxy', ephwarn=ephwarn)
				return render_template('security.html', ephwarn=ephwarn)
			if request.path=='/view':
				return json.dumps(securityconfig)
		if request.method=='POST':
			if request.path=='/save':
				secjson=request.get_json()
				if is_stick():
					secjson['web_server_allow']=False
					secjson['port_fw_allow']=[]
				securityconfig=secjson
				save_securityconfig(secjson)
				return 'Security Configurations saved'


	with routing_table_lock:
		if nac not in routing_table:
			logging.warning(f'HOST {host} NOT IN ROUTING TABLE.')
			respcont='Host not in routing table.'.encode()
			return Response(respcont, 400)

	target_url = host
	if path:
		target_url = f"{target_url}/{path}"
	target_url=f'http://{target_url}?'
	logging.info(f"Proxying request to: {target_url}")
	headers = dict(request.headers) 
	if not exit_node_proxy:
		headers['Access-Control-Allow-Origin'] = "*"
		headers['mariana-host']= f'{config["nac"]}.mariana'
	
	try:
		if True:
			reqparam={}
			reqparam['method']=request.method
			reqparam['target_url']=target_url
			reqparam['headers']=headers
			reqparam['args']=dict(request.args)
			reqparam['data']=request.get_data(cache=False).hex()
			reqparamstr=json.dumps(reqparam)
			resp=get_response(nac, reqparamstr)
			respdict=json.loads(resp)
			status_code=respdict['status_code']
			content=bytes.fromhex(respdict['content'])
			dummyheaders=respdict['headers']
			dummyheaders['Host']=host
			dummyheaders['Access-Control-Allow-Origin'] = "*"
			if 'Content-Type' in dummyheaders and 'html' in dummyheaders['Content-Type']:
				content=rewrite_content(content)
			response = Response(content, status_code)
			response.headers=dummyheaders
			return response
			
	except requests.exceptions.RequestException as e:
		logging.error(f"Error proxying request: {e}")
		return f"Error proxying request: {str(e)}", 500

def start_proxyserver():
	logging.info("Starting proxy server on port 8000")
	app.run(host='0.0.0.0', port=8000)

def start_proxythread():
	proxythread=threading.Thread(target=start_proxyserver, daemon=True)
	proxythread.start()		

if __name__ == '__main__':
	start_proxyserver()
	
	

