from flask import Flask, render_template, request, Response
import threading
import queue
import time
import json

import userops
	


app = Flask(__name__)
message_queue = queue.Queue()
client_queues = []
client_queues_lock = threading.Lock()

def user_response(source_nac, payload):
	response=(f'{source_nac}: (To you) {payload.decode()}')
	with client_queues_lock:
		for q in client_queues:
			q.put({"message": response})
	return None
	
userops.user_response=user_response

from internals import *


@app.route('/')
def index():
	return render_template('index.html')

@app.route('/send', methods=['POST'])
def send_message():
	message = request.form.get('message')
	nac= request.form.get('nac')
	if message:
		message_queue.put(message)
		with client_queues_lock:
			for q in client_queues:
				q.put({"message": f"You: (To {nac}) {message}"})
				send_payload(nac, message.encode())
			return {"status": "Message sent"}, 200
	return {"status": "No message provided"}, 400

@app.route('/stream')
def stream():
	def generate():
		client_queue = queue.Queue()
		with client_queues_lock:
			client_queues.append(client_queue)
		try:
			while True:
				message_data = client_queue.get()
				yield f"data: {json.dumps(message_data)}\n\n"
		except GeneratorExit:
			with client_queues_lock:
				if client_queue in client_queues:
					client_queues.remove(client_queue)
    
	return Response(generate(), mimetype='text/event-stream')

if __name__ == '__main__':
	init_threads()
	app.run(host='localhost')