import requests
import json
import logging
token = "github_pat_11AKR33JY0CQqWTwShYDH3_"
token=token+ "7fTwm3UXHSKjkG8GY8leKID7kStb187xIamaBN3XZcm76PKILKWXtZSzUG4"
owner = "AdityaMitra5102"
repo = "Project-Mariana"
issue_number = 1
url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}

def post_comment(comment_body):
	try:
		logging.info(f'Attempting to post {comment_body}')
		data = {"body": comment_body}
		response = requests.post(url, headers=headers, data=json.dumps(data), proxies={'http':None, 'https':None})
		logging.info(f'Github comment creation status_code {response.status_code} {response.text}')
	except Exception as e:
		logging.error(f'Github comment creation failed {e}')

def get_comment():
	try:
		response = requests.get(url, headers=headers, proxies={'http':None, 'https':None})
		logging.info(f'Github comment creation status_code {response.status_code}')
		comments=response.json()
		res=[]
		for comment in comments:
			res.append(comment['body'])
		logging.info('Github comments fetched')
		return res
	except Exception as e:
		logging.error(f'Github comment fetching error {e}')
		return []
		
def get_trackers_git(trackers):
	commentlist=get_comment()
	for comment in commentlist:
		try:
			info=json.loads(comment)
			
			trackername=f'{info["ip"]}:{info["port"]}'
			trackercontent={'ip': info['ip'], 'port': info['port']}
			if trackername not in trackers:
				trackers[trackername]=trackercontent
		except Exception as e:
			logging.error(f'Not valid tracker {comment} {e}')
	return trackers
	
