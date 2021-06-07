import requests


class POC:
	def __init__(self,target):
		self.target=target

	def verify(self,target):
		headers={
		'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36'
		}
		if 'http:' not in target:
			target='http://'+target
		try:
			res=requests.get(url=target,timeout=1,headers=headers).text
			if ("access" in res) and ("MongoDB" in res) and ("port" in res):
				print('[+]发现目标mongo未授权访问----->%s'%target)
		except:
			pass
		
		print('[*]2 poc done')

	def atack(self):
		print('[*]2 poc start')
		self.verify(self.target)

