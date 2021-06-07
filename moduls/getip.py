import requests
import socket

class GetIp():
	"""docstring for GetIp"""
	def __init__(self, target):
		self.target=target

	def getip(self,target):
		domain=''
		if 'http' in target:
			domain=target.replace('http://','').replace('https://','').strip('/')
		else:
			domain=target
		#print(domain)
		ip=socket.gethostbyname(domain)
		return ip
		#print(ip)
	def run(self):
		return self.getip(self.target)
		#print('目标IP----->%s'%self.getip(self.target))
'''
	def getip2(self):
		
		nodelist=['5d6f1340bf4b3a82dbd64845f7ccd293']
		headers={
		'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36',
		'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
		'X-Requested-With': 'XMLHttpRequest',
		'Referer': 'https://www.wepcc.com/',
		'Cookie': 'Hm_lvt_c001bd3b5a4d3a12e3ae1a5373826c40=1606734440; Hm_lpvt_c001bd3b5a4d3a12e3ae1a5373826c40=1606734440'
		}
		data={
		'node':'8002b9a5-9676-33e1-ac7e-e72a09dff94d',
		'host':self.target
		}
		myapi='https://www.wepcc.com/check-ping.html'
		res=requests.post(url=myapi,data=data,headers=headers)
		txt=res.text
		print(txt)

'''

'''
target='www.mytools.com'
g=GetIp(target)
print(g.run())
'''