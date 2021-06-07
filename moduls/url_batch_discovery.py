import os
import sys
import json
import time
import pandas as pd

class UrlBatchDiscovery:
	def __init__(self, file, match_string, ports, threads):
		self.file=file
		self.match_string=match_string
		self.tmpoutput='../results/tmp.txt'
		self.output='../results/target'
		self.ports=ports
		self.threads=threads

	def UrlCheck(self,):
		if not os.path.exists('../results'):
			os.makedirs('../results')
		if self.match_string == 'null':
			os.system(
				'httpx -l %s -threads %s -title -title -json -silent -ports %s -follow-redirects > %s' %(
					self.file,self.threads,self.ports,self.tmpoutput
					)
				)
		else:
			os.system(
				'httpx -l %s -threads %s -title -title -json -silent -ports %s -match-string "%s" -follow-redirects > %s'%(
					self.file,self.threads,self.ports,self.match_string,self.tmpoutput
					)
				)
	def myoutput(self):
		pool=[]
		self.UrlCheck()
		f=open(self.tmpoutput,encoding='utf-8')
		ftxt=open('../results/'+self.output+'.txt','a')
		for line in f.readlines():#连接数据库信息
			line=json.loads(line.strip('\n'))
			info={}
			info['url']=line['url']
			info['url'] = line['url']
			info['title'] = line['title']
			info['webserver'] = line['webserver']
			info['status-code'] = line['status-code']
			info['ip'] = line['ip']
			info['content-length'] = line['content-length']
			info['response-time'] = line['response-time']
			pool.append(info)
			ftxt.write(str(line['url'])+'\n')
		f.close()
		ftxt.close()
		if len(pool) == 0:
			print('[-] 未获取到数据')
		else:
			df=pd.DataFrame(pool)
			df.to_excel(self.output+'.xls',
				columns=['url', 'title', 'webserver', 'status-code', 'ip', 'content-length', 'response-time'],
				index=False, encoding='utf_8_sig'
				)
		os.remove(self.tmpoutput)
	def run(self):
		self.myoutput()

file='a.txt'
match_string='null'
ports='80'
th='60'
u=UrlBatchDiscovery(file,match_string,ports,th)
u.run()