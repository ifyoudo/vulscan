# -*- coding: utf-8 -*-
import requests
import re

headers={
'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.66 Safari/537.36'
}
suc_list=[]
class LeakScan:
	def __init__(self,mytype,dictfile,target,springfile):
		self.dictfile=dictfile
		self.target=target
		self.springfile=springfile
		self.mytype=mytype
	
	def BakScan(self,target,bdict):
		if 'http' not in target:
			target='http://'+target+'/'
		pattern=r"(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])"
		fb=open(bdict)
		if re.search(pattern,target):
			for line in fb:
				myurl=target+line.strip('\n')
				print('[*]正在扫描%s'%myurl)
				try:
					res=requests.get(url=myurl,headers=headers)
					if res.status_code == 200 and int(res.headers['Content-Length']) > 1000:
						self.save(target)
						suc_list.append(myurl)
						#print('[+] %s'%myurl)
				except Exception:
					continue	
					
		else:
			list=self.generate_bak(target)
			for line in fb:
				list.append(line.strip('\n').strip('/'))
			for dic in list:
				myurl=target+dic
				print('[*]正在扫描%s'%myurl)
				try:
					res=requests.get(url=myurl,headers=headers)
					if res.status_code == 200 and int(res.headers['Content-Length']) > 1000:
						self.save(target)
						suc_list.append(myurl)
						#print('[+] %s'%myurl)
				except Exception:
					continue
		fb.close()
		return suc_list

	def SpringScan(self,target,sdict):
		if 'http' not in target:
			target='http://'+target
		fs=open(sdict)
		for line in fs:
			myurl=target+line.strip('\n')
			#print(line)
			try:
				res=requests.get(url=myurl,headers=headers)
				#print(myurl)
				if res.status_code == 200:
					print('[+]发现spring配置泄露--->%s'%myurl)
				else:
					print('[-]%s'%myurl)
			except Exception as e:
				print(e)
				continue

	def generate_bak(self,mytarget):
		dictlist=[]
		tmp=''
		i=0
		exts=['.rar','.zip','.7z','.tar','.tar.7z','.tar.gz','.tar.bz2','.tgz']
		if 'http' in mytarget:
			target=mytarget.strip('http://').strip('https://').strip('/')
			for i in exts:
				dictlist.append('/'+target+i)
		domain=target.split('.')[:-1][1]
		for i in exts:
			dictlist.append('/'+domain+i)
		domain2=target.split('.')[:-1][0]+'.'+target.split('.')[:-1][1]
		for i in exts:
			dictlist.append('/'+domain2+i)		
		return dictlist

	def run(self):
		if self.mytype == 'bak':
			self.BakScan(self.target,self.dictfile)
			for suc in suc_list:
				print('[+]发现备份文件泄露----->%s'%suc)

		if self.mytype == 'spring':
			self.SpringScan(self.target,self.springfile)
	def save(self,str):
		f=open('result.txt','a')
		f.write(str+'\n')
		f.close()



	
dicfile="rar.txt"
springfile="../data/spring.txt"
mytype='bak'
f=open('target.txt','r')
for url in f.readlines():
	s=LeakScan(mytype,dicfile,url.strip('\n'),springfile)
	s.run()
f.close()
s.run()
