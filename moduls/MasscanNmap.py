import nmap
import json
import os
import re
import sys
import threading
class mnPortScan:
	"""docstring for mnPortScan"""
	def __init__(self, target, ports, ):
		self.target=target
		self.ports=ports
		self.info_ip={}

	def Masscan(self,):
		if os.name == 'posix':
			os.system('chmod +777 ./masscan/masscan')
			if 'txt' in self.target:
				# --rate 1000 发包速 1000 --wait 扫描全部结束后等待3秒用于接受剩余返回包
				mscan=os.popen('./masscan/masscan -iL %s --wait 3 -p %s  --rate 1000'%(self.target,self.ports))
			else:
				mscan=os.popen('./masscan/masscan %s --wait 3 -p %s  --rate 1000'%(self.target,self.ports))
		elif os.name == 'nt':
			if 'txt' in self.target:
				mscan=os.popen('.\masscan\masscan.exe -iL %s --wait 3 -p %s  --rate 1000'%(self.target,self.ports))
			else:
				mscan=os.popen('.\masscan\masscan.exe %s --wait 3 -p %s  --rate 1000'%(self.target,self.ports))
		mresult=mscan.read()
		mscaninfolist=mresult.strip('\n').split('\n')
		if len(mscaninfolist) == 1:
			print('')
			sys.exit()
		if len(mscaninfolist) < 50:
			#print(mscaninfolist)
			for info in mscaninfolist:
				reinfo=re.search(re.compile(r'Discovered open port (\d+?)/tcp on (.*)'),info.strip(' '))
				if reinfo.group(2) in self.info_ip:
					self.info_ip[reinfo.group(2)].append(reinfo.group(1))
				else:
					lis = [reinfo.group(1)]
					self.info_ip[reinfo.group(2)] = lis
		else:
			print('WAF!!!')
		#print(self.info_ip)

	def Nmap(self,ip):
		infos=[]
		nmscan=nmap.PortScanner()
		print('————————————————')
		print(ip)
		for port in self.info_ip[ip]:
			print('port:'+port)
			try:
				# nmap扫描参数 -T5:疯狂扫描速度 -Pn:不ping -sV:端口对应服务版本 -O:系统指纹识别
				nminfo=nmscan.scan(hosts=ip, ports=port, arguments='-T5 -Pn -sV -O')
				try:
					mylist=list(nminfo['scan'][ip].keys())
					if 'tcp' in mylist:
						loc=mylist.index('tcp')
					elif 'udp' in mylist:
						loc=mylist.index('udp')
					porttype=list(nminfo['scan'][ip].keys())[loc]
					name=nminfo['scan'][ip][porttype][int(port)]['name']
					product=nminfo['scan'][ip][porttype][int(port)]['product']
					version=nminfo['scan'][ip][porttype][int(port)]['version']
					extrainfo=nminfo['scan'][ip][porttype][int(port)]['extrainfo']
					#osmatch=nminfo['scan'][ip]['osmatch'][0]
					#print(osmatch)
					serverinfo=name+' '+extrainfo+'\n'+product+' version:'+version
				except:
					serverinfo=''
			except:
				serverinfo=''
			print(serverinfo)
			print('---------')
	def run(self,):{finished: 1}

		self.Masscan()
		for ip in self.info_ip.keys():
			print('...',ip)
			self.Nmap(ip)
		


#test('./masscan/masscan.json')
ports='1-5000'
mn=mnPortScan('39.98.225.4',ports)
mn.run()
