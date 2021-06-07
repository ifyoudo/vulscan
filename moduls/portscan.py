#from Base import *
import socket
from .cgenera import *
import telnetlib

portlist=[80,81,445,1433,1521,3306,7001,8000,8080,8081,9090,9000,6379,27017]
class PScan:
	def __init__(self, host):
		#supes PortScan, self.__init__()
		self.host=host

	def scan(self,host):
		#sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
		#sock.settimeout(1)
		suc=[]
		host=host.strip('http://').strip('http://').strip('/')
		server=telnetlib.Telnet()
		for port in portlist:
			try:
				server.open(host,port,timeout=1)
				print('[+] 发现目标端口开放----> %s:%a'%(host,port))
				suc.append('%s:%a'%(host,port))
			except:
				print('[-] %s:%a 未发现目标'%(host,port))
		return suc
			

	def run(self,scantype):
		if scantype == 'c':
			print('[*] 开始C段扫描')
			clist=[]
			c=Cgenera(self.host)
			iplist=c.run()
			for ip in iplist:
				clist+=self.scan(ip)
			return clist

		elif scantype == 'm':
			mlist=self.scan(self.host)
			return mlist

'''
host='192.168.209.155'
p=PScan(host)
p.run()
for i in suc:
	print('[+] 发现目标---->',i)
'''