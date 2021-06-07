class Base:
	def __init__(self,scan_target='',scan_port='80',scan_thread='100'):
		self.scan_target=self.split_ip(scan_target)
		self.scan_port=scan_port
		self.scan_thread=scan_thread

	def split_ip(self,ip):
		iplist=[]
		target=ip.split('.')[:-1][0]+'.'+ip.split('.')[:-1][1]+'.'+ip.split('.')[:-1][2]+'.'
		#print(target)
		for i in range(1,255):
			iplist.append(target+str(i))
		print(iplist)
		return iplist

	def slit_port(self,port):
		pass

b=Base('192.168.10.1')




