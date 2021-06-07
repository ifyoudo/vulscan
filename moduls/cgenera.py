#from Base import *
import os
import subprocess
class Cgenera:
	def __init__(self,target,):
		self.target=target

	def split_ip(self,target):
		if 'http' in target:
			target=target.strip('http://').strip('https://').strip('/')
		ip_list=[]
		ip=target.split('.')[:-1][0]+'.'+target.split('.')[:-1][1]+'.'+target.split('.')[:-1][2]
		for i in range(1,255):
			ip_list.append(ip+'.'+str(i))
		return ip_list
	def run(self):
		return self.split_ip(self.target)

'''
ip='192.168.8.1'
c=Cgenera(ip)
print(c.run())
'''