import requests
import json
import importlib

class VulScan:
	def __init__(self,target):
		self.target=target

	'''
	1.读取json文件，遍历？ 怎么遍历，根据文件名前的数字遍历？另取一个变量？
	2.读取json文件，然后解析json，通过键取值？
	3.解决
	'''
	def scan(self,target):
		f=open('data/vul.json')
		vuldata=json.load(f)
		for num in range(1,len(vuldata)+1):
			mymodul='moduls.Vulmoduls.'+str(num)+'-'+vuldata[str(num)]
			modulc=importlib.import_module(mymodul)
			r=modulc.POC(target)
			r.atack()

	def run(self):
		self.scan(self.target)



'''
f=open('../data/vul.json')
vuldata=json.load(f)
print(vuldata)
'''

'''
target='192.168.209.155:6379'
target2='http://192.168.209.155:27017/'
v=VulScan(target)
v2=VulScan(target2)
print('目标%s开始扫描...'%target)
v.run()
print('目标%s开始扫描...'%target2)
v2.run()
'''