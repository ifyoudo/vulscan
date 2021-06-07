#from moduls.cscan import *
from moduls.leakscan import *
from moduls.getip import *
from moduls.portscan import *
from moduls.VulScan import *
from optparse import OptionParser
import re
import time
import csv

banner='''
______            _    _         _____                                
|  _  \          | |  (_)       /  ___|                               
| | | | ___  ___ | |_  _  _ __  \ `--.   ___  __ _  _ __    ___  _ __ 
| | | |/ _ \/ __|| __|| || '_ \  `--. \ / __|/ _` || '_ \  / _ \| '__|
| |/ /|  __/\__ \| |_ | || | | |/\__/ /| (__| (_| || | | ||  __/| |   
|___/  \___||___/ \__||_||_| |_|\____/  \___|\__,_||_| |_| \___||_|  v1.0   
                                                                      
'''


def main():
	usage="%prog [-u <target>]"
	optParser=OptionParser(usage)
	optParser.add_option("-u","--url",dest="target")
	optParser.add_option("-l","--leaktype",dest="leaktype")
	optParser.add_option("-s","--scantype",dest="scantype")
	#optParser.add_option("-k","--vulkill",dest="scanvul")
	options,args=optParser.parse_args()
	mytarget=options.target
	leaktype=options.leaktype
	scantype=options.scantype
	#scanvul=options.scanvul
	pattern=r"(([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])\.){3}([01]{0,1}\d{0,1}\d|2[0-4]\d|25[0-5])"
	dicfile='data/bakfile.txt'
	springfile='data/spring.txt'
	print(banner)
	print("开始扫描："+time.asctime( time.localtime(time.time())))
	if mytarget != '' and mytarget != None:
		if leaktype !='' and leaktype !=None:
			print('[*] 开始扫描泄露')
			if not re.search(pattern,mytarget):
				getip=GetIp(mytarget)
				myip=getip.run()
				print('目标IP---->%s'%myip)
			leak=LeakScan(leaktype,dicfile,mytarget,springfile)
			leak.run()

	if scantype !='' and scantype != None:
		if scantype == 'm':
			print('=== 扫描模式：默认扫描 ===')
		elif scantype == 'c':
			print('=== 扫描模式：C段扫描 ===')
		print('[*] 开始扫描端口')
		p=PScan(mytarget)
		suc=p.run(scantype)
		if not len(suc) == 0:
			print('[*] 开始扫描漏洞')
			for target in suc:
				p=VulScan(target)
				p.run()
	print("扫描结束："+time.asctime(time.localtime(time.time())))
if __name__ == '__main__':
	main()