# vulscan

很久以前练手的一个小Demo，
* 主要是自动对目标进行端口C段扫描，然后进行漏洞验证。
* 主机发现和端口扫描直接调用的nmap和masscan
* 漏洞扫描，主要是动态调用导入moduls中的那些poc模块
```
运行
python DestinScaner.py
```
