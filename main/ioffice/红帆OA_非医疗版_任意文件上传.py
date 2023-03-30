import time

import requests
import urllib3


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(url):
    target_url1 = url + "/ioffice/prg/set/Report/ioRepPicAdd.aspx"
    data = '{ioffice}'
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Mobile Safari/537.36",
        "Content-type": "application/x-www-form-urlencoded"
    }
    print(now_time() + " [INFO]     正在检测红帆任意文件上传漏洞")
    try:
        urllib3.disable_warnings()
        res1 = requests.post(url=target_url1, headers=headers, data=data, verify=False)
        if res1.status_code == 200:
            print(now_time() + " [SUCCESS]     暂无exp，存在红帆任意文件上传:{}".format(target_url1))
        else:
            print(now_time() + " [WARNING]  不存在红帆任意文件上传")
    except Exception as e:
        print(now_time() + " [ERROR]    目标请求失败 ")
