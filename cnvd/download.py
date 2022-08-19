#!/usr/bin/env python3
import re
import os
import sys
import argparse
import logging
import requests
import pyduktape2
from concurrent.futures import ThreadPoolExecutor, as_completed

logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
GLOBAL_JS = r'''var navigator = {
    'userAgent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
}
var location = {
    "ancestorOrigins":{},
    "href":"https://www.cnvd.org.cn",
    "origin":"http://www.cnvd.org.cn",
    "protocol":"https:",
    "host":"www.cnvd.org.cn",
    "hostname":"www.cnvd.org.cn",
    "port":"",
    "pathname":"/",
    "search":"",
    "hash":"",
}
var document = {

}
var setTimeout = function (callback, t) {
    callback();
}
var window = {
    navigator: navigator,
    location: location,
    document: document,
}
'''
TARGET = 'https://www.cnvd.org.cn'
USER_AGENT = 'Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0'
SCRIPT_PATTERN = re.compile(rb'<script>(.+)</script>', re.I | re.S)
FILENAME_PATTERN = re.compile(r'filename=(.*)', re.I | re.S)


class CNVD(object):
    def __init__(self, worker: int = 20, from_id: int = 1, to_id: int = 9999):
        self.from_id = from_id
        self.to_id = to_id
        self.jsenv = pyduktape2.DuktapeContext()
        self.jsenv.eval_js(GLOBAL_JS)
        self.session = requests.session()
        self.session.headers = {
            'User-Agent': USER_AGENT
        }
        self.pool = ThreadPoolExecutor(max_workers=worker)

    @staticmethod
    def parse_cookie(cookie: str):
        start = cookie.find('=')
        if start < 0:
            return None

        name = cookie[:start]
        end = cookie.find(';')
        if end >= 0:
            return name, cookie[start + 1:end]
        else:
            return name, cookie[start + 1:]

    @staticmethod
    def get_script(data: bytes) -> bytes:
        g = SCRIPT_PATTERN.search(data)
        if g is None:
            return b''

        return g.group(1)

    def eval_cookie(self, script: bytes):
        self.jsenv.eval_js(script)
        cookie = self.jsenv.eval_js('document.cookie')
        return self.parse_cookie(cookie)

    def prepare_cookie(self):
        response = self.session.get(TARGET)
        script = self.get_script(response.content)
        name, cookie = self.eval_cookie(script)
        response = self.session.get(TARGET, cookies={name: cookie})
        script = self.get_script(response.content)
        name, cookie = self.eval_cookie(script)
        self.session.cookies.set(name, cookie)

    def download(self, to_path):
        if not os.path.exists(to_path):
            os.makedirs(to_path)

        task_list = []
        for i in range(self.from_id, self.to_id):
            task_list.append(self.pool.submit(self.download_one, i, to_path))

        for future in as_completed(task_list):
            data = future.result()
            if data:
                sys.stdout.write(f"{data}\n")
                sys.stdout.flush()

    def download_one(self, i, to_path):
        target = TARGET + f'/shareData/download/{i}'
        done = False
        # 重试 5 次
        for i in range(5):
            try:
                r = self.session.get(target, stream=True)
            except Exception as e:
                logging.warning(f'{target} download error {e}')
            else:
                done = True
                break
        if not done:
            logging.error(f'{target} download error')
            return

        if 'Content-disposition' not in r.headers:
            logging.info(f"{target} not exists")
            return

        g = FILENAME_PATTERN.search(r.headers['Content-disposition'])
        if g is None:
            logging.warning(f'{target} download format error')
            return

        filename = g.group(1)
        with open(os.path.join(to_path, filename), 'wb') as f:
            for data in r.iter_content(4096):
                if data:
                    f.write(data)
                    f.flush()

            logging.info(f'{target} download complete')

        return os.path.join(to_path, filename)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='crawler for CNVD vulnerabilities XMLs')
    parser.add_argument('-o', '--dir', type=str, required=True, help='output path')
    parser.add_argument('-w', '--worker', type=int, default=20, help='worker count')
    # 这里是循环遍历所有的 id 来下载全量的数据
    # 目前观测到的最小的数字没有小于 200
    # 目前观测到的最大的数字没有大于 1200
    parser.add_argument('--from', type=int, default=200, help='from ID')
    parser.add_argument('--to', type=int, default=1200, help='to ID')
    args = parser.parse_args()

    cnvd = CNVD(args.worker, getattr(args, 'from'), args.to)
    cnvd.prepare_cookie()
    cnvd.download(args.dir)

