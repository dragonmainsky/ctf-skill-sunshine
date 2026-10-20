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
