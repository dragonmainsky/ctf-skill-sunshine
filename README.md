<div align="center">

# CTF Skill by Sunshine

**สกิลสำหรับ AI agent ที่พาแก้ CTF ตั้งแต่ดึงโจทย์ ยันเขียน writeup ภาษาไทย**

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](#cross-platform)
[![Agent Skill](https://img.shields.io/badge/Agent%20Skill-SKILL.md-purple.svg)](SKILL.md)
[![GitHub stars](https://img.shields.io/github/stars/dragonmainsky/ctf-skill-sunshine?style=social)](https://github.com/dragonmainsky/ctf-skill-sunshine)

[ภาพรวม](#ภาพรวม) · [ติดตั้ง](#ติดตั้ง) · [เริ่มใช้งาน](#เริ่มใช้งาน) · [Tool Manager](#external-tool-manager) · [English](#english-summary)

</div>

---

## ภาพรวม

`ctf-skill-sunshine` คือ **Agent Skill** แบบพกพาสำหรับงาน CTF (Capture The Flag) ใช้ได้กับ Claude Code, OpenCode, Codex, ChatGPT และไคลเอนต์ที่รองรับ `SKILL.md`

จุดเด่น:

- **แยก 2 โหมดชัดเจน** — ตอนแก้ตอบสั้น `Found / Means / Next` (เนื้อ 75%) หลังได้ flag ค่อยเขียน writeup ภาษาไทยแบบละเอียด
- **CTFd automation** — login (nonce flow), ดึงโจทย์ + ไฟล์ + hint, ส่ง flag ผ่าน CLI
- **Playbook 7 หมวด** — Web, Reverse, Crypto, Forensics, Pwn, Misc, Mobile พร้อม toolbox ~140 ตัวใน `references/TOOLS.md`
- **OS-aware** — ตรวจจับ Windows / Linux / macOS / WSL แล้วเลือกคำสั่งที่รันได้จริง มี Python fallback ทุกงาน
- **External tool manager** — ดาวน์โหลด/ติดตั้งเครื่องมือลง `tools/` พร้อมตรวจ SHA-256 ก่อนรัน
- **Multi-agent coordinator (on-demand)** — แตก worker เฉพาะตอนมีโจทย์หลายหมวดหรือต้องการยิงหลาย hypothesis
- **Writeup ภาษาไทย** — โครงสร้างบังคับครบ TL;DR, Recon, Vulnerability, Exploitation, Flag, Lessons Learned

> ใช้เมื่อผู้ใช้พิมพ์ trigger: **`sunshine_CTF`**

---

## โครงสร้างโปรเจกต์

```text
ctf-skill-sunshine/
├─ SKILL.md                  # ตัวสกิลหลัก (activation, modes, playbooks, checklist)
├─ README.md                 # ไฟล์นี้
├─ LICENSE                   # MIT
├─ references/
│  └─ TOOLS.md               # Toolbox ~140 ตัว แยก 7 หมวด + ตารางเทียบ Linux/Windows
├─ scripts/
│  ├─ ctfd_common.py         # login + session + nonce + cookie reuse
│  ├─ fetch_ctf.py           # ดึงโจทย์/ไฟล์/hint เป็นโฟลเดอร์
│  ├─ submit_flag.py         # ส่ง flag ด้วย --id หรือ --name
│  ├─ unzip_recursive.py     # แตก zip/tar ซ้อนหลายชั้นอัตโนมัติ
│  ├─ tool_manager.py        # OS detection + download/install/verify/run tools
│  └─ requirements.txt       # requests>=2.31
└─ tools/
   ├─ README.md              # คู่มือโฟลเดอร์ tools
   ├─ strings.py             # strings ข้ามแพลตฟอร์ม
   ├─ factordb.py            # แยกตัวประกอบผ่าน FactorDB API
   ├─ jwt_tool.py            # วิเคราะห์/ปลอม JWT
   └─ rockyou-10k.txt        # dictionary 10,000 รหัส
```

---

## ติดตั้ง

### ต้องมี

- Python **3.9+** และ `pip`
- `git`
- (ไม่บังคับ) Burp Suite, Ghidra, Wireshark, pwntools, SageMath ฯลฯ — สกิลจะช่วยเลือก/ติดตั้งที่จำเป็นให้

```bash
pip install -r scripts/requirements.txt
```

### ติดตั้งเป็น Skill

```bash
git clone https://github.com/dragonmainsky/ctf-skill-sunshine.git
```

**Claude Code**

```bash
# Global
mkdir -p ~/.claude/skills/ctf-skill-sunshine
cp -r ctf-skill-sunshine/. ~/.claude/skills/ctf-skill-sunshine/

# Project-only (รันจาก root ของโปรเจกต์ที่ต้องการใช้)
mkdir -p .claude/skills/ctf-skill-sunshine
cp -r ../ctf-skill-sunshine/. .claude/skills/ctf-skill-sunshine/
```

**OpenCode**

```bash
# Global
mkdir -p ~/.config/opencode/skill/ctf-skill-sunshine
cp -r ctf-skill-sunshine/. ~/.config/opencode/skill/ctf-skill-sunshine/

# Project-only (รันจาก root ของโปรเจกต์ที่ต้องการใช้)
mkdir -p .opencode/skill/ctf-skill-sunshine
cp -r ../ctf-skill-sunshine/. .opencode/skill/ctf-skill-sunshine/
```

**Windows (PowerShell)**

```powershell
git clone https://github.com/dragonmainsky/ctf-skill-sunshine.git
New-Item -ItemType Directory -Force "$HOME\.claude\skills\ctf-skill-sunshine" | Out-Null
Copy-Item -Recurse -Force ".\ctf-skill-sunshine\*" "$HOME\.claude\skills\ctf-skill-sunshine\"
```

**Codex / ChatGPT / ไคลเอนต์อื่น** — วางโฟลเดอร์นี้ใน skills directory ของไคลเอนต์นั้น หรือ import `SKILL.md` ตามวิธีของแพลตฟอร์ม

จากนั้นพิมพ์ `sunshine_CTF` ในแชทเพื่อเปิดใช้

---

## เริ่มใช้งาน

### 1. ตั้งค่า credential

ลำดับความสำคัญ (ตัวแรกชนะ):

1. flags: `--url`, `--user`, `--pass`
2. environment variables: `CTF_URL`, `CTF_USER`, `CTF_PASS`
3. ไฟล์ `~/.ctfd_creds.json`

```json
{
  "url": "https://ctf.example.com",
  "user": "your_username",
  "pass": "your_password"
}
```

**Linux / macOS**

```bash
export CTF_URL="https://ctf.example.com"
export CTF_USER="your_username"
export CTF_PASS="your_password"
```

**Windows (PowerShell)**

```powershell
$env:CTF_URL  = "https://ctf.example.com"
$env:CTF_USER = "your_username"
$env:CTF_PASS = "your_password"
```

> ห้าม commit password หรือไฟล์ credential ลง git — `.gitignore` กันไว้ให้แล้ว

### 2. ดึงโจทย์

```bash
python scripts/fetch_ctf.py --out ./challenges
python scripts/fetch_ctf.py --unsolved --out ./challenges
python scripts/fetch_ctf.py --category web --out ./challenges
```

ผลลัพธ์:

```text
challenges/
├─ index.md                 # ภาพรวมทุกข้อ
└─ 001_challenge_name/
   ├─ README.md            # description + hint
   ├─ challenge.json       # raw API response
   └─ files...             # ไฟล์แนบ
```

### 3. ส่ง flag

```bash
python scripts/submit_flag.py --list
python scripts/submit_flag.py --id 75 --flag 'FLAG{...}'
python scripts/submit_flag.py --name "Gemini" --flag 'FLAG{...}'
```

### 4. แตกไฟล์ซ้อนหลายชั้น

```bash
python scripts/unzip_recursive.py nested.zip
```

---

## External Tool Manager

จัดการเครื่องมือภายนอกใน `tools/` แบบมี checksum

```bash
# ตรวจ OS / shell / utility ที่มี
python scripts/tool_manager.py --os

# ดูเครื่องมือที่ติดตั้งแล้ว + presets
python scripts/tool_manager.py list

# ดาวน์โหลดไฟล์หรือ archive (แตกอัตโนมัติ)
python scripts/tool_manager.py download --url <URL> --extract

# โคลนจาก Git
python scripts/tool_manager.py git --repo <git_url> --name <folder>

# ติดตั้ง preset
python scripts/tool_manager.py install strings-py
python scripts/tool_manager.py install factordb
python scripts/tool_manager.py install rockyou-10k
python scripts/tool_manager.py install stegsolve
python scripts/tool_manager.py install jwt_tool
python scripts/tool_manager.py install cyberchef
python scripts/tool_manager.py install sysinternals-strings

# รันเครื่องมือ
python scripts/tool_manager.py run factordb 123456789
python scripts/tool_manager.py run strings.py sample.bin -p "flag"

# ตรวจ SHA-256
python scripts/tool_manager.py checksum --all
python scripts/tool_manager.py verify
python scripts/tool_manager.py verify --strict

# บังคับตรวจ hash ตอนติดตั้ง
python scripts/tool_manager.py download --url <URL> --sha256 <64-hex>
```

**กฎความปลอดภัย:** hash ไม่ตรง = ลบไฟล์ทิ้ง ห้ามรัน และให้ `verify` ก่อนรัน binary ที่เพิ่งดาวน์โหลดทุกครั้ง

---

## Cross-platform

สกิลตรวจจับ OS ก่อนเลือกคำสั่งเสมอ ตัวอย่าง:

| งาน | Linux / WSL | Windows (PowerShell) | Python fallback |
| :--- | :--- | :--- | :--- |
| strings | `strings f \| grep -i flag` | `Select-String -Pattern "flag" f` | `python tools/strings.py f -p flag` |
| hexdump | `xxd -p f` | `Format-Hex f` | `python -c "print(open('f','rb').read(64).hex(' '))"` |
| grep | `grep -rEi "x" .` | `Select-String -Path * -Pattern "x"` | Python regex |
| HTTP | `curl -s URL` | `curl.exe -s URL` | `requests` |
| netcat | `nc host port` | `Test-NetConnection` | `python -c "import socket; ..."` |
| hash | `sha256sum f` | `Get-FileHash -Algorithm SHA256 f` | `hashlib` |
| nested zip | `unzip` | `Expand-Archive` / 7z | `python scripts/unzip_recursive.py f` |

> ELF / pwn binary รันบน Windows ตรงๆ ไม่ได้ — ใช้ WSL/Docker หรือวิเคราะห์ static ด้วย `pyelftools`

---

## โหมดการทำงาน

| โหมด | ใช้ตอนไหน | รูปแบบ |
| :--- | :--- | :--- |
| **Mode 0 — CTFd Ops** | login / fetch / submit | สั้น ตรงประเด็น ใช้สคริปต์ใน `scripts/` |
| **Mode 1 — During Solving** | กำลังแก้โจทย์ | `Found / Means / Next` ไม่เกิน 3–6 บรรทัด |
| **Mode 2 — Writeup** | ได้ flag แล้ว | writeup ภาษาไทยเต็มรูปแบบตาม template |

Trigger: `sunshine_CTF`, `ctf`, `flag`, `writeup`, `pwn`, `reverse`, `forensics`, `crypto`, `web exploit`, `apk`, `flutter`, `submit flag`, `ดึงโจทย์`, `ส่งธง`, `multi-agent` ฯลฯ

---

## Multi-agent Coordinator

- **Default = single agent**
- spawn worker เมื่อ: มีโจทย์ unsolved ≥ 3 ข้อต่างหมวด, ผู้ใช้สั่ง `parallel` / `multi` / `ลุยพร้อมกัน`, หรือโจทย์เดียวแต่ตันและต้องยิงหลาย hypothesis
- Worker 1 ตัว = 1 โจทย์ หรือ 1 hypothesis, คืนเฉพาะ `Found / Means / Next` + payload
- Coordinator รวมผลและเป็นคน submit เอง (กันส่งซ้ำเกิน 3 ครั้ง)

---

## ความปลอดภัยและข้อจำกัด

- ใช้กับ CTF / ระบบที่คุณมีสิทธิ์เข้าร่วมหรือทดสอบเท่านั้น
- ห้าม commit credential, token, flag หรือไฟล์โจทย์ที่แพลตฟอร์มห้ามเผยแพร่
- เครื่องมือภายนอกถูกตรวจ SHA-256 แต่ยังควรอ่านโค้ด/แหล่งที่มาก่อนรัน
- สกิลนี้เป็นผู้ช่วย ไม่ได้แทนการคิดวิเคราะห์ของมนุษย์

---

## English summary

**CTF Skill by Sunshine** is a portable Agent Skill for CTF competitions. It automates CTFd workflows (login, challenge/file/hint fetching, flag submission), provides playbooks for seven categories (Web, Reverse, Crypto, Forensics, Pwn, Misc, Mobile), selects commands based on the host OS, manages external tools with SHA-256 verification, and writes detailed Thai writeups after each solve.

Works with Claude Code, OpenCode, Codex, ChatGPT, and any client that supports `SKILL.md`.

```bash
pip install -r scripts/requirements.txt
export CTF_URL="https://ctf.example.com" CTF_USER="user" CTF_PASS="pass"
python scripts/fetch_ctf.py --unsolved --out ./challenges
```

Trigger: `sunshine_CTF`

---

## License

[MIT](LICENSE) © sunshine ([dragonmainsky](https://github.com/dragonmainsky))

## Credits

- Author: **sunshine**
- Built for Claude Code, OpenCode, Codex, and ChatGPT
- Toolbox and playbooks compiled from the CTF community — credit goes to the original tool authors
