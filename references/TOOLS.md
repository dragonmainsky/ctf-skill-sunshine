# CTF Tools by Sunshine — รวมเยอะ จบในไฟล์เดียว

> หลัก: ติดอะไร -> เปิดหัวข้อนั้น -> รันตามลำดับ checklist อย่าเดามั่ว
> `★` = ต้องมีก่อนแข่ง / ไม่มีคือเสียเปรียบ

## 0. Base / General (ทุกหมวดใช้) & OS Awareness

### ตรวจสอบ OS และสภาพแวดล้อมก่อนเลือกเครื่องมือ
```bash
python scripts/tool_manager.py --os
```

### การดาวน์โหลดและจัดการเครื่องมือภายนอก (`tools/` folder)
```bash
# ดูเครื่องมือใน tools/ และ presets ที่พร้อมโหลด
python scripts/tool_manager.py list

# ดาวน์โหลด tool / archive จาก URL พร้อมแตกไฟล์ลง tools/
python scripts/tool_manager.py download --url <URL> [--extract]

# ติดตั้ง Quick Presets ลง tools/ อัตโนมัติ
python scripts/tool_manager.py install strings-py      # strings ข้ามแพลตฟอร์ม (Windows/Linux/Mac)
python scripts/tool_manager.py install factordb        # CLI แยกตัวประกอบเลขใหญ่ผ่าน FactorDB API
python scripts/tool_manager.py install rockyou-10k     # Dictionary 10k รหัสผ่านสำหรับ brute force
python scripts/tool_manager.py install stegsolve       # Stegsolve JAR สำหรับวิเคราะห์ภาพ
python scripts/tool_manager.py install jwt_tool        # jwt_tool.py สำหรับวิเคราะห์และปลอม JWT
python scripts/tool_manager.py install cyberchef       # CyberChef Standalone Offline HTML

# รันเครื่องมือจาก tools/
python scripts/tool_manager.py run <tool_name> [args...]
```

### ตารางเปรียบเทียบเครื่องมือตาม OS (Linux vs Windows vs Python Fallback)
| เครื่องมือหลัก | Linux / Kali | Windows (PowerShell) | Universal Python Fallback |
| :--- | :--- | :--- | :--- |
| `strings` | `strings file` | `Select-String` หรือ `python tools/strings.py` | `python -c "import re; print(re.findall(rb'[ -~]{4,}', open('f','rb').read()))"` |
| `xxd` / `hexdump` | `xxd -p file` / `hexdump -C` | `Format-Hex file` | `python -c "print(open('f','rb').read(64).hex(' '))"` |
| `grep` | `grep -Ei 'pattern'` | `Select-String -Pattern 'pattern'` | Python regex search |
| `curl` | `curl -i -s URL` | `curl.exe` หรือ `Invoke-RestMethod` | `python -c "import requests; ..."` |
| `nc` / `netcat` | `nc -lvnp port` / `nc ip port` | `Test-NetConnection` หรือ python socket | `python -c "import socket; ..."` |
| `file` | `file sample` | เช็ค magic bytes ผ่าน python | `python -c "print(open('f','rb').read(16))"` |
| `unzip` (nested) | `unzip` | `Expand-Archive` / 7z | `python scripts/unzip_recursive.py` |

- ★ `python3` + `pip` + `requests` `pwntools` `pycryptodome` `gmpy2` `z3-solver` `scapy` `Pillow` `numpy`
- ★ `file` `strings` `xxd` `hexdump` `curl` `unzip` `7z` `git` `socat` `ncat` `netcat` `tmux`
- ★ CyberChef (web) https://gchq.github.io/CyberChef — กินทุก encoding, กด Magic ก่อนเสมอ
- ★ dCode.fr — solver cipher แปลกๆ (Vigenere, Playfair, Enigma, Railfence)
- `openssl` — `openssl enc -d -aes-256-cbc -in enc -out dec`
- `jq` `yq` — ดู `challenge.json` จากสคริปต์ fetch
- Docker/Kali/Parrot — แยก env แข่ง ไม่ทำเครื่องหลักพัง

```bash
pip install requests pwntools pycryptodome gmpy2 z3-solver scapy Pillow numpy matplotlib volatility3
```

## 1. Web Exploitation (~25 ตัว)
**Proxy / ดูทราฟฟิก:**
- ★ Burp Suite Community / Caido — intercept + Repeater (ตัวหลัก)
- ★ Browser DevTools (F12) — ดู JS, cookie, header, network
- OWASP ZAP — proxy + active scan ฟรี (แทน Burp ได้)
- `curl` — `curl -i -s URL`, `curl -X POST -d 'a=1' URL`
- Postman / `httpie` — ยิง API ไวๆ

**Fuzz / Dir / Param:**
- ★ `ffuf` — `ffuf -u URL/FUZZ -w wordlist -mc 200`
- `feroxbuster` / `gobuster` / `dirsearch` — `feroxbuster -u URL -w wordlist -x php,txt,bak`
- `katana` `hakrawler` — crawl JS หา endpoint ซ่อน
- `kxss` `dalfox` — `dalfox url URL` หา XSS อัตโนมัติ
- `nuclei` — `nuclei -u URL -t cves/` สแกน CVE สำเร็จรูป
- `nikto` — `nikto -h URL` สแกนหยาบๆ ตั้งต้น
- Backup ที่ชอบลืม (เช็ค autoindex ทุกตัว): `/_baks/` `/_backup/` `/backup/` — เคยเจอ flag เป็นชื่อไฟล์ + `recovery_token` ใน `.bak` (TCTT2026 Naomi Bay)
- ระวังทางหลอก: `/notify?email=` สะท้อนดิบเป็น reflected XSS แต่ไม่มี bot มากด — อย่าจมกับ XSS ถ้า hint บอก enumeration

**SQLi / SSTI / LFI / Upload / Auth:**
- ★ `sqlmap` — `sqlmap -u "URL?id=1" --dbs --batch`, หรือ `--request burp.req --dump`
- SQLi login bypass (JSON API 2026): `{"username":"admin'-- -","password":"x"}` -> `WHERE name='admin'-- -' AND ...` ได้ `cspp{...}` ทันที สำรอง `' OR '1'='1` / `' OR 1=1-- -`
- `sqlmap --tamper=space2comment` — bypass WAF เบื้องต้น
- SSTI: `{{7*7}}` -> `49` ยืนยันได้เลย แล้วลอง `{{config}}` / `{{flag}}` / `{{FLAG}}` ก่อน (csplusplus 2026 คาย `cspp{...}` ทันที) ถ้าโดนกรอง `__` ค่อยใช้ `SSTImap` / `<%=7*7%>`
- LFI: `../../etc/passwd`, `php://filter/convert.base64-encode/resource=index.php`, `expect://id`
- Traversal file API (2026): `GET /file?name=../secret/flag.txt` ใช้ `../` ดิบๆ ได้ `cspp{...}` ทันที ห้าม encode `%2F` (server ไม่ decode ซ้ำแล้ว 404)
- JitCommerce/Aegis (2026): `/image?file=../../etc/passwd` -> อ่าน `../../app/server.js` + `../../app/config/secret.txt` (JWT HS256 base64) -> forge `{"role":"admin"}` -> `GET /api/verify-token` ได้ `aegis{...}` + ต้องใช้ `UA: Mozilla/5.0` ไม่งั้นโดน `Aegis AI Shield: Access denied for AI Agents`
- Upload: `.phtml` `.phar` double-ext `shell.php.jpg` + `exiftool` ยัด payload
- JWT: `jwt_tool`, `jwt.io` — ลอง `alg:none`, `kid=../../dev/null`, brute secret ด้วย `hashcat -m 16500`
- `wpscan` — `wpscan --url URL --enumerate p,u` ถ้าเจอ WordPress
- `hydra` `ffuf` — brute login: `hydra -l admin -P rockyou.txt URL http-post-form`
- SSRF preview (2026): `GET /fetch?url=http://127.0.0.1/` -> `internal service: try /flag` -> `GET /fetch?url=http://127.0.0.1/flag` ได้ `cspp{...}` ทันที สำรอง `localhost/flag`, `169.254.169.254/flag`, `0.0.0.0/flag`

## 2. Reverse Engineering (~15 ตัว)
- ★ Ghidra (NSA, ฟรี) — decompile เป็น C อ่านง่ายสุด
- ★ `strings` `ltrace` `strace` `file` — 3 คำสั่งแรกที่ต้องรันทุก binary
- ★ `checksec` `rabin2 -I` — ดู mitigation + arch
- `radare2`/`rizin` + Cutter (GUI) — patch binary ไว
- IDA Free / Binary Ninja Demo — สำรองถ้า Ghidra เอาไม่อยู่
- `upx` — `upx -d packed` แตก pack ก่อน
- `dnSpy` / `ILSpy` — .NET, `apktool` + `jadx` — Android APK
- `x64dbg` — Windows debugger, `frida` — hook function ตอนรัน
- `angr` — symbolic execution แก้ crackme ยากๆ
- `z3` — แก้สมการจาก logic ใน binary

```bash
file ./pwn; strings ./pwn | head -50; ltrace ./pwn; checksec --file=./pwn
```

## 3. Cryptography (~20 ตัว)
- ★ CyberChef Magic + `factordb.com` — 2 ที่แรกที่ต้องเปิด
- ★ `RsaCtfTool` — `RsaCtfTool --publickey pub.pem --uncipher c.txt --private`
- ★ `openssl` `python pycryptodome` — AES/RSA manual
- RSA เสริม: `sagemath` `yafu` `msieve` `cado-nfs` — factor `n` ใหญ่
- RSA attack list: `e=3` broadcast (Hastad), Wiener (d เล็ก), common modulus, GCD หลาย `n`, Fermat (p,q ใกล้กัน), Boneh-Durfee
- XOR: single-byte brute (`CyberChef`/`xorBruteForcer`), repeating-key (`cribdrag`), `crib` คือ `FLAG{`
- Hash: `hash-identifier` / `haiti` แยกชนิด -> `john` / `hashcat -m 0` (MD5) `-m 1000` (NTLM) `-m 1800` (sha512crypt)
- Classic: `dCode` + `quipqiup.com` (substitution), Caesar/ROT/Vigenere/Railfence/Base32/58/85/91/Morse
- ROT13 lesson (2026): `pfcc{ebg13_vf_n_pnrfne}` -> `cspp{rot13_is_a_caesar}` -> `python -c "import codecs;print(codecs.decode(s,'rot_13'))"` จำ: ROT13 ถอดทั้ง header+body ทีเดียว อย่าตัด `xxx{` ทิ้ง
- Caesar lesson (2026): `jzww{la_ab_iybal}` brute 26 -> shift -7 ได้ `cspp{et_tu_brute}` (`et tu brute` = วลี Julius Caesar) -> `python: ''.join(chr((ord(c)-97-7)%26+97) if 'a'<=c<='z' else c for c in s)` จำ: brute ทั้ง header+body อย่าตัด `xxx{` ทิ้ง
- Vigenere lesson (2026, corrected): `fmrz{ycioqyto_nyac_puvdhl}` + format `cspp{...}` known-plaintext -> `K=C-P`: `f-c=D,m-s=U,r-p=C,z-p=K` ได้ key `DUCK` (`duckduck` คือ `DUCK` ซ้ำ ใช้ได้เหมือนกัน) -> ถอดทั้ง header+body ข้าม `{_}` ไม่เลื่อน key ได้ `cspp{vigenere_keys_matter}` จำ: อย่าตัด header ทิ้ง ต้องถอดทั้งเส้น
- ROT47 lesson (2026): ตัวอักษร `!-~` (33-126) เลื่อน 47 (`4DAALC_Ecf0C@==DN` -> `cspp{r0t47_rolls}`) -> `python: ''.join(chr(33+((ord(c)-33+47)%94)) if 33<=ord(c)<=126 else c for c in s)` ลอง CyberChef `ROT47` ก่อนเสมอถ้าเจอ `A-Z0-9_@=+/` ปนกัน
- Base85 lesson (2026): แยก `b85 (RFC1924)` vs `a85 (Ascii85/Adobe)` -> `python: base64.b85decode(s)` / `base64.a85decode(s,adobe=False)` ลอง a85 ก่อนถ้ามี `? & . @ ]` เช่น `@rlU.HXSdABk]Oa?Zg7&0Onm0A:4` -> `cspp{a5cii85_unl0cked}`
- Base64 first: เจอ `^[A-Za-z0-9+/=]{20,}$` ให้ `echo ... | base64 -d` ก่อนเสมอ — `base64 is not encryption` (2026: `Y3NwcHtiNHNlNjRfaXNfbm90X2VuY3J5cHRpb259` -> `cspp{b4se64_is_not_encryption}`)
- Atbash lesson (2026): `xhkk{nriili_nriili_dzoo}` -> `cspp{mirror_mirror_wall}` (`a<->z`: `chr(219-ord(c))` lower / `chr(155-ord(c))` upper) -> `python: ''.join(chr(219-ord(c)) if 'a'<=c<='z' else chr(155-ord(c)) if 'A'<=c<='Z' else c for c in s)` จำ: ถอดทั้ง header+body ทีเดียว อย่าตัด `xxx{` ทิ้ง
- Hex first: เจอ `^[0-9a-fA-F]{20,}$` (ยาวคู่) ให้ `python -c "print(bytes.fromhex(s).decode())"` ก่อนเสมอ — `hex is not encryption` (2026: `637370707b6865785f74305f61736369695f6674777d` -> `cspp{hex_t0_ascii_ftw}`)
- URL double-encode first: เจอ `%25` ในสตริง = เข้ารหัสซ้ำ 2 ชั้น ให้ `unquote(unquote(s))` ก่อนเสมอ — `url is not encryption` (2026: `cspp%257Bd0uble_url_3ncoded%257D` -> `cspp{d0uble_url_3ncoded}`)
- Base58 first: เจอ `^[1-9A-HJ-NP-Za-km-z]{20,}$` (ไม่มี `0,O,I,l`) ให้ `b58decode` ก่อนเสมอ — `base58 is not encryption` (2026: `2PMtKWJy4QEGtjrMAeJWZQGZVQSQ` -> `cspp{b4se58_satoshi}`) -> `python: n=0; [n:=n*58+'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'.index(c) for c in s]; print(n.to_bytes((n.bit_length()+7)//8,'big').decode())`
- Base32 first: เจอ `^[A-Z2-7=]{16,}$` ยาวหาร 8 ลงตัว ให้ `python -c "import base64;print(base64.b32decode(s).decode())"` ก่อนเสมอ — `base32 is not encryption` (2026: `MNZXA4D3MI2HGZJTGJPXEZTDGQ3DIOD5` -> `cspp{b4se32_rfc4648}`)
- ROT47 first: เจอ ASCII แปลกๆ มีตัวใหญ่+เล็ก+เลข+ `_@=` ปนกัน ให้ลอง ROT47 ก่อนเสมอ — `python -c "print(''.join(chr(33+((ord(c)-33+47)%94)) if 33<=ord(c)<=126 else c for c in s))"` (2026: `4DAALC_Ecf0C@==DN` -> `cspp{r0t47_rolls}`)
- ECC/DLOG: `sagemath` `BSGS` `Pohlig-Hellman`, `z3` แก้ relation แปลกๆ
- สคริปต์ช่วย: `CTF_Crypto_Solver`, `flagcapt.py`, `CTF-Crypto-Toolkit`

## 4. Forensics (เยอะสุด ~30 ตัว)
**File / carving:**
- ★ `file` `binwalk` `foremost` `scalpel` `xxd` — `binwalk -e file`, `foremost file`
- ★ `exiftool` `strings -n 8` `hexdump -C | head` — metadata + magic bytes
- Strings lesson (2026): `noise.dat` มี junk ปน flag บรรทัดเดียว -> `strings -n 4 noise.dat | grep -Eo 'cspp\{[^}]+\}'` ได้ `cspp{strings_finds_secrets}` ทันที (Windows: `Select-String -Pattern 'cspp\{[^}]+\}'`)
- EXIF lesson (2026): dump `beach_sunset.jpg` มี flag ใน `User Comment` -> `exiftool photo.jpg | grep -i 'comment\|cspp'` ได้ `cspp{exif_says_too_much}` ทันที จำ: เช็ค `Comment/Artist/GPS/Software` ก่อนเสมอ อย่ามัวดูแต่พิกัด
- Polyglot lesson (2026): `polyglot.png` 16,981 bytes ใหญ่เกินพิกเซล -> หา `PK\x03\x04` ที่ offset 16,838 (หลัง `IEND`) carve แล้ว `unzip` ได้ `flag.dat` = `cspp{z1p_appended_after_iend}` จำ: ไฟล์ใหญ่เกินจริงให้สแกน `PK/EOCD` ก่อน `stegsolve`
- Matryoshka lesson (2026): `nested.zip` (442 bytes) ซ้อน 5 ชั้น `layer3>layer2>layer1>layer0>flag.dat` -> วน `zipfile` เช็ค magic `PK\x03\x04` จนเจอ zip ชั้นใน ได้ `cspp{m4tryoshka_z1p_dolls}` ใช้สคริปต์ `scripts/unzip_recursive.py` ได้เลย
- magic ที่จำ: `89504e47`=PNG `ffd8ff`=JPEG `504b0304`=ZIP `7f454c46`=ELF

**Image stego:**
- ★ JPEG/BMP -> `steghide extract -sf img.jpg -p ""` (ลองรหัสว่างก่อน)
- ★ PNG/BMP -> `zsteg -a img.png`, `stegoveritas img.png`
- `pngcheck` `apngdis` `stegsolve` (ดู bit-plane) `outguess`
- ลำดับ: `file` -> `exiftool` -> `strings` -> `binwalk -e` -> `steghide/zsteg` -> `stegsolve`

**Audio / Spectrogram:**
- `audacity` (ดู spectrogram) `sox` `ffmpeg` — SSTV/DTMF/Morse ซ่อนในเสียง
- `deepsound` `sonic-visualiser`

**PDF / Doc / Archive:**
- `pdftotext` `pdfinfo` `mutool clean -d` `strings | grep -i flag`
- `7z x` `unzip` `fcrackzip` `john --format=zip` — แคร็กรหัส zip

**Network / PCAP:**
- ★ `wireshark` `tshark` `tcpdump` `capinfos` `pcapfix`
- `tshark -r cap.pcap -Y http.request -T fields -e http.request.uri`
- `tshark -r cap.pcap -Y tls -T fields -e tls.handshake.extensions_server_name`
- ดึง POST body ตรงๆ: `tshark -r cap.pcap -Y http -T fields -e http.file_data` (ได้ hex, decode ด้วย `bytes.fromhex(h).decode()`) — ถ้า traffic เป็น HTTP plaintext ธรรมดา ลอง `strings cap.pcap | grep -i pass` ก่อนได้เลย เร็วกว่ามาก
- Follow TCP stream + Export Objects (HTTP/SMB) หาไฟล์ที่โอน
- WiFi: `aircrack-ng -w rockyou.txt cap.pcap`

**Memory / Disk:**
- ★ `volatility3` — `vol3 -f mem.dmp windows.info`, `windows.pslist`, `windows.pstree`, `windows.cmdline`, `windows.netscan`, `windows.filescan`, `windows.malfind`, `windows.hashdump`
- `strings -a -n 6 mem.dmp | grep -Ei 'flag|password|ssh.*key'`
- Disk: `fls -r img.dd` `photorec` `autopsy` `sleuthkit` `mount -o loop`

## 5. Binary Exploitation / Pwn (~15 ตัว)
- ★ `pwntools` — `from pwn import *`, `cyclic`/`pattern_offset`, `ELF()`, `ROP()`, `remote()`
- ★ `gdb` + `pwndbg` / `gef` — `context`, heap analysis
- ★ `checksec` — ดู RELRO/Canary/NX/PIE ก่อนทุกครั้ง
- `ROPgadget` / `ropper` — `ROPgadget --binary ./pwn`
- `one_gadget libc.so` — หา addr สปอว์น shell ทีเดียว
- `libc-database` / `libc.blukat.me` — หา libc จาก leak
- `patchelf` `seccomp-tools` — ดู seccomp งาน sandbox
- `socat` — `socat TCP-LISTEN:1337,reuseaddr,fork EXEC:./pwn` เทส local

```bash
checksec --file=./pwn; cyclic 200 > in; ./pwn < in; dmesg | tail
```

## 6. Misc / OSINT / Coding (~20 ตัว)
- URL/percent-decode: `python -c "import urllib.parse;print(urllib.parse.unquote(s))"` + จำ `%25=%` `%7B={` `%7D=}` `%5F=_` + CyberChef Magic
- Binary decode: `python -c "print(''.join(chr(int(b,2)) for b in s.split()))"` — เคส `cspp{b1nary_t0_ascii}` (2026)
- Acrostic lesson (2026): กลอน 16 บรรทัดอักษรแรกได้ `READFIRSTLETTERS` -> `python: ''.join(l.strip()[0] for l in open(f).read().splitlines() if l.strip())` แล้ว lowercase ห่อ `cspp{...}` ได้ `cspp{readfirstletters}` จำ: เจอคำใบ้ shape/acrostic ให้ดึงอักษรแรกก่อนเสมอ
- Zero-width lesson (2026): `note.txt` ซ่อน `U+200B=0/U+200C=1` หลังตัวอักษร 176 บิต = 22 ไบต์ -> `python: bits=''.join('0' if c=='\u200b' else '1' for c in data if c in '\u200b\u200c'); bytes(int(bits[i:i+8],2) for i in range(0,len(bits),8))` ได้ `cspp{zer0_width_ninja}` จำ: นับ `U+200B/U+200C/U+200D/U+FEFF` ก่อนเสมอ
- STDiO2026 codec-chain (fragments): Hex->b64->reverse->binary->ROT13, locket 5x b64, ring `chr(i+40)`, lore-XOR (`RAVENCLAW`/`BASILISK`), time-gate `1981-10-31` via faketime, final md5+AES-ECB(`VoldemortTheDarkLord`)
- STDiO2026 audio-hydra (dream-sequence `Dream.wav`): reverse -> speed 0.5x/2x/8x -> spectrogram/SSTV -> 18-24kHz bandpass -> stereo-diff
- Python jail: `().__class__.__base__.__subclasses__()` + `getattr` + `__builtins__`
- Esoteric: brainfuck/whitespace interpreter (web), `pypykat`
- QR/barcode: `zbarimg` `qrscan`, `ffmpeg` แตกเฟรมหา QR
- OSINT: `whois` `nslookup` `theHarvester` `amass` `subfinder` `shodan` `crt.sh` `waybackurls`
- `nmap` `masscan` `rustscan` — `nmap -sV -sC -p- target`
- `netcat` — `nc -lvnp 4444`, `nc target port` คุย service ตรงๆ

## 7. Mobile / APK (NEW STDiO2026, ~10 ตัว)
- Triage: `file app.apk`, SHA256 verify, `aapt dump badging`, `dex?/so?/flutter?`
- Flutter: `lib/*/libapp.so` (Dart-AOT) + `blutter`/`reFlutter`, `AssetManifest.json`, `strings libapp.so | grep -i pity/hmac`, `DPK2` assets
- Static: `jadx`/`apktool d`, `grep -r "pity\|HMAC\|SEAL\|NOT YET SUMMONED"`
- Dynamic: `adb install`, `frida -U -f com.app --no-pause -l hook.js`, `objection explore`, `shared_preferences` edit
- STDiO2026 (pity-me/where-are-you `b55af985`): pity 70 force hard-pity, `mewtwo.png` sealed-dex, `collectionHmac` anti-tamper -> hook `Random/summon/save-verify`

## ติดตั้งรวดเดียว (Kali/Ubuntu)
```bash
sudo apt update && sudo apt install -y \
file binutils curl git unzip p7zip-full socat ncat netcat-openbsd \
exiftool binwalk foremost scalpel pngcheck upx-ufr \
steghide stegsolve zbar-tools qrencode \
wireshark tshark tcpdump capinfos \
sqlmap ffuf gobuster feroxbuster nikto nuclei hydra john hashcat \
radare2 strace ltrace gdb patchelf \
sagemath yafu msieve \
volatility3 sleuthkit autopsy testdisk photorec \
audacity sox ffmpeg poppler-utils mupdf-tools \
nmap masscan whois dnsrecon amass \
openssl jq xxd
pip install requests pwntools pycryptodome gmpy2 z3-solver scapy Pillow numpy matplotlib volatility3
gem install zsteg
```

## Bookmark (web ไม่ต้องลง)
- CyberChef, dCode, factordb.com, quipqiup.com, jwt.io, libc.blukat.me, gtfobins.github.io
