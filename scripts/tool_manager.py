#!/usr/bin/env python3
"""tool_manager.py — OS detection and external CTF tool manager for Sunshine CTF Skill.

Features:
1. OS & Environment Detection:
   - Identifies OS (Windows, Linux, macOS, WSL) and architecture
   - Probes available shells (PowerShell, CMD, Bash, Zsh)
   - Checks presence of standard CTF tools in PATH
   - Recommends OS-appropriate commands and fallbacks

2. External Tool Downloader & Management (tools/ directory):
   - Downloads tools/scripts/binaries from URL or Git
   - Auto-extracts archives (.zip, .tar.gz, .tar.xz, etc.)
   - Built-in curated presets for popular CTF utilities
   - Directly runs tools from the tools/ directory with OS compatibility

3. Checksum Integrity (SHA-256):
   - Prints SHA-256 for every download/install and records it in tools/.checksums.json
   - Verifies an expected hash before trusting a download (--sha256)
   - `checksum` computes hashes for files/directories, `verify` audits the manifest

Usage:
    # OS & Environment detection:
    python scripts/tool_manager.py --os
    python scripts/tool_manager.py --os --json

    # External tool management:
    python scripts/tool_manager.py list
    python scripts/tool_manager.py download --url <URL> [--name <filename>] [--extract] [--sha256 <hash>]
    python scripts/tool_manager.py git --repo <git_url> [--name <folder_name>]
    python scripts/tool_manager.py install <preset_name> [--sha256 <hash>]
    python scripts/tool_manager.py run <tool_name> [args...]

    # Checksum integrity:
    python scripts/tool_manager.py checksum <file_or_tool> [...]
    python scripts/tool_manager.py checksum --all [--record]
    python scripts/tool_manager.py verify [--strict] [--json]

Default tools directory: <skill_root>/tools (or specify with --tools-dir / CTF_TOOLS_DIR)
"""

import argparse
import hashlib
import hmac
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile
from datetime import datetime, timezone
from pathlib import Path

# Base directory of this skill
SKILL_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TOOLS_DIR = Path(os.environ.get("CTF_TOOLS_DIR", str(SKILL_ROOT / "tools")))

# Checksum manifest lives inside the tools directory
MANIFEST_NAME = ".checksums.json"
CHECKSUM_ALGORITHMS = ("sha256", "sha1", "md5")
MAX_MANIFEST_FILES = 5000

# Common CTF tools to probe across platforms
PROBE_TOOLS = [
    "python3", "python", "pip", "git", "curl", "wget",
    "file", "strings", "xxd", "hexdump", "7z", "unzip", "tar",
    "exiftool", "binwalk", "foremost", "zsteg", "steghide",
    "tshark", "wireshark", "tcpdump",
    "sqlmap", "ffuf", "gobuster", "feroxbuster", "nikto",
    "gdb", "checksec", "ropgadget", "radare2", "ghidra",
    "john", "hashcat", "nmap", "socat", "nc"
]

# Curated safe CTF tool presets (analyzers, solvers, decoders)
PRESETS = {
    "cyberchef": {
        "description": "CyberChef offline standalone HTML app (magic decoder, crypto swiss army knife)",
        "url": "https://github.com/gchq/CyberChef/releases/download/v11.4.0/CyberChef_49d1a5634a67a3b806c6db0fdca7dcecb41a776c.zip",
        "extract": True,
        "type": "archive"
    },
    "stegsolve": {
        "description": "Stegsolve JAR (image bit-plane analysis and stego solver)",
        "url": "https://github.com/eugenekolo/sec-tools/raw/master/stego/stegsolve/stegsolve/stegsolve.jar",
        "name": "stegsolve.jar",
        "type": "file"
    },
    "jwt_tool": {
        "description": "jwt_tool.py (JSON Web Token analysis, verification and tampering tool)",
        "url": "https://raw.githubusercontent.com/ticarpi/jwt_tool/master/jwt_tool.py",
        "name": "jwt_tool.py",
        "type": "file"
    },
    "rockyou-10k": {
        "description": "Top 10,000 common passwords dictionary for quick CTF brute force",
        "url": "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt",
        "name": "rockyou-10k.txt",
        "type": "file"
    },
    "factordb": {
        "description": "FactorDB CLI script (queries factordb.com API to factor large integers)",
        "name": "factordb.py",
        "type": "builtin_generator",
        "generator": "create_factordb_cli"
    },
    "strings-py": {
        "description": "Universal cross-platform strings extractor with regex support",
        "name": "strings.py",
        "type": "builtin_generator",
        "generator": "create_strings_cli"
    },
    "sysinternals-strings": {
        "description": "Sysinternals Strings executable for Windows (strings.exe / strings64.exe)",
        "url": "https://download.sysinternals.com/files/Strings.zip",
        "name": "Strings.zip",
        "extract": True,
        "type": "archive",
        "os_filter": ["Windows"]
    }
}


def checksum_file(path: Path, algorithm: str = "sha256") -> str:
    """Return the hex digest of a single file, streamed in 1 MiB chunks."""
    hasher = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _manifest_path(tools_dir: Path) -> Path:
    return tools_dir / MANIFEST_NAME


def load_manifest(tools_dir: Path) -> dict:
    """Load tools/.checksums.json, returning a safe empty manifest on any problem."""
    path = _manifest_path(tools_dir)
    if not path.exists():
        return {"version": 1, "files": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
            raise ValueError("invalid manifest structure")
        return data
    except Exception as exc:
        print(f"[!] Warning: cannot read {MANIFEST_NAME} ({exc}); starting a fresh manifest.")
        return {"version": 1, "files": {}}


def save_manifest(tools_dir: Path, manifest: dict) -> None:
    """Atomically write the checksum manifest."""
    manifest["version"] = 1
    manifest["updated"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
    path = _manifest_path(tools_dir)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _manifest_key(tools_dir: Path, path: Path) -> str:
    """Use a tools-relative POSIX key when possible, otherwise an absolute path."""
    resolved = path.resolve()
    try:
        return resolved.relative_to(tools_dir.resolve()).as_posix()
    except ValueError:
        return resolved.as_posix()


def record_checksums(tools_dir: Path, targets, source: str = "", sha256: str = None,
                     quiet: bool = False) -> dict:
    """Record SHA-256 + size + source for files (recurses into directories)."""
    if isinstance(targets, (str, Path)):
        targets = [targets]

    files = []
    for target in targets:
        target = Path(target)
        if target.is_dir():
            found = sorted(p for p in target.rglob("*") if p.is_file() and not p.is_symlink())
            if len(found) > MAX_MANIFEST_FILES:
                print(f"[!] Warning: {len(found)} files under {target.name}; recording the first {MAX_MANIFEST_FILES}.")
                found = found[:MAX_MANIFEST_FILES]
            files.extend(found)
        elif target.is_file():
            files.append(target)
        else:
            print(f"[-] Cannot record checksum, path does not exist: {target}")

    # De-duplicate while preserving sorted order
    files = sorted({p.resolve() for p in files})
    if not files:
        return load_manifest(tools_dir)

    manifest = load_manifest(tools_dir)
    entries = manifest.setdefault("files", {})
    recorded_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    for file_path in files:
        digest = sha256 if (sha256 and len(files) == 1) else checksum_file(file_path, "sha256")
        key = _manifest_key(tools_dir, file_path)
        entries[key] = {
            "sha256": digest.lower(),
            "size": file_path.stat().st_size,
            "source": source,
            "recorded": recorded_at,
        }
        if not quiet:
            print(f"[+] SHA256 {key}: {digest}")

    save_manifest(tools_dir, manifest)
    return manifest


def ensure_tools_dir(tools_dir: Path) -> Path:
    """Ensure tools directory and an explanatory README and .gitignore exist."""
    tools_dir.mkdir(parents=True, exist_ok=True)
    
    readme = tools_dir / "README.md"
    if not readme.exists():
        readme.write_text(
            "# External Tools Directory (Sunshine CTF)\n\n"
            "This folder stores external binaries, scripts, dictionaries, and dependencies\n"
            "downloaded via `scripts/tool_manager.py`.\n\n"
            "Manage tools using:\n"
            "```bash\n"
            "python scripts/tool_manager.py list\n"
            "python scripts/tool_manager.py download --url <URL> [--extract] [--sha256 <hash>]\n"
            "python scripts/tool_manager.py install <preset>\n"
            "python scripts/tool_manager.py run <tool_name> [args...]\n"
            "python scripts/tool_manager.py checksum --all\n"
            "python scripts/tool_manager.py verify\n"
            "```\n\n"
            "Every download/install is recorded with its SHA-256 in `.checksums.json`.\n",
            encoding="utf-8"
        )

    gitignore = tools_dir / ".gitignore"
    if not gitignore.exists():
        gitignore.write_text(
            "# Ignore downloaded heavy tools & archives, but track directory\n"
            "*\n"
            "!.gitignore\n"
            "!README.md\n",
            encoding="utf-8"
        )
    return tools_dir


def detect_environment():
    """Detect current OS, architecture, WSL status, shells, and available tools."""
    system = platform.system()
    release = platform.release()
    version = platform.version()
    machine = platform.machine()
    is_wsl = False

    if system == "Linux":
        try:
            with open("/proc/version", "r", encoding="utf-8", errors="ignore") as f:
                proc_ver = f.read().lower()
                if "microsoft" in proc_ver or "wsl" in proc_ver:
                    is_wsl = True
        except Exception:
            pass

    # Distro name if Linux
    distro = ""
    if system == "Linux":
        try:
            with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        distro = line.split("=", 1)[1].strip().strip('"')
                        break
        except Exception:
            pass

    # Shell detection
    shells = []
    if system == "Windows":
        if shutil.which("powershell") or shutil.which("pwsh"):
            shells.append("PowerShell")
        if shutil.which("cmd"):
            shells.append("CMD")
        if shutil.which("bash"):
            shells.append("Git-Bash/WSL-Bash")
    else:
        for s in ["bash", "zsh", "sh", "fish"]:
            if shutil.which(s):
                shells.append(s)

    # Tool probing
    installed_tools = {}
    missing_tools = []
    for tool in PROBE_TOOLS:
        p = shutil.which(tool)
        if p:
            installed_tools[tool] = p
        else:
            missing_tools.append(tool)

    # Cross-platform recommendations
    recommendations = {}
    if system == "Windows":
        recommendations = {
            "shell_preference": "PowerShell",
            "strings_cmd": "Get-Content -Raw <file> | Select-String -Pattern '<pattern>' OR python tools/strings.py <file>",
            "hexdump_cmd": "Format-Hex <file> OR python -c \"import sys; print(open(sys.argv[1],'rb').read(64).hex(' '))\"",
            "grep_cmd": "Select-String -Pattern '<pattern>' <file>",
            "file_cmd": "python scripts/unzip_recursive.py (probe) or inspect header bytes",
            "external_tools": "Download standalone Windows .exe / .jar / .py directly into tools/"
        }
    else:
        recommendations = {
            "shell_preference": "bash",
            "strings_cmd": "strings <file> | grep -Ei '<pattern>'",
            "hexdump_cmd": "xxd <file> or hexdump -C <file>",
            "grep_cmd": "grep -Ei '<pattern>' <file>",
            "file_cmd": "file <file>",
            "external_tools": "chmod +x in tools/ and run directly"
        }

    return {
        "os": system,
        "distro": distro if distro else f"{system} {release}",
        "release": release,
        "version": version,
        "architecture": machine,
        "is_wsl": is_wsl,
        "python_executable": sys.executable,
        "python_version": platform.python_version(),
        "available_shells": shells,
        "tools_found_count": len(installed_tools),
        "tools_missing_count": len(missing_tools),
        "installed_tools": installed_tools,
        "missing_tools": missing_tools,
        "recommendations": recommendations
    }


def print_os_report(info: dict):
    """Print readable OS report formatted cleanly for any console."""
    print("=" * 65)
    print(" sunshine CTF - OS & Environment Detection Report")
    print("=" * 65)
    print(f" OS Name         : {info['os']} ({info['distro']})")
    print(f" Architecture    : {info['architecture']}")
    print(f" WSL Environment : {'Yes (Windows Subsystem for Linux)' if info['is_wsl'] else 'No / Native'}")
    print(f" Python Version  : {info['python_version']} ({info['python_executable']})")
    print(f" Shells Detected : {', '.join(info['available_shells']) if info['available_shells'] else 'Default'}")
    print("-" * 65)
    print(f" Installed CTF Utilities ({info['tools_found_count']}/{len(PROBE_TOOLS)}):")
    tools_line = ", ".join(sorted(info['installed_tools'].keys()))
    print(f"   {tools_line if tools_line else 'None detected in standard PATH'}")
    print("-" * 65)
    print(" Recommended Alternatives for this OS:")
    for k, v in info["recommendations"].items():
        print(f"   * {k:18s}: {v}")
    print("=" * 65)


def download_file(url: str, dest_path: Path, expected_sha256: str = None):
    """Download a file, print its SHA-256, and optionally enforce an expected hash.

    Returns the SHA-256 hex digest on success, or None on failure/mismatch.
    """
    print(f"[*] Downloading from: {url}")
    print(f"[*] Destination: {dest_path}")
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) sunshine-ctf-tool-manager"}
    req = urllib.request.Request(url, headers=headers)
    
    try:
        with urllib.request.urlopen(req) as resp, open(dest_path, "wb") as out_f:
            total_size = resp.headers.get("Content-Length")
            total_size = int(total_size) if total_size and total_size.isdigit() else 0
            downloaded = 0
            chunk_size = 64 * 1024
            
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                out_f.write(chunk)
                downloaded += len(chunk)
                if total_size > 0:
                    percent = (downloaded / total_size) * 100
                    print(f"\r    Progress: {downloaded}/{total_size} bytes ({percent:.1f}%)", end="", flush=True)
                else:
                    print(f"\r    Downloaded: {downloaded} bytes", end="", flush=True)
            print()
        print(f"[+] Download complete: {dest_path.name} ({os.path.getsize(dest_path):,} bytes)")

        digest = checksum_file(dest_path, "sha256")
        print(f"[+] SHA256: {digest}")
        if expected_sha256:
            expected = expected_sha256.strip().lower()
            if hmac.compare_digest(digest.lower(), expected):
                print("[+] Checksum verified (SHA-256).")
            else:
                print("[-] Checksum mismatch (SHA-256).")
                print(f"    expected: {expected}")
                print(f"    actual  : {digest}")
                print("[!] Downloaded file deleted; refusing to trust it.")
                dest_path.unlink()
                return None
        return digest
    except urllib.error.HTTPError as e:
        print(f"[-] HTTP Error {e.code}: {e.reason} while fetching {url}")
        if dest_path.exists():
            dest_path.unlink()
        return None
    except Exception as e:
        print(f"[-] Download failed: {e}")
        if dest_path.exists():
            dest_path.unlink()
        return None


def _is_within(base: Path, candidate: Path) -> bool:
    """True when candidate resolves inside base (blocks zip-slip / path traversal)."""
    try:
        candidate.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False


def extract_archive(archive_path: Path, target_dir: Path):
    """Extract zip or tar archives into target_dir with path-traversal protection."""
    print(f"[*] Extracting archive: {archive_path.name} -> {target_dir}")
    target_dir.mkdir(parents=True, exist_ok=True)

    try:
        if zipfile.is_zipfile(archive_path):
            with zipfile.ZipFile(archive_path, 'r') as zf:
                for info in zf.infolist():
                    if not _is_within(target_dir, target_dir / info.filename):
                        raise ValueError(f"unsafe path in archive: {info.filename}")
                zf.extractall(target_dir)
            print(f"[+] Zip extracted successfully to {target_dir}")
            return True
        elif tarfile.is_tarfile(archive_path):
            with tarfile.open(archive_path, 'r:*') as tf:
                for member in tf.getmembers():
                    if member.issym() or member.islnk():
                        raise ValueError(f"unsafe link in archive: {member.name}")
                    if not _is_within(target_dir, target_dir / member.name):
                        raise ValueError(f"unsafe path in archive: {member.name}")
                tf.extractall(target_dir)
            print(f"[+] Tar archive extracted successfully to {target_dir}")
            return True
        else:
            print(f"[!] Warning: {archive_path.name} is not recognized as a zip or tar archive.")
            return False
    except Exception as exc:
        print(f"[-] Extraction failed: {exc}")
        return False


def create_factordb_cli(tools_dir: Path) -> bool:
    """Generate a lightweight, standalone FactorDB CLI script."""
    dest = tools_dir / "factordb.py"
    code = (
        '#!/usr/bin/env python3\n'
        '"""factordb.py — Query factordb.com API to factor large integers."""\n'
        'import sys, json, urllib.request\n\n'
        'def factor(num_str):\n'
        '    url = f"https://factordb.com/api?query={num_str.strip()}"\n'
        '    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})\n'
        '    try:\n'
        '        with urllib.request.urlopen(req) as resp:\n'
        '            data = json.loads(resp.read().decode())\n'
        '            print(f"[*] FactorDB Status: {data.get(\'status\')} (FF=Fully Factored, CF=Composite Factor)")\n'
        '            factors = data.get("factors", [])\n'
        '            print("[+] Factors:")\n'
        '            for p, count in factors:\n'
        '                exp = f"^{count}" if count > 1 else ""\n'
        '                print(f"    {p}{exp}")\n'
        '            return factors\n'
        '    except Exception as e:\n'
        '        print(f"[-] Query failed: {e}")\n'
        '        return None\n\n'
        'if __name__ == "__main__":\n'
        '    if len(sys.argv) < 2:\n'
        '        print("Usage: python factordb.py <integer>")\n'
        '        sys.exit(1)\n'
        '    factor(sys.argv[1])\n'
    )
    dest.write_text(code, encoding="utf-8")
    print(f"[+] Created FactorDB CLI helper at {dest}")
    return True


def create_strings_cli(tools_dir: Path) -> bool:
    """Generate a cross-platform Python strings extractor."""
    dest = tools_dir / "strings.py"
    code = (
        '#!/usr/bin/env python3\n'
        '"""strings.py — Cross-platform strings extractor with regex filter."""\n'
        'import sys, re, argparse\n\n'
        'def extract_strings(filepath, min_len=4, pattern=None):\n'
        '    with open(filepath, "rb") as f:\n'
        '        data = f.read()\n'
        '    regex = re.compile(rb"[A-Za-z0-9_!#$%&\'()*+,\\-./:;<=>?@[\\]^_`{|}~ ]{" + str(min_len).encode() + rb",}")\n'
        '    matcher = re.compile(pattern.encode()) if pattern else None\n'
        '    for m in regex.finditer(data):\n'
        '        val = m.group()\n'
        '        if not matcher or matcher.search(val):\n'
        '            try:\n'
        '                print(val.decode("ascii", errors="ignore"))\n'
        '            except Exception:\n'
        '                pass\n\n'
        'if __name__ == "__main__":\n'
        '    parser = argparse.ArgumentParser(description="Extract printable strings from file")\n'
        '    parser.add_argument("file", help="Path to binary or data file")\n'
        '    parser.add_argument("-n", "--min-len", type=int, default=4, help="Minimum string length")\n'
        '    parser.add_argument("-p", "--pattern", help="Filter strings matching regex pattern (e.g. cspp|flag)")\n'
        '    args = parser.parse_args()\n'
        '    extract_strings(args.file, args.min_len, args.pattern)\n'
    )
    dest.write_text(code, encoding="utf-8")
    print(f"[+] Created cross-platform strings extractor at {dest}")
    return True


def list_tools(tools_dir: Path):
    """List installed tools in tools/ directory and available presets."""
    ensure_tools_dir(tools_dir)
    entries = sorted(tools_dir.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
    
    print("=" * 65)
    print(f" Sunshine CTF - Tools Directory: {tools_dir}")
    print("=" * 65)
    
    user_tools = [e for e in entries if e.name not in [".gitignore", "README.md"]]
    if not user_tools:
        print(" (No external tools installed yet. Use 'download' or 'install' to add.)")
    else:
        print(f"{'Name':<30} {'Type':<12} {'Size':<12}")
        print("-" * 65)
        for t in user_tools:
            t_type = "Directory" if t.is_dir() else "File"
            if t.is_dir():
                file_count = sum(1 for _ in t.rglob("*") if _.is_file())
                size_str = f"{file_count} files"
            else:
                sz = t.stat().st_size
                if sz > 1024 * 1024:
                    size_str = f"{sz / (1024*1024):.1f} MB"
                elif sz > 1024:
                    size_str = f"{sz / 1024:.1f} KB"
                else:
                    size_str = f"{sz} B"
            print(f"{t.name:<30} {t_type:<12} {size_str:<12}")

    print("\n" + "-" * 65)
    print(" Available Quick Presets (`install <preset_name>`):")
    print("-" * 65)
    for p_name, p_info in PRESETS.items():
        is_installed = (tools_dir / (p_info.get("name") or p_name)).exists() or \
                       (tools_dir / f"{p_name}.py").exists() or \
                       (tools_dir / p_name).exists()
        status = "[Installed]" if is_installed else "[Available]"
        print(f" * {p_name:<20} {status:<12} {p_info['description']}")

    manifest = load_manifest(tools_dir)
    tracked = len(manifest.get("files", {}))
    print("-" * 65)
    print(f" Checksum manifest: {tracked} file(s) tracked in {MANIFEST_NAME}")
    print("   Audit integrity: python scripts/tool_manager.py verify [--strict]")
    print("=" * 65)


def install_preset(preset_name: str, tools_dir: Path, expected_sha256: str = None):
    """Install a curated CTF preset and record checksums for every installed file."""
    if preset_name not in PRESETS:
        print(f"[-] Unknown preset '{preset_name}'. Choose from: {', '.join(PRESETS.keys())}")
        return False

    cfg = PRESETS[preset_name]
    ensure_tools_dir(tools_dir)
    print(f"[*] Installing preset: {preset_name}")
    print(f"[*] Description: {cfg['description']}")

    # Check OS filter if specified
    if "os_filter" in cfg:
        cur_os = platform.system()
        if cur_os not in cfg["os_filter"]:
            print(f"[!] Warning: Preset '{preset_name}' is designed for {cfg['os_filter']}, but current OS is {cur_os}.")

    if cfg.get("type") == "builtin_generator":
        gen_func = globals().get(cfg.get("generator"))
        if not gen_func:
            print("[-] Generator function not found.")
            return False
        ok = gen_func(tools_dir)
        if ok:
            generated = tools_dir / (cfg.get("name") or f"{preset_name}.py")
            if generated.exists():
                record_checksums(tools_dir, generated, source=f"builtin:{cfg.get('generator')}")
        return ok

    target_name = cfg.get("name") or f"{preset_name}.zip"
    dest = tools_dir / target_name
    url = cfg.get("url")
    expected = expected_sha256 or cfg.get("sha256")

    digest = download_file(url, dest, expected_sha256=expected)
    if not digest:
        return False
    record_checksums(tools_dir, dest, source=url, sha256=digest)

    if cfg.get("extract", False):
        extract_dest = tools_dir / preset_name
        if extract_archive(dest, extract_dest):
            record_checksums(tools_dir, extract_dest, source=f"{url} (extracted)")

    print(f"[+] Preset '{preset_name}' ready in {tools_dir}")
    return True


def clone_git_repo(repo_url: str, tools_dir: Path, folder_name: str = None):
    """Clone a git repository into the tools directory."""
    ensure_tools_dir(tools_dir)
    if not shutil.which("git"):
        print("[-] Git is not installed in the system PATH. Please install git or download ZIP archive.")
        return False
        
    if not folder_name:
        folder_name = repo_url.rstrip("/").split("/")[-1]
        if folder_name.endswith(".git"):
            folder_name = folder_name[:-4]
            
    dest = tools_dir / folder_name
    if dest.exists():
        print(f"[!] Target destination already exists: {dest}")
        return False
        
    print(f"[*] Cloning {repo_url} into {dest}...")
    res = subprocess.run(["git", "clone", "--depth", "1", repo_url, str(dest)])
    if res.returncode == 0:
        print(f"[+] Successfully cloned repository into {dest}")
        return True
    else:
        print(f"[-] Failed to clone repository. Return code: {res.returncode}")
        return False


def get_tool_path(tool_name: str, tools_dir: Path):
    """Resolve absolute path to a tool in tools/."""
    ensure_tools_dir(tools_dir)
    target = tools_dir / tool_name
    if target.exists():
        return target
    matches = list(tools_dir.rglob(tool_name))
    if matches:
        return matches[0]
    # Check with common extensions
    for ext in [".py", ".exe", ".jar", ".sh", ".txt"]:
        candidate = tools_dir / f"{tool_name}{ext}"
        if candidate.exists():
            return candidate
    return None


def run_tool(tool_name: str, args: list, tools_dir: Path):
    """Run an installed tool from the tools/ directory."""
    ensure_tools_dir(tools_dir)
    target = get_tool_path(tool_name, tools_dir)
    if not target or not target.exists():
        print(f"[-] Tool '{tool_name}' not found in {tools_dir}")
        print(f"    Run 'python scripts/tool_manager.py list' to inspect available tools.")
        return 1
            
    cmd = []
    if target.suffix == ".py":
        cmd = [sys.executable, str(target)] + args
    elif target.suffix == ".jar":
        if not shutil.which("java"):
            print("[-] Java runtime (java) is required to run .jar files but was not found in PATH.")
            return 1
        cmd = ["java", "-jar", str(target)] + args
    elif target.suffix in [".exe", ".bat", ".cmd"] or (os.access(target, os.X_OK) and not target.is_dir()):
        cmd = [str(target)] + args
    elif target.is_dir():
        # Look for main runner file
        for candidate in [tool_name + ".py", "main.py", "run.py", tool_name + ".exe"]:
            c_path = target / candidate
            if c_path.exists():
                return run_tool(str(c_path.relative_to(tools_dir)), args, tools_dir)
        print(f"[-] Directory {target} does not contain an obvious entrypoint script.")
        return 1
    else:
        cmd = [str(target)] + args

    print(f"[*] Running: {' '.join(cmd)}")
    try:
        return subprocess.call(cmd)
    except Exception as e:
        print(f"[-] Execution error: {e}")
        return 1


def checksum_command(tools_dir: Path, targets, algorithm: str = "sha256",
                     all_files: bool = False, record: bool = False,
                     as_json: bool = False) -> int:
    """Print checksums for tools/files; optionally record SHA-256 values in the manifest."""
    ensure_tools_dir(tools_dir)
    if algorithm not in CHECKSUM_ALGORITHMS:
        print(f"[-] Unsupported algorithm '{algorithm}'. Choose from: {', '.join(CHECKSUM_ALGORITHMS)}")
        return 1

    paths = []
    missing = []
    ignored_names = {MANIFEST_NAME, "README.md", ".gitignore"}
    if all_files or not targets:
        paths = sorted(
            p for p in tools_dir.rglob("*")
            if p.is_file() and not p.is_symlink() and p.name not in ignored_names
        )
    else:
        for raw in targets:
            candidate = Path(raw).expanduser()
            if not candidate.is_absolute() and not candidate.exists():
                candidate = tools_dir / raw
            if not candidate.exists():
                resolved = get_tool_path(raw, tools_dir)
                if resolved:
                    candidate = resolved
            if candidate.is_dir():
                paths.extend(sorted(p for p in candidate.rglob("*") if p.is_file() and not p.is_symlink()))
            elif candidate.is_file():
                paths.append(candidate)
            else:
                missing.append(raw)

    for raw in missing:
        print(f"[-] Not found: {raw}", file=sys.stderr)
    if not paths:
        return 1

    results = [(p, checksum_file(p, algorithm)) for p in paths]

    if record:
        record_checksums(tools_dir, paths, source="checksum --record", quiet=True)

    if as_json:
        payload = {
            "algorithm": algorithm,
            "tools_dir": str(tools_dir),
            "files": [
                {
                    "path": _manifest_key(tools_dir, p),
                    "size": p.stat().st_size,
                    algorithm: digest,
                }
                for p, digest in results
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        for p, digest in results:
            print(f"{digest}  {_manifest_key(tools_dir, p)}")
    return 0


def verify_checksums(tools_dir: Path, strict: bool = False, as_json: bool = False) -> int:
    """Audit every manifest entry against the current file contents."""
    ensure_tools_dir(tools_dir)
    manifest = load_manifest(tools_dir)
    entries = manifest.get("files", {})

    results = []
    ok = modified = missing = 0
    for key, meta in sorted(entries.items()):
        path = Path(key)
        if not path.is_absolute():
            path = tools_dir / key
        expected = str(meta.get("sha256", "")).lower()

        if not path.is_file():
            status, actual = "missing", None
            missing += 1
        else:
            actual = checksum_file(path, "sha256")
            if expected and hmac.compare_digest(actual, expected):
                status = "ok"
                ok += 1
            else:
                status = "modified"
                modified += 1
        results.append({"path": key, "status": status, "expected": expected, "actual": actual})

    untracked = []
    if strict:
        tracked = set(entries)
        for path in sorted(tools_dir.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            key = _manifest_key(tools_dir, path)
            if key in tracked or path.name in {MANIFEST_NAME, "README.md", ".gitignore"}:
                continue
            untracked.append({"path": key, "status": "untracked"})

    if as_json:
        print(json.dumps({
            "ok": ok,
            "modified": modified,
            "missing": missing,
            "untracked": len(untracked),
            "results": results + untracked,
        }, indent=2))
    else:
        if not entries:
            print(f"[!] No checksum entries in {tools_dir / MANIFEST_NAME}.")
            print("    Run: python scripts/tool_manager.py checksum --all --record")
        for item in results:
            if item["status"] == "ok":
                print(f"[OK]        {item['path']}")
            elif item["status"] == "missing":
                print(f"[MISSING]   {item['path']}")
            else:
                print(f"[MODIFIED]  {item['path']}")
                print(f"            expected: {item['expected']}")
                print(f"            actual  : {item['actual']}")
        for item in untracked:
            print(f"[UNTRACKED] {item['path']}")
        print("-" * 65)
        print(f" Summary: {ok} ok, {modified} modified, {missing} missing, {len(untracked)} untracked")

    failed = missing > 0 or modified > 0 or (strict and bool(untracked))
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description="Sunshine CTF OS Detector & External Tool Manager")
    parser.add_argument("--tools-dir", default=str(DEFAULT_TOOLS_DIR), help="Custom tools directory (default: <skill>/tools)")
    parser.add_argument("--os", dest="show_os", action="store_true", help="Inspect current OS, shells, and CTF utilities")
    parser.add_argument("--json", action="store_true", help="Output OS inspection in JSON format")
    
    subparsers = parser.add_subparsers(dest="action", help="Sub-commands")
    
    # OS command
    subparsers.add_parser("os", help="Inspect current OS and environment")
    
    # List command
    subparsers.add_parser("list", help="List installed tools and presets")
    
    # Checksum command
    ck_parser = subparsers.add_parser("checksum", help="Print checksums and optionally record them")
    ck_parser.add_argument("targets", nargs="*", help="Files, tools, or directories (default: all files in tools/)")
    ck_parser.add_argument("-a", "--algorithm", choices=CHECKSUM_ALGORITHMS, default="sha256",
                           help="Hash algorithm (default: sha256)")
    ck_parser.add_argument("--all", action="store_true", help="Checksum every file in tools/")
    ck_parser.add_argument("--record", action="store_true", help="Record SHA-256 values in the manifest")
    ck_parser.add_argument("--json", action="store_true", help="Output JSON")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify files against the checksum manifest")
    verify_parser.add_argument("--strict", action="store_true", help="Also fail on untracked files")
    verify_parser.add_argument("--json", action="store_true", help="Output JSON")

    # Download command
    dl_parser = subparsers.add_parser("download", help="Download a tool or file from a URL")
    dl_parser.add_argument("--url", required=True, help="Direct download URL")
    dl_parser.add_argument("--name", help="Save filename (default: derived from URL)")
    dl_parser.add_argument("--extract", action="store_true", help="Extract archive if downloaded file is zip/tar")
    dl_parser.add_argument("--sha256", help="Expected SHA-256 hex digest; abort if it does not match")

    # Install preset
    inst_parser = subparsers.add_parser("install", help="Install a curated CTF preset")
    inst_parser.add_argument("preset", help=f"Preset name ({', '.join(PRESETS.keys())})")
    inst_parser.add_argument("--sha256", help="Expected SHA-256 hex digest; abort if it does not match")
    
    # Git clone command
    git_parser = subparsers.add_parser("git", help="Clone a tool repository with git")
    git_parser.add_argument("--repo", required=True, help="Git repository URL")
    git_parser.add_argument("--name", help="Target folder name")

    # Path command
    path_parser = subparsers.add_parser("path", help="Get absolute path to an installed tool")
    path_parser.add_argument("tool", help="Tool name")
    
    # Run command
    run_parser = subparsers.add_parser("run", help="Run a tool from the tools directory")
    run_parser.add_argument("tool", help="Name of the tool/file to run")
    run_parser.add_argument("args", nargs=argparse.REMAINDER, help="Arguments passed to the tool")

    parsed_args, extra = parser.parse_known_args()
    tools_dir = Path(parsed_args.tools_dir).resolve()
    
    if parsed_args.show_os or parsed_args.action == "os" or (not parsed_args.action and len(sys.argv) == 1):
        info = detect_environment()
        if parsed_args.json:
            print(json.dumps(info, indent=2, ensure_ascii=False))
        else:
            print_os_report(info)
        return 0
        
    if parsed_args.action == "list":
        list_tools(tools_dir)
        return 0

    if parsed_args.action == "checksum":
        return checksum_command(
            tools_dir,
            parsed_args.targets,
            algorithm=parsed_args.algorithm,
            all_files=parsed_args.all,
            record=parsed_args.record,
            as_json=parsed_args.json,
        )

    if parsed_args.action == "verify":
        return verify_checksums(tools_dir, strict=parsed_args.strict, as_json=parsed_args.json)

    if parsed_args.action == "download":
        ensure_tools_dir(tools_dir)
        filename = parsed_args.name or parsed_args.url.rstrip("/").split("/")[-1].split("?")[0]
        if not filename:
            filename = "downloaded_tool"
        target_path = tools_dir / filename
        digest = download_file(parsed_args.url, target_path, expected_sha256=parsed_args.sha256)
        if not digest:
            return 1
        record_checksums(tools_dir, target_path, source=parsed_args.url, sha256=digest)
        if parsed_args.extract:
            extract_dest = tools_dir / target_path.stem
            if extract_archive(target_path, extract_dest):
                record_checksums(tools_dir, extract_dest, source=f"{parsed_args.url} (extracted)")
        return 0

    if parsed_args.action == "install":
        return 0 if install_preset(parsed_args.preset, tools_dir, expected_sha256=parsed_args.sha256) else 1
        
    if parsed_args.action == "git":
        return 0 if clone_git_repo(parsed_args.repo, tools_dir, parsed_args.name) else 1

    if parsed_args.action == "path":
        p = get_tool_path(parsed_args.tool, tools_dir)
        if p:
            print(str(p))
            return 0
        else:
            print(f"[-] Tool '{parsed_args.tool}' not found in {tools_dir}", file=sys.stderr)
            return 1
        
    if parsed_args.action == "run":
        full_args = parsed_args.args + extra
        return run_tool(parsed_args.tool, full_args, tools_dir)

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
