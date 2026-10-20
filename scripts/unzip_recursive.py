#!/usr/bin/env python3
"""unzip_recursive.py — Matryoshka / nested-archive extractor (flexible).

Unpacks archives-inside-archives until nothing is left to extract, then
scans every file for CTF flag patterns. Detection is by MAGIC BYTES
(not extension), so renamed/no-extension layers still work.

Supported (stdlib only): zip, tar, tar.gz/tgz, gz, bz2, xz.
Optional fallback via `7z` CLI (if installed): 7z, rar, encrypted zips.

Usage:
    python scripts/unzip_recursive.py nested.zip
    python scripts/unzip_recursive.py nested.zip --out ./out --depth 100
    python scripts/unzip_recursive.py chall.bin --password secret
    python scripts/unzip_recursive.py chall --pattern "flag\\{[^}]+\\}"

Exit code 0 + prints FLAG lines when a flag pattern is found.
"""
import argparse
import bz2
import gzip
import io
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile

DEFAULT_PATTERN = r"(?:cspp|flag|ctf|aegis|picoctf)\{[^}\r\n]+\}"

MAGICS = (
    (b"PK\x03\x04", "zip"),
    (b"PK\x05\x06", "zip"),  # empty archive
    (b"PK\x07\x08", "zip"),  # spanned
    (b"\x1f\x8b", "gzip"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"7z\xbc\xaf'\x1c", "7z"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"Rar!\x1a\x07\x01\x00", "rar5"),
)


def detect(data: bytes) -> str | None:
    for magic, kind in MAGICS:
        if data.startswith(magic):
            return kind
    # tar (ustar at offset 257) has no fixed header magic
    if len(data) > 262 and data[257:262] == b"ustar":
        return "tar"
    # single-file members renamed without extension: try zip/tar probe
    if len(data) > 4:
        try:
            with zipfile.ZipFile(io.BytesIO(data)):
                return "zip"
        except Exception:
            pass
        try:
            with tarfile.open(fileobj=io.BytesIO(data)):
                return "tar"
        except Exception:
            pass
    return None


def safe_join(base: str, name: str) -> str:
    """Block zip-slip path traversal; always stay inside base."""
    name = name.lstrip("/\\").replace("..", "_")
    return os.path.join(base, *name.split("/"))


def extract_zip(data: bytes, dest: str, password: bytes | None) -> list[str]:
    out = []
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            target = safe_join(dest, info.filename)
            os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
            try:
                with zf.open(info, pwd=password) as src, open(target, "wb") as fh:
                    shutil.copyfileobj(src, fh)
            except RuntimeError:  # bad password -> retry handled by caller
                raise
            out.append(target)
    return out


def extract_tar(data: bytes, dest: str) -> list[str]:
    out = []
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            target = safe_join(dest, member.name)
            os.makedirs(os.path.dirname(target) or dest, exist_ok=True)
            src = tf.extractfile(member)
            if src is None:
                continue
            with src, open(target, "wb") as fh:
                shutil.copyfileobj(src, fh)
            out.append(target)
    return out


def decomp_single(data: bytes, kind: str, dest: str, stem: str) -> list[str]:
    if kind == "gzip":
        raw = gzip.decompress(data)
    elif kind == "bzip2":
        raw = bz2.decompress(data)
    elif kind == "xz":
        raw = lzma.decompress(data)
    else:  # pragma: no cover
        raise ValueError(kind)
    # a .gz may itself be a tar -> keep tar magic for next round
    target = os.path.join(dest, stem)
    with open(target, "wb") as fh:
        fh.write(raw)
    return [target]


def extract_7z_cli(path: str, dest: str, password: str | None) -> list[str]:
    cmd = ["7z", "x", path, "-o" + dest, "-y"]
    if password:
        cmd.append("-p" + password)
    try:
        subprocess.run(cmd, capture_output=True, check=True, timeout=120)
    except FileNotFoundError:
        raise RuntimeError("7z CLI not installed; cannot handle this format")
    out = []
    for root, _, files in os.walk(dest):
        out.extend(os.path.join(root, f) for f in files)
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="Recursively extract nested archives, then hunt flags.")
    ap.add_argument("file", help="outermost file (any name/extension)")
    ap.add_argument("--out", default=None, help="output dir (default: <file>_out)")
    ap.add_argument("--depth", type=int, default=50, help="max nesting depth (default 50)")
    ap.add_argument("--password", "-p", default=None, help="archive password (also tried on every zip layer)")
    ap.add_argument("--pattern", default=DEFAULT_PATTERN, help="flag regex (default: common CTF formats)")
    ap.add_argument("--max-mb", type=int, default=500, help="total extracted size cap in MB (zip-bomb guard)")
    ap.add_argument("--keep", action="store_true", help="keep intermediate archives")
    args = ap.parse_args()

    src = os.path.abspath(args.file)
    out = os.path.abspath(args.out or (src + "_out"))
    os.makedirs(out, exist_ok=True)
    flag_re = re.compile(args.pattern)
    pw = args.password.encode() if args.password else None

    pending = [shutil.copy(src, os.path.join(out, "layer0_" + os.path.basename(src)))]
    # bootstrap: work on a copy so the original is untouched
    depth_files = {0: pending}
    total_bytes = 0
    hits: list[tuple[str, str]] = []

    def scan(path: str) -> None:
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
        except OSError:
            return
        try:
            text = blob.decode("utf-8", errors="ignore")
        except Exception:
            return
        for m in flag_re.finditer(text):
            line = m.group(0)  # full match even if pattern has groups
            if (path, line) not in hits:
                hits.append((path, line))
                print(f"FLAG {line}  <- {os.path.relpath(path, out)}")

    level = 0
    current = pending
    while current and level < args.depth:
        nxt: list[str] = []
        for path in current:
            try:
                with open(path, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            kind = detect(data)
            if kind is None:
                scan(path)
                continue
            print(f"[L{level}] {os.path.relpath(path, out)} ({kind}, {len(data)}B)")
            layer_dir = os.path.join(out, f"L{level + 1}")
            os.makedirs(layer_dir, exist_ok=True)
            try:
                if kind == "zip":
                    try:
                        produced = extract_zip(data, layer_dir, pw)
                    except RuntimeError:
                        alt = input(f"password for {path} (empty=skip): ").strip() or None
                        produced = extract_zip(data, layer_dir, alt.encode() if alt else None)
                elif kind == "tar":
                    produced = extract_tar(data, layer_dir)
                elif kind in ("gzip", "bzip2", "xz"):
                    stem = os.path.basename(path)
                    for ext in (".tgz", ".tar.gz", ".gz", ".bz2", ".xz", ".tar"):
                        if stem.endswith(ext):
                            stem = stem[: -len(ext)]
                            break
                    produced = decomp_single(data, kind, layer_dir, stem or "data")
                else:  # 7z / rar -> CLI fallback in an isolated tmp dir
                    with tempfile.TemporaryDirectory() as tmp:
                        tmppath = os.path.join(tmp, "a." + kind)
                        with open(tmppath, "wb") as fh:
                            fh.write(data)
                        produced_tmp = extract_7z_cli(tmppath, tmp, args.password)
                        produced = []
                        for p in produced_tmp:
                            dst = os.path.join(layer_dir, os.path.basename(p))
                            shutil.copy(p, dst)
                            produced.append(dst)
            except Exception as e:  # not actually extractable -> treat as plain file
                print(f"  ! extract failed ({e}); scanning as-is")
                scan(path)
                continue
            for p in produced:
                total_bytes += os.path.getsize(p)
            if total_bytes > args.max_mb * 1024 * 1024:
                print("! size cap hit, stop (zip-bomb guard). Use --max-mb to raise.")
                current = []
                break
            if not args.keep:
                try:
                    os.remove(path)
                except OSError:
                    pass
            nxt.extend(produced)
        current = nxt
        level += 1

    # final sweep over everything left on disk
    for root, _, files in os.walk(out):
        for f in files:
            scan(os.path.join(root, f))

    print(f"done: {level} layer(s), {len(hits)} flag hit(s) in {out}")
    return 0 if hits else 1


if __name__ == "__main__":
    sys.exit(main())
