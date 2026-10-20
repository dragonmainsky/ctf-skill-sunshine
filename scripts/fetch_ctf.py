#!/usr/bin/env python3
"""Fetch all CTFd challenges: descriptions, files, hints, and metadata.

For each challenge a folder is created under the output directory, named after
the (sanitised) challenge name. Each folder contains:
    - README.md   : human-readable write-up of everything we pulled
    - challenge.json : the raw API response (for later processing)
    - any attached files, downloaded with their original filenames

A top-level index.md lists every challenge with its id, category, points and
solved status. Re-running the script overwrites previous output for the same
challenge but leaves unrelated files in place.

Usage:
    python3 fetch_ctf.py --url URL --user USER --pass PASS [--out DIR]
    # or via env / creds file (see ctfd_common.py)

    --unsolved     only fetch challenges not yet solved by the team
    --category CAT only fetch challenges whose category contains CAT (case-insens.)
"""
import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ctfd_common import CTFdClient  # noqa: E402


def slugify(name):
    s = re.sub(r"[^\w\s.-]", "_", name).strip()
    s = re.sub(r"[\s_.-]+", "_", s)
    return s or "challenge"


def main():
    ap = argparse.ArgumentParser(description="Fetch all CTFd challenges + files.")
    ap.add_argument("--url")
    ap.add_argument("--user")
    ap.add_argument("--pass", dest="password")
    ap.add_argument("--out", default="challenges", help="output directory (default: ./challenges)")
    ap.add_argument("--unsolved", action="store_true", help="only fetch unsolved challenges")
    ap.add_argument("--category", help="filter by category substring (case-insens.)")
    ap.add_argument("--no-files", action="store_true", help="skip downloading attachments")
    args = ap.parse_args()

    client = CTFdClient(url=args.url, user=args.user, password=args.password)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    challenges = client.list_challenges()
    if not challenges:
        print("[!] no challenges found (are you logged in / is the contest open?)")
        return

    print(f"[i] {len(challenges)} challenge(s) listed", file=sys.stderr)

    index_rows = []
    for ch in challenges:
        if args.category and args.category.lower() not in ch.get("category", "").lower():
            continue
        if args.unsolved and ch.get("solved_by_me"):
            continue

        cid = ch["id"]
        detail = client.get_challenge(cid)
        if not detail:
            print(f"[!] could not fetch challenge {cid}", file=sys.stderr)
            continue

        name = detail.get("name", f"challenge_{cid}")
        category = detail.get("category", "")
        slug = f"{cid:03d}_{slugify(name)}"
        ch_dir = out_dir / slug
        ch_dir.mkdir(parents=True, exist_ok=True)

        # save raw json
        (ch_dir / "challenge.json").write_text(
            json.dumps(detail, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        # download files
        file_names = []
        for furl in detail.get("files", []) or []:
            # original filename is the last path segment before "?token="
            fname = furl.split("?")[0].rstrip("/").split("/")[-1] or "attachment"
            dest = ch_dir / fname
            try:
                client.download_file(furl, dest)
                file_names.append(fname)
                print(f"   [file] {fname}", file=sys.stderr)
            except Exception as e:  # noqa: BLE001
                print(f"   [warn] failed to download {furl}: {e}", file=sys.stderr)

        # hints
        hints = client.list_hints(cid)

        # build README.md
        md = []
        md.append(f"# {name}\n")
        md.append(f"- **ID:** {cid}")
        md.append(f"- **Category:** {category}")
        md.append(f"- **Type:** {detail.get('type')}")
        md.append(f"- **Points:** {detail.get('value')} "
                  f"(initial {detail.get('initial')}, min {detail.get('minimum')}, "
                  f"decay {detail.get('decay')})")
        md.append(f"- **Solved by me:** {detail.get('solved_by_me')}")
        md.append(f"- **Attempts:** {detail.get('attempts', 0)}")
        conn = detail.get("connection_info")
        if conn:
            md.append(f"- **Connection info:** `{conn}`")
        md.append("")
        md.append("## Description\n")
        desc = detail.get("description") or "_(no description)_"
        md.append(desc + "\n")
        if file_names:
            md.append("## Files\n")
            for f in file_names:
                md.append(f"- [{f}](./{f})")
            md.append("")
        tags = [t.get("value") for t in detail.get("tags", []) if t.get("value")]
        if tags:
            md.append("## Tags\n")
            md.append(", ".join(f"`{t}`" for t in tags) + "\n")
        if hints:
            md.append("## Hints\n")
            for h in hints:
                content = h.get("content") or h.get("requirements") or "_(locked hint)_"
                md.append(f"- {content}")
            md.append("")
        md.append(f"## URL\n")
        md.append(f"{client.base}/challenges#{cid}-{slugify(name)}\n")
        (ch_dir / "README.md").write_text("\n".join(md), encoding="utf-8")

        index_rows.append({
            "id": cid,
            "name": name,
            "category": category,
            "value": detail.get("value"),
            "solved": detail.get("solved_by_me"),
            "dir": slug,
        })
        print(f"[ok] {cid}: {name} ({category}, {detail.get('value')} pts)", file=sys.stderr)

    # write index
    lines = ["# Challenges Index\n",
             "| ID | Name | Category | Points | Solved | Folder |",
             "|----|------|----------|--------|--------|--------|"]
    for r in sorted(index_rows, key=lambda x: (x["category"], x["id"])):
        lines.append(f"| {r['id']} | {r['name']} | {r['category']} | {r['value']} | "
                     f"{'✅' if r['solved'] else '⬜'} | [{r['dir']}](./{r['dir']}/README.md) |")
    (out_dir / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"\n[done] wrote {len(index_rows)} challenge(s) to {out_dir}/", file=sys.stderr)
    print(f"[done] index: {out_dir/'index.md'}", file=sys.stderr)


if __name__ == "__main__":
    main()
