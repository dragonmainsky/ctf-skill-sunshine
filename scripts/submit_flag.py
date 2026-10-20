#!/usr/bin/env python3
"""Submit a flag to a CTFd challenge.

Resolves the challenge either by numeric --id or by --name (substring match,
case-insensitive). Prints a clear result line plus the raw JSON response.

Usage:
    python3 submit_flag.py --id 75 --flag 'flag{...}'
    python3 submit_flag.py --name Gemini --flag 'flag{...}'
    # credentials via --url/--user/--pass, env, or creds file (see ctfd_common.py)

    --list   print the challenge id/name table and exit (no submission)
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ctfd_common import CTFdClient  # noqa: E402


def find_challenge_id(client, challenge_id=None, name=None):
    if challenge_id is not None:
        return int(challenge_id)
    if not name:
        raise SystemExit("Provide --id or --name to identify the challenge.")
    matches = []
    for ch in client.list_challenges():
        if name.lower() in ch.get("name", "").lower():
            matches.append(ch)
    if not matches:
        raise SystemExit("No challenge name matches '%s'." % name)
    if len(matches) > 1:
        msg = "Multiple challenges match, use --id:\n"
        for m in matches:
            msg += "  %d: %s (%s)\n" % (m["id"], m["name"], m.get("category"))
        raise SystemExit(msg)
    cid = matches[0]["id"]
    print("[i] matched challenge %d: %s" % (cid, matches[0]["name"]), file=sys.stderr)
    return cid


def main():
    ap = argparse.ArgumentParser(description="Submit a flag to a CTFd challenge.")
    ap.add_argument("--url")
    ap.add_argument("--user")
    ap.add_argument("--pass", dest="password")
    ap.add_argument("--id", type=int, help="challenge id")
    ap.add_argument("--name", help="challenge name substring (case-insens.)")
    ap.add_argument("--flag", help="the flag to submit")
    ap.add_argument("--list", action="store_true", help="list challenges and exit")
    args = ap.parse_args()

    client = CTFdClient(url=args.url, user=args.user, password=args.password)

    if args.list:
        rows = client.list_challenges()
        if not rows:
            print("[!] no challenges found.")
            return
        print("  ID  SOLVED   PTS  CATEGORY / NAME")
        for ch in sorted(rows, key=lambda x: (x.get("category", ""), x["id"])):
            solved = "yes" if ch.get("solved_by_me") else "no"
            cat = ch.get("category", "")
            nm = ch.get("name", "")
            print("%4d  %-6s  %4d  %s / %s" % (ch["id"], solved, ch.get("value", 0), cat, nm))
        return

    if not args.flag:
        ap.error("the --flag argument is required (unless using --list)")

    cid = find_challenge_id(client, args.id, args.name)
    result = client.submit(cid, args.flag)

    data = result.get("data", {}) if isinstance(result, dict) else {}
    status = data.get("status", "?")
    message = data.get("message", "")

    if status == "correct":
        verdict = "[CORRECT] challenge %d" % cid
    elif status == "already_solved":
        verdict = "[ALREADY SOLVED] challenge %d" % cid
    elif status == "incorrect":
        verdict = "[INCORRECT] challenge %d" % cid
    else:
        verdict = "[?] %s (challenge %d)" % (status, cid)

    print(verdict)
    if message:
        print("   " + message)
    print("   raw: " + json.dumps(result, ensure_ascii=False))
    sys.exit(0 if status in ("correct", "already_solved") else (2 if status == "incorrect" else 1))


if __name__ == "__main__":
    main()
