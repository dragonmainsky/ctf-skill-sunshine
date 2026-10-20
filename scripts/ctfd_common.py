#!/usr/bin/env python3
"""Common helpers for talking to a CTFd platform.

Handles login (nonce flow), session cookies, JSON API calls, file downloads,
and fetching a fresh CSRF nonce for POST requests (e.g. submitting flags).

Credentials / URL resolution order (first wins):
    1. explicit function arguments
    2. environment variables: CTF_URL, CTF_USER, CTF_PASS
    3. a credentials file (default ~/.ctfd_creds.json) with keys:
       url, user, pass
"""
import json
import os
import re
import sys
from pathlib import Path

import requests


CREDS_FILE = Path(os.environ.get("CTF_CREDS_FILE", str(Path.home() / ".ctfd_creds.json")))


def _read_creds(url=None, user=None, password=None, creds_file=None):
    """Resolve url/user/password from args, env, then creds file."""
    path = Path(creds_file) if creds_file else CREDS_FILE
    file_creds = {}
    if path.exists():
        try:
            file_creds = json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            print(f"[warn] could not parse {path}: {e}", file=sys.stderr)

    url = url or os.environ.get("CTF_URL") or file_creds.get("url")
    user = user or os.environ.get("CTF_USER") or file_creds.get("user")
    password = password or os.environ.get("CTF_PASS") or file_creds.get("pass")
    if not url or not user or not password:
        raise SystemExit(
            "Missing credentials. Provide --url/--user/--pass, set CTF_URL/CTF_USER/CTF_PASS, "
            f"or populate {path} with {{\"url\",\"user\",\"pass\"}}."
        )
    return url.rstrip("/"), user, password


def _extract_nonce(html):
    """Pull the CTFd csrfNonce out of an HTML page."""
    m = re.search(r'csrfNonce["\']?\s*[:=]\s*["\']([A-Za-z0-9]+)["\']', html)
    if m:
        return m.group(1)
    # fallback: hidden nonce input
    m = re.search(r'name=["\']nonce["\']\s+value=["\']([A-Za-z0-9]+)["\']', html)
    return m.group(1) if m else None


class CTFdClient:
    """A logged-in CTFd session."""

    def __init__(self, url=None, user=None, password=None, creds_file=None, verbose=True,
                 cookie_jar=None):
        self.base, self.user, self.password = _read_creds(url, user, password, creds_file)
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ctf-tools/1.0 (python requests)",
            "Accept": "application/json",
        })
        self._nonce = None
        # persist cookies so repeated script runs reuse the session instead of
        # re-logging in (CTFd rate-limits logins).
        self.cookie_jar = Path(cookie_jar) if cookie_jar else \
            Path.home() / ".ctfd_cookies.json"
        if self.cookie_jar.exists():
            try:
                self.session.cookies.update(json.loads(self.cookie_jar.read_text()))
            except Exception:
                pass
        if not self._session_valid():
            self.login()
        else:
            self._log("[ok] reused existing session")
        self._save_cookies()

    def _save_cookies(self):
        try:
            self.cookie_jar.write_text(json.dumps(dict(self.session.cookies)))
        except Exception:
            pass

    def _session_valid(self):
        """A session is valid if /api/v1/challenges returns success without login."""
        try:
            r = self.session.get(f"{self.base}/api/v1/challenges")
            if r.status_code == 200:
                return r.json().get("success", False)
        except Exception:
            pass
        return False

    def _log(self, msg):
        if self.verbose:
            print(msg, file=sys.stderr)

    def login(self):
        """Log in via the CTFd nonce flow."""
        # 1. fetch login page for the nonce + cookies
        r = self.session.get(f"{self.base}/login")
        r.raise_for_status()
        nonce = _extract_nonce(r.text)
        if not nonce:
            raise SystemExit("Could not find login nonce on /login page.")

        # 2. POST credentials
        r = self.session.post(
            f"{self.base}/login",
            data={"name": self.user, "password": self.password, "nonce": nonce},
            allow_redirects=False,
        )
        # CTFd redirects (302) to /challenges on success.
        if r.status_code not in (301, 302, 303):
            if "incorrect" in r.text.lower() or "invalid" in r.text.lower():
                raise SystemExit("Login failed: incorrect credentials.")
            raise SystemExit(f"Login failed: unexpected status {r.status_code}.")
        self._log(f"[ok] logged in as {self.user}")
        self._save_cookies()
        return True

    def get_nonce(self):
        """Fetch a fresh CSRF nonce (needed for POST /attempt)."""
        if self._nonce:
            return self._nonce
        r = self.session.get(f"{self.base}/challenges")
        r.raise_for_status()
        self._nonce = _extract_nonce(r.text)
        if not self._nonce:
            raise SystemExit("Could not find csrfNonce on /challenges page.")
        return self._nonce

    def api_get(self, path):
        r = self.session.get(f"{self.base}{path}")
        r.raise_for_status()
        return r.json()

    def list_challenges(self):
        data = self.api_get("/api/v1/challenges")
        return data.get("data", []) if data.get("success") else []

    def get_challenge(self, challenge_id):
        data = self.api_get(f"/api/v1/challenges/{challenge_id}")
        return data.get("data") if data.get("success") else None

    def list_hints(self, challenge_id):
        """Get hints for a challenge (may be locked)."""
        try:
            data = self.api_get(f"/api/v1/hints?challenge_id={challenge_id}")
            return data.get("data") if data.get("success") else []
        except Exception:
            return []

    def download_file(self, file_url, dest):
        """Download a CTFd file URL (relative path with ?token=...) to dest."""
        url = file_url if file_url.startswith("http") else f"{self.base}{file_url}"
        with self.session.get(url, stream=True) as r:
            r.raise_for_status()
            dest.parent.mkdir(parents=True, exist_ok=True)
            with open(dest, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
        return dest

    def submit(self, challenge_id, flag):
        """Submit a flag. Returns the raw JSON response dict."""
        nonce = self.get_nonce()
        r = self.session.post(
            f"{self.base}/api/v1/challenges/attempt",
            headers={"CSRF-Token": nonce, "Content-Type": "application/json"},
            json={"challenge_id": int(challenge_id), "submission": flag},
        )
        try:
            return r.json()
        except Exception:
            return {"success": False, "error": f"HTTP {r.status_code}: {r.text[:200]}"}
