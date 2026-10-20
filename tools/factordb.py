#!/usr/bin/env python3
"""factordb.py — Query factordb.com API to factor large integers."""
import sys, json, urllib.request

def factor(num_str):
    url = f"https://factordb.com/api?query={num_str.strip()}"
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode())
            print(f"[*] FactorDB Status: {data.get('status')} (FF=Fully Factored, CF=Composite Factor)")
            factors = data.get("factors", [])
            print("[+] Factors:")
            for p, count in factors:
                exp = f"^{count}" if count > 1 else ""
                print(f"    {p}{exp}")
            return factors
    except Exception as e:
        print(f"[-] Query failed: {e}")
        return None

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python factordb.py <integer>")
        sys.exit(1)
    factor(sys.argv[1])
