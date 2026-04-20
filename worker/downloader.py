#!/usr/bin/env python3
"""CZDS API client for downloading zone files."""

import os
import requests
from datetime import datetime, timezone

AUTH_URL = "https://account-api.icann.org/api/authenticate"
LINKS_URL = "https://czds-download-api.icann.org/czds/downloads/links"
BASE_API = "https://czds-download-api.icann.org"


def get_token(username: str, password: str) -> str | None:
    """Authenticate and return a Bearer token."""
    print("[*] Authenticating at account-api.icann.org ...")
    r = requests.post(AUTH_URL, json={"username": username, "password": password}, timeout=30)
    if r.status_code != 200:
        print(f"[-] Authentication failed: HTTP {r.status_code} - {r.text}")
        return None
    token = r.json().get("accessToken")
    if not token:
        print("[-] No accessToken in response.")
        return None
    print("[+] Token obtained.")
    return token


def get_approved_tlds(token: str) -> list[str]:
    """Return a list of approved TLD names by querying CZDS links."""
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(LINKS_URL, headers=headers, timeout=30)
    if r.status_code != 200:
        print(f"[-] Failed to list TLDs: HTTP {r.status_code} - {r.text}")
        return []
    data = r.json()
    # Response is a list of objects like {"tld": "zip", "link": "..."}
    tlds = []
    for item in data:
        tld = item.get("tld", "")
        if tld:
            tlds.append(tld.lower())
    print(f"[+] Approved TLDs found: {len(tlds)}")
    return tlds


def download_zone(tld: str, token: str, output_path: str) -> bool:
    """Download a single zone file to output_path. Returns True on success."""
    url = f"{BASE_API}/czds/downloads/{tld}.zone"
    headers = {"Authorization": f"Bearer {token}"}
    print(f"[*] Downloading {tld}.zone ...")

    r = requests.get(url, headers=headers, stream=True, timeout=600)
    if r.status_code == 401:
        print(f"[-] ERROR {tld}: Invalid token or no access.")
        return False
    elif r.status_code == 403:
        print(f"[-] ERROR {tld}: Access denied. Is this TLD approved?")
        return False
    elif r.status_code != 200:
        print(f"[-] ERROR {tld}: HTTP {r.status_code}")
        return False

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)

    size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"[+] {tld} saved: {output_path} ({size_mb:.1f} MB)")
    return True
