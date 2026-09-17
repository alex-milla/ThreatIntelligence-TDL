#!/usr/bin/env python3
"""CZDS API client for downloading zone files."""

import os
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

AUTH_URL = "https://account-api.icann.org/api/authenticate"
LINKS_URL = "https://czds-api.icann.org/czds/downloads/links"
BASE_API = "https://czds-api.icann.org"


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
    # Response is a list of download URLs like "https://czds-api.icann.org/czds/downloads/zip.zone"
    tlds = []
    for item in data:
        if isinstance(item, str):
            # Extract TLD from URL robustly: https://.../downloads/zip.zone -> zip
            path = urlparse(item).path
            name = os.path.basename(path)
            if name.endswith(".zone"):
                tld = name[:-5].lower()
                if tld:
                    tlds.append(tld)
        elif isinstance(item, dict):
            tld = item.get("tld", "")
            if tld:
                tlds.append(tld.lower())
    print(f"[+] Approved TLDs found: {len(tlds)}")
    return tlds


def download_zone(tld: str, token: str, output_path: str,
                  etag: str | None = None, last_modified: str | None = None) -> tuple[str, str | None, str | None]:
    """
    Download a single zone file using a conditional HTTP request.

    Sends If-None-Match / If-Modified-Since when previous validators are known
    so that an unchanged zone is not transferred again. This keeps the load on
    the ICANN CZDS API to the minimum.

    Returns a tuple (status, etag, last_modified):
      - ("downloaded", new_etag, new_last_modified) on HTTP 200
      - ("not_modified", etag, last_modified) on HTTP 304
      - ("failed", None, None) on any error
    """
    url = f"{BASE_API}/czds/downloads/{tld}.zone"
    headers = {"Authorization": f"Bearer {token}"}
    if etag:
        headers["If-None-Match"] = etag
    if last_modified:
        headers["If-Modified-Since"] = last_modified
    print(f"[*] Downloading {tld}.zone ...")

    r = requests.get(url, headers=headers, stream=True, timeout=600)
    if r.status_code == 304:
        print(f"[=] {tld}.zone not modified (HTTP 304). Skipping download.")
        return "not_modified", etag, last_modified
    elif r.status_code == 401:
        print(f"[-] ERROR {tld}: Invalid token or no access.")
        return "failed", None, None
    elif r.status_code == 403:
        print(f"[-] ERROR {tld}: Access denied. Is this TLD approved?")
        return "failed", None, None
    elif r.status_code != 200:
        print(f"[-] ERROR {tld}: HTTP {r.status_code}")
        return "failed", None, None

    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Write to a temp file and rename atomically so an interrupted download
    # never replaces a previously good copy of the zone.
    tmp_path = output_path + ".part"
    with open(tmp_path, "wb") as f:
        for chunk in r.iter_content(chunk_size=1024 * 1024):
            if chunk:
                f.write(chunk)
    os.replace(tmp_path, output_path)

    new_etag = r.headers.get("ETag")
    new_last_modified = r.headers.get("Last-Modified")
    size_mb = os.path.getsize(output_path) / (1024 * 1024)
    print(f"[+] {tld} saved: {output_path} ({size_mb:.1f} MB)")
    return "downloaded", new_etag, new_last_modified
