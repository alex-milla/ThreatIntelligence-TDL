#!/usr/bin/env python3
"""CZDS API client for downloading zone files."""

import http.client
import json
import os
import time
import requests
from datetime import datetime, timezone
from urllib.parse import urlparse

AUTH_URL = "https://account-api.icann.org/api/authenticate"
LINKS_URL = "https://czds-api.icann.org/czds/downloads/links"
BASE_API = "https://czds-api.icann.org"

CHUNK_SIZE = 1024 * 1024


def get_token(username: str, password: str) -> str | None:
    """Authenticate and return a Bearer token."""
    print("[*] Authenticating at account-api.icann.org ...", flush=True)
    r = requests.post(AUTH_URL, json={"username": username, "password": password}, timeout=30)
    if r.status_code != 200:
        print(f"[-] Authentication failed: HTTP {r.status_code} - {r.text}", flush=True)
        return None
    token = r.json().get("accessToken")
    if not token:
        print("[-] No accessToken in response.", flush=True)
        return None
    print("[+] Token obtained.", flush=True)
    return token


def get_approved_tlds(token: str) -> list[str]:
    """Return a list of approved TLD names by querying CZDS links."""
    headers = {"Authorization": f"Bearer {token}"}
    r = requests.get(LINKS_URL, headers=headers, timeout=30)
    if r.status_code != 200:
        print(f"[-] Failed to list TLDs: HTTP {r.status_code} - {r.text}", flush=True)
        return []
    data = r.json()
    tlds = []
    for item in data:
        if isinstance(item, str):
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
    print(f"[+] Approved TLDs found: {len(tlds)}", flush=True)
    return tlds


def head_zone(tld: str, token: str) -> tuple[int | None, str | None, str | None]:
    """Return (content_length, etag, last_modified) for a zone without downloading it."""
    url = f"{BASE_API}/czds/downloads/{tld}.zone"
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.head(url, headers=headers, timeout=30, allow_redirects=True)
        if r.status_code == 200:
            length = r.headers.get("Content-Length")
            return (int(length) if length and length.isdigit() else None,
                    r.headers.get("ETag"), r.headers.get("Last-Modified"))
    except requests.RequestException:
        pass
    return None, None, None


def _read_meta(meta_path: str) -> dict:
    try:
        with open(meta_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _write_meta(meta_path: str, etag: str | None, total: int | None) -> None:
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump({"etag": etag, "total": total}, f)
    except OSError:
        pass


def _parse_content_range(value: str | None) -> int | None:
    """Extract the total size from a 'bytes start-end/total' header."""
    if not value or "/" not in value:
        return None
    total = value.rsplit("/", 1)[1].strip()
    return int(total) if total.isdigit() else None


def download_zone(tld: str, token: str, output_path: str,
                  etag: str | None = None, last_modified: str | None = None,
                  progress_callback=None, max_retries: int = 3,
                  resume: bool = True) -> tuple[str, str | None, str | None, str | None]:
    """
    Download a single zone file robustly.

    Supports resuming a previous partial download (HTTP Range + If-Range) and
    retries transient failures (connection drops / incomplete reads). Progress is
    reported through progress_callback("download", downloaded_bytes, total_bytes).

    Returns (status, etag, last_modified, error):
      - ("downloaded",   etag, last_modified, None)   on a complete download
      - ("not_modified", etag, last_modified, None)   on HTTP 304
      - ("failed",       None, None, reason)          on any error
    """
    url = f"{BASE_API}/czds/downloads/{tld}.zone"
    part_path = output_path + ".part"
    meta_path = part_path + ".meta"
    out_dir = os.path.dirname(output_path)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    # Decide whether an existing partial can be resumed.
    part_size = os.path.getsize(part_path) if os.path.exists(part_path) else 0
    meta = _read_meta(meta_path) if (resume and part_size > 0) else {}
    resume_etag = meta.get("etag")
    if part_size > 0 and not resume_etag:
        # Partial without validators: cannot guarantee it matches the current
        # zone, so discard it and start fresh.
        try:
            os.remove(part_path)
        except OSError:
            pass
        part_size = 0

    last_error = "unknown error"
    for attempt in range(1, max_retries + 1):
        headers = {"Authorization": f"Bearer {token}"}
        resuming = part_size > 0 and bool(resume_etag)
        if resuming:
            headers["Range"] = f"bytes={part_size}-"
            headers["If-Range"] = resume_etag
        else:
            if etag:
                headers["If-None-Match"] = etag
            if last_modified:
                headers["If-Modified-Since"] = last_modified

        try:
            r = requests.get(url, headers=headers, stream=True, timeout=(30, 600))
        except requests.RequestException as e:
            last_error = f"connection error: {e}"
            time.sleep(min(5 * attempt, 30))
            continue

        try:
            if r.status_code == 304:
                print(f"[=] {tld}.zone not modified (HTTP 304). Skipping download.", flush=True)
                return "not_modified", etag, last_modified, None
            if r.status_code in (401, 403):
                return "failed", None, None, f"HTTP {r.status_code}: access denied or invalid token"
            if r.status_code == 416:
                # Range not satisfiable (partial larger than remote): restart.
                try:
                    os.remove(part_path)
                except OSError:
                    pass
                part_size = 0
                resume_etag = None
                last_error = "HTTP 416 (range not satisfiable); restarting"
                continue
            if r.status_code == 206:
                resuming = True
                expected_total = _parse_content_range(r.headers.get("Content-Range"))
                response_etag = r.headers.get("ETag") or resume_etag
            elif r.status_code == 200:
                resuming = False
                part_size = 0
                expected_total = r.headers.get("Content-Length")
                expected_total = int(expected_total) if expected_total and expected_total.isdigit() else None
                response_etag = r.headers.get("ETag")
            else:
                return "failed", None, None, f"HTTP {r.status_code}"

            response_lm = r.headers.get("Last-Modified")
            mode = "ab" if resuming else "wb"
            written = part_size
            _write_meta(meta_path, response_etag, expected_total)

            print(f"[*] Downloading {tld}.zone "
                  + (f"(resuming at {written / 1048576:.1f} MB) ..." if resuming else "..."), flush=True)

            last_report = 0.0
            with open(part_path, mode) as f:
                for chunk in r.iter_content(chunk_size=CHUNK_SIZE):
                    if not chunk:
                        continue
                    f.write(chunk)
                    written += len(chunk)
                    now = time.time()
                    if progress_callback and (now - last_report >= 1.0):
                        last_report = now
                        progress_callback("download", written, expected_total)

            if expected_total is not None and written != expected_total:
                last_error = f"incomplete download: {written} of {expected_total} bytes"
                # Keep the partial + meta so the next attempt can resume.
                time.sleep(min(5 * attempt, 30))
                continue

            os.replace(part_path, output_path)
            try:
                os.remove(meta_path)
            except OSError:
                pass
            size_mb = os.path.getsize(output_path) / 1048576
            print(f"[+] {tld} saved: {output_path} ({size_mb:.1f} MB)", flush=True)
            return "downloaded", response_etag, response_lm, None
        except (requests.exceptions.ChunkedEncodingError,
                requests.exceptions.ConnectionError,
                http.client.IncompleteRead,
                requests.exceptions.RequestException) as e:
            last_error = f"transfer interrupted: {e}"
            # Keep whatever was written; refresh part size for the resume.
            part_size = os.path.getsize(part_path) if os.path.exists(part_path) else 0
            if part_size == 0:
                resume_etag = None
            time.sleep(min(5 * attempt, 30))
            continue
        finally:
            r.close()

    return "failed", None, None, last_error
