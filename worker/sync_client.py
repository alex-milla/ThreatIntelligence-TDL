#!/usr/bin/env python3
"""Client to sync matches and fetch keywords from the shared hosting API."""

import json
import requests
from datetime import datetime, timezone, timedelta


def get_keywords(host_url: str, api_key: str) -> list[dict]:
    """Fetch active keywords from the hosting API."""
    url = f"{host_url}/api/v1/keywords.php"
    headers = {"X-API-Key": api_key}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    if data.get("success"):
        return data.get("keywords", [])
    return []


def send_matches(host_url: str, api_key: str, matches: list[dict]) -> bool:
    """Send matches to the hosting API. Returns True on success."""
    if not matches:
        return True
    url = f"{host_url}/api/v1/matches.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "matches": matches,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    if r.status_code == 200:
        print(f"[+] Sent {len(matches)} matches to hosting.")
        return True
    else:
        print(f"[-] Failed to send matches: HTTP {r.status_code} - {r.text}")
        return False


def send_heartbeat(host_url: str, api_key: str, stats: dict) -> bool:
    """Send worker heartbeat/status to hosting."""
    url = f"{host_url}/api/v1/heartbeat.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    r = requests.post(url, headers=headers, json=stats, timeout=30)
    return r.status_code == 200
