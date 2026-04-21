#!/usr/bin/env python3
"""Client to sync with the shared hosting API."""

import json
import requests
from datetime import datetime, timezone


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
    url = f"{host_url}/api/v1/worker_status.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    r = requests.post(url, headers=headers, json=stats, timeout=30)
    return r.status_code == 200


def get_commands(host_url: str, api_key: str) -> list[dict]:
    """Fetch pending commands from the hosting API."""
    url = f"{host_url}/api/v1/commands.php"
    headers = {"X-API-Key": api_key}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    if data.get("success"):
        return data.get("commands", [])
    return []


def mark_command_done(host_url: str, api_key: str, command_id: int, status: str = "completed", result: str = "") -> bool:
    """Mark a command as completed on the hosting API."""
    url = f"{host_url}/api/v1/commands.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "command_id": command_id,
        "status": status,
        "result": result,
    }
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    return r.status_code == 200


def send_logs(host_url: str, api_key: str, logs: list[dict]) -> bool:
    """Send worker logs to the hosting API."""
    if not logs:
        return True
    url = f"{host_url}/api/v1/worker_logs.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    payload = {"logs": logs}
    r = requests.post(url, headers=headers, json=payload, timeout=30)
    return r.status_code == 200


def send_tlds(host_url: str, api_key: str, tlds: list[str]) -> bool:
    """Send approved TLD list to the hosting API."""
    url = f"{host_url}/api/v1/tlds.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    r = requests.post(url, headers=headers, json={"tlds": tlds}, timeout=60)
    return r.status_code == 200


def get_active_tlds(host_url: str, api_key: str) -> list[str]:
    """Fetch active TLDs from the hosting API."""
    url = f"{host_url}/api/v1/tlds.php?active=1"
    headers = {"X-API-Key": api_key}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    if data.get("success"):
        return [row["name"] for row in data.get("tlds", [])]
    return []


def send_recheck_status(host_url: str, api_key: str, status: dict) -> bool:
    """Send recheck progress to the hosting API."""
    url = f"{host_url}/api/v1/recheck_status.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    r = requests.post(url, headers=headers, json=status, timeout=30)
    return r.status_code == 200
