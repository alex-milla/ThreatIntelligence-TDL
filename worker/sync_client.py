#!/usr/bin/env python3
"""Client to sync with the shared hosting API."""

import json
import time
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


def update_command_status(host_url: str, api_key: str, command_id: int, status: str, result: str = "") -> bool:
    """Update a command's lifecycle status on the hosting API. Retries on failure."""
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
    for attempt in range(1, 4):
        r = requests.post(url, headers=headers, json=payload, timeout=30)
        if r.status_code == 200:
            return True
        if attempt < 3:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"Failed to mark command {command_id} as {status}: HTTP {r.status_code} - {r.text}")


def mark_command_done(host_url: str, api_key: str, command_id: int, status: str = "completed", result: str = "") -> bool:
    """Mark a command as completed on the hosting API. Raises on failure so callers can retry."""
    return update_command_status(host_url, api_key, command_id, status, result)


def send_whois_results(host_url: str, api_key: str, entries: list[dict]) -> bool:
    """Send domain registration (whois/RDAP) results to the hosting API."""
    if not entries:
        return True
    url = f"{host_url}/api/v1/whois_results.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    r = requests.post(url, headers=headers, json={"entries": entries}, timeout=60)
    if r.status_code == 200:
        return True
    print(f"[-] Failed to send whois results: HTTP {r.status_code} - {r.text}")
    return False


def get_running_commands(host_url: str, api_key: str) -> list[dict]:
    """Return commands left in 'running' state (e.g. after a worker restart)."""
    url = f"{host_url}/api/v1/commands.php?recover=1"
    headers = {"X-API-Key": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        if data.get("success"):
            return data.get("commands", [])
    except Exception:
        pass
    return []


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


def report_tld_sync(host_url: str, api_key: str, entries: list[dict]) -> bool:
    """Report per-TLD download/parse results so the web UI can show what was updated."""
    if not entries:
        return True
    url = f"{host_url}/api/v1/tld_sync.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    r = requests.post(url, headers=headers, json={"entries": entries}, timeout=60)
    if r.status_code == 200:
        return True
    print(f"[-] Failed to report TLD sync: HTTP {r.status_code} - {r.text}")
    return False


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


def send_cctld_sync(host_url: str, api_key: str, entries: list[dict]) -> bool:
    """Report OpenINTEL per-ccTLD results so the web UI can show them."""
    if not entries:
        return True
    url = f"{host_url}/api/v1/cctld_sync.php"
    headers = {
        "X-API-Key": api_key,
        "Content-Type": "application/json",
    }
    r = requests.post(url, headers=headers, json={"entries": entries}, timeout=60)
    if r.status_code == 200:
        return True
    print(f"[-] Failed to report ccTLD sync: HTTP {r.status_code} - {r.text}")
    return False


def get_openintel_tlds(host_url: str, api_key: str) -> list[str]:
    """Fetch the active OpenINTEL (ccTLD) TLDs configured in the web panel."""
    url = f"{host_url}/api/v1/tlds.php?source=openintel&active=1"
    headers = {"X-API-Key": api_key}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    data = r.json()
    if data.get("success"):
        return [row["name"] for row in data.get("tlds", [])]
    return []
