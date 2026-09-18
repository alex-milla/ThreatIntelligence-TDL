#!/usr/bin/env python3
"""Domain registration lookup (RDAP with a WHOIS port 43 fallback).

RDAP is preferred (JSON, IANA bootstrap). When a TLD has no RDAP server, or the
RDAP query fails, an optional classic WHOIS query on port 43 is attempted.
"""

import json
import os
import re
import socket
import time
from urllib.parse import quote

import requests

IANA_RDAP_URL = "https://data.iana.org/rdap/dns.json"
IANA_WHOIS_HOST = "whois.iana.org"
USER_AGENT = "ThreatIntelligence-TDL-Worker/1.0"
BOOTSTRAP_MAX_AGE = 7 * 24 * 3600


def _bootstrap_path(data_dir: str) -> str:
    return os.path.join(data_dir, "rdap_bootstrap.json")


def get_rdap_base(tld: str, data_dir: str, timeout: int = 15) -> str | None:
    """Return the RDAP base URL for a TLD using the IANA bootstrap (cached 7 days)."""
    tld = tld.lower().strip(".")
    cache_file = _bootstrap_path(data_dir)
    bootstrap = None

    try:
        if os.path.exists(cache_file) and (time.time() - os.path.getmtime(cache_file)) < BOOTSTRAP_MAX_AGE:
            with open(cache_file, "r", encoding="utf-8") as f:
                bootstrap = json.load(f)
    except (OSError, ValueError):
        bootstrap = None

    if not bootstrap:
        try:
            r = requests.get(IANA_RDAP_URL, headers={"User-Agent": USER_AGENT}, timeout=timeout)
            if r.status_code == 200:
                decoded = r.json()
                if decoded.get("services"):
                    os.makedirs(os.path.dirname(cache_file), exist_ok=True)
                    with open(cache_file, "w", encoding="utf-8") as f:
                        f.write(r.text)
                    bootstrap = decoded
        except (requests.RequestException, ValueError):
            bootstrap = None

    if not bootstrap:
        return None

    for service in bootstrap.get("services", []):
        tlds = service[0] if len(service) > 0 else []
        endpoints = service[1] if len(service) > 1 else []
        if tld in tlds and endpoints:
            return endpoints[0].rstrip("/") + "/"
    return None


def _parse_rdap(data: dict) -> dict:
    creation = None
    expiration = None
    registrar = None
    nameservers = []

    for event in data.get("events", []) or []:
        action = str(event.get("eventAction", "")).lower()
        if "registration" in action and not creation:
            creation = event.get("eventDate")
        if ("expiration" in action or "renewal" in action) and not expiration:
            expiration = event.get("eventDate")

    for entity in data.get("entities", []) or []:
        roles = [str(r).lower() for r in (entity.get("roles") or [])]
        if "registrar" in roles:
            vcard = entity.get("vcardArray")
            if isinstance(vcard, list) and len(vcard) > 1:
                for item in vcard[1]:
                    if item and item[0] in ("fn", "organization"):
                        registrar = item[3] if len(item) > 3 else None
                        break
            if not registrar:
                for pid in entity.get("publicIds", []) or []:
                    if pid.get("type") == "IANA Registrar ID":
                        registrar = "Registrar ID " + str(pid.get("identifier", "?"))
                        break

    for ns in data.get("nameservers", []) or []:
        name = ns.get("ldhName")
        if name:
            nameservers.append(name.lower().rstrip("."))

    return {
        "creation_date": creation,
        "expiration_date": expiration,
        "registrar": registrar,
        "name_servers": nameservers,
        "source": "rdap",
        "status": "ok",
    }


def lookup_rdap(domain: str, data_dir: str, timeout: int = 20) -> dict | None:
    tld = domain.rsplit(".", 1)[-1]
    base = get_rdap_base(tld, data_dir, timeout=timeout)
    urls = []
    if base:
        urls.append(base + "domain/" + quote(domain))
    urls.append("https://rdap.org/domain/" + quote(domain))

    for url in urls:
        try:
            r = requests.get(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                             timeout=timeout)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        try:
            data = r.json()
        except ValueError:
            continue
        parsed = _parse_rdap(data)
        parsed["domain"] = domain
        return parsed
    return None


def _whois_query(host: str, query: str, timeout: int = 15) -> str:
    with socket.create_connection((host, 43), timeout=timeout) as sock:
        sock.sendall((query + "\r\n").encode("utf-8", "ignore"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "ignore")


def _whois_server_for_tld(tld: str, timeout: int = 15) -> str | None:
    try:
        text = _whois_query(IANA_WHOIS_HOST, tld, timeout)
    except OSError:
        return None
    m = re.search(r"(?im)^(?:refer|whois):\s*(\S+)", text)
    return m.group(1).strip() if m else None


def _parse_whois_text(text: str) -> dict:
    def first(patterns):
        for pat in patterns:
            m = re.search(pat, text, re.IGNORECASE | re.MULTILINE)
            if m:
                return m.group(1).strip()
        return None

    registrar = first([r"^Registrar:\s*(.+)", r"^Sponsoring Registrar:\s*(.+)", r"^Registrar Name:\s*(.+)"])
    creation = first([
        r"^Creation Date:\s*(.+)", r"^Created On:\s*(.+)", r"^Domain Registration Date:\s*(.+)",
        r"^created:\s*(.+)", r"^registered:\s*(.+)",
    ])
    expiration = first([
        r"^Registry Expiry Date:\s*(.+)", r"^Expiry Date:\s*(.+)", r"^Expiration Date:\s*(.+)",
        r"^Registrar Registration Expiration Date:\s*(.+)", r"^paid-till:\s*(.+)",
    ])
    nameservers = [n.strip().lower().rstrip(".") for n in
                   re.findall(r"^(?:Name Server|nserver):\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)]

    return {
        "creation_date": creation,
        "expiration_date": expiration,
        "registrar": registrar,
        "name_servers": nameservers,
        "source": "whois",
        "status": "ok",
    }


def lookup_whois43(domain: str, timeout: int = 20) -> dict | None:
    tld = domain.rsplit(".", 1)[-1]
    server = _whois_server_for_tld(tld, timeout)
    if not server:
        return None
    try:
        text = _whois_query(server, domain, timeout)
    except OSError:
        return None
    if not text.strip():
        return None
    parsed = _parse_whois_text(text)
    parsed["domain"] = domain
    return parsed


def lookup_domain(domain: str, data_dir: str, timeout: int = 20,
                  rdap_only: bool = False, whois_fallback: bool = True) -> dict:
    """Look up a domain's registration data. Always returns a dict (never raises)."""
    domain = domain.lower().strip()
    result = lookup_rdap(domain, data_dir, timeout=timeout)
    if result is not None:
        return result

    if not rdap_only and whois_fallback:
        result = lookup_whois43(domain, timeout=timeout)
        if result is not None:
            return result
        return {"domain": domain, "status": "error", "source": "none",
                "creation_date": None, "expiration_date": None,
                "registrar": None, "name_servers": []}

    return {"domain": domain, "status": "unsupported", "source": "none",
            "creation_date": None, "expiration_date": None,
            "registrar": None, "name_servers": []}
