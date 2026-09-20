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

# RDAP base URLs for TLDs missing from the IANA bootstrap (verified manually).
# Merged with any [whois] rdap_overrides coming from the configuration.
RDAP_OVERRIDES = {
    "de": "https://rdap.denic.de/",
}

# Registries that restrict WHOIS port 43 (authorized IPs only) and/or do not
# publish registration data, so a direct lookup cannot succeed. Checked before
# any network call; override with [whois] disabled_tlds (use an empty value to
# disable this default and rely on [whois] whois_overrides).
DEFAULT_RESTRICTED_TLDS = {"es"}


def _bootstrap_path(data_dir: str) -> str:
    return os.path.join(data_dir, "rdap_bootstrap.json")


def get_rdap_base(tld: str, data_dir: str, timeout: int = 15,
                  overrides: dict | None = None) -> str | None:
    """Return the RDAP base URL for a TLD using the IANA bootstrap (cached 7 days)."""
    tld = tld.lower().strip(".")

    # Explicit overrides win over the bootstrap (some registries publish RDAP
    # without being listed by IANA, e.g. .de).
    merged = dict(RDAP_OVERRIDES)
    if overrides:
        merged.update({str(k).lower().strip("."): v for k, v in overrides.items() if v})
    if tld in merged:
        return str(merged[tld]).rstrip("/") + "/"

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


def lookup_rdap(domain: str, data_dir: str, timeout: int = 20,
                connect_timeout: int = 6, overrides: dict | None = None) -> dict | None:
    tld = domain.rsplit(".", 1)[-1]
    base = get_rdap_base(tld, data_dir, timeout=timeout, overrides=overrides)
    urls = []
    if base:
        urls.append(base + "domain/" + quote(domain))
    urls.append("https://rdap.org/domain/" + quote(domain))

    for url in urls:
        try:
            r = requests.get(url, headers={"Accept": "application/json", "User-Agent": USER_AGENT},
                             timeout=(max(1, connect_timeout), max(1, timeout)))
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


def _whois_query(host: str, query: str, timeout: int = 15, connect_timeout: int = 6) -> str:
    with socket.create_connection((host, 43), timeout=max(1, connect_timeout)) as sock:
        sock.settimeout(max(1, timeout))
        sock.sendall((query + "\r\n").encode("utf-8", "ignore"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "ignore")


def _whois_server_for_tld(tld: str, timeout: int = 15, connect_timeout: int = 6) -> str | None:
    try:
        text = _whois_query(IANA_WHOIS_HOST, tld, timeout, connect_timeout)
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


def lookup_whois43(domain: str, timeout: int = 20, connect_timeout: int = 6,
                   server_override: str | None = None) -> dict | None:
    tld = domain.rsplit(".", 1)[-1]
    server = server_override or _whois_server_for_tld(tld, timeout, connect_timeout)
    if not server:
        return None
    try:
        text = _whois_query(server, domain, timeout, connect_timeout)
    except OSError:
        return None
    if not text.strip():
        return None
    parsed = _parse_whois_text(text)
    parsed["domain"] = domain
    return parsed


def lookup_domain(domain: str, data_dir: str, timeout: int = 20,
                  rdap_only: bool = False, whois_fallback: bool = True,
                  connect_timeout: int = 6,
                  overrides: dict | None = None,
                  whois_overrides: dict | None = None,
                  disabled_tlds: set | None = None) -> dict:
    """Look up a domain's registration data. Always returns a dict (never raises).

    ``disabled_tlds`` defaults to :data:`DEFAULT_RESTRICTED_TLDS` (registries
    that need authorized IPs or publish no data). Pass an explicit set to change
    it; an empty set disables the shortcut entirely.
    """
    domain = domain.lower().strip()
    tld = domain.rsplit(".", 1)[-1]

    empty = {
        "domain": domain,
        "creation_date": None,
        "expiration_date": None,
        "registrar": None,
        "name_servers": [],
    }

    restricted = DEFAULT_RESTRICTED_TLDS if disabled_tlds is None else {
        str(t).lower().lstrip(".") for t in disabled_tlds
    }
    if tld in restricted:
        return {**empty, "status": "unsupported", "source": "none"}

    result = lookup_rdap(domain, data_dir, timeout=timeout,
                         connect_timeout=connect_timeout, overrides=overrides)
    if result is not None:
        return result

    if not rdap_only and whois_fallback:
        server_override = (whois_overrides or {}).get(tld)
        result = lookup_whois43(domain, timeout=timeout, connect_timeout=connect_timeout,
                                server_override=server_override)
        if result is not None:
            return result
        return {**empty, "status": "error", "source": "none"}

    return {**empty, "status": "unsupported", "source": "none"}
