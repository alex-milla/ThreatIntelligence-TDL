#!/usr/bin/env python3
"""Dormant-domain tracking signals (Intelligence).

`evaluate` / `compare_whois` are pure logic (unit-tested). The DNS and crt.sh
helpers reach the network; they use free, key-less services (Google DoH and
crt.sh) so no extra dependency is needed.
"""

import json
from datetime import datetime
from urllib.parse import quote

import requests

USER_AGENT = "ThreatIntelligence-TDL-Worker/1.0"
DOH_URL = "https://dns.google/resolve?name={name}&type={type}"
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"


def _ns_set(value):
    """Normalize a nameserver value (JSON string or list) into a lowercase set."""
    if not value:
        return set()
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return set()
    if not isinstance(value, (list, tuple, set)):
        return set()
    return {str(x).strip().lower() for x in value if str(x).strip()}


def compare_whois(baseline, whois_now):
    """Detect nameserver / registrar changes against the enrollment baseline.

    Returns ``(changed: bool, detail: str)``.
    """
    base = (baseline or {}).get("whois") or {}
    now = whois_now or {}
    details = []

    base_ns = _ns_set(base.get("name_servers"))
    now_ns = _ns_set(now.get("name_servers"))
    if base_ns and now_ns and base_ns != now_ns:
        details.append("nameservers changed")

    base_reg = str(base.get("registrar") or "").strip().lower()
    now_reg = str(now.get("registrar") or "").strip().lower()
    if base_reg and now_reg and base_reg != now_reg:
        details.append("registrar changed")

    return (len(details) > 0, "; ".join(details))


def evaluate(abusech_result, vt_result, whois_changed, whois_detail="",
             dns_started=False, dns_now=None, cert_new=False):
    """Combine the tracking signals into a result dict.

    Activation signals: reputation malicious/suspicious (F1), a domain that
    starts resolving after not resolving at enrollment, and a TLS certificate
    issued after enrollment (F2). WHOIS/NS changes are informational.
    """
    av = (abusech_result or {}).get("verdict")
    vv = (vt_result or {}).get("verdict")

    reasons = []
    if av in ("malicious", "suspicious"):
        reasons.append("abuse.ch: " + av)
    if vv in ("malicious", "suspicious", "dga"):
        reasons.append("VirusTotal: " + vv)
    if dns_started:
        reasons.append("DNS: now resolves")
    if cert_new:
        reasons.append("TLS certificate issued")

    signals = [{
        "type": "reputation",
        "abusech": av or "not_checked",
        "vt": vv or "not_checked",
    }]
    if whois_changed:
        signals.append({"type": "whois_change", "detail": whois_detail or "changed"})
    if dns_now is not None:
        signals.append({"type": "dns", "resolves": bool(dns_now)})
    if cert_new:
        signals.append({"type": "cert", "detail": "new certificate"})

    return {
        "activated": bool(reasons),
        "activated_reason": "; ".join(reasons),
        "signals": signals,
        "whois_changed": bool(whois_changed),
        "whois_detail": whois_detail,
    }


def dns_resolves(domain, timeout: int = 10):
    """True/False if the domain resolves (A or AAAA), None on error.

    Uses Google's DNS-over-HTTPS JSON API (no dependency, no key).
    """
    for rtype in ("A", "AAAA"):
        try:
            r = requests.get(DOH_URL.format(name=quote(domain), type=rtype),
                             headers={"User-Agent": USER_AGENT}, timeout=timeout)
        except requests.RequestException:
            return None
        if r.status_code != 200:
            return None
        try:
            data = r.json()
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        if data.get("Status") == 0 and data.get("Answer"):
            return True
    return False


def cert_newer_than(entries, since_utc: str) -> bool:
    """True if any crt.sh entry was issued (not_before) after `since_utc`."""
    if not entries or not since_utc:
        return False
    try:
        since = datetime.strptime(str(since_utc)[:19], "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return False
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("not_before") or entry.get("entry_timestamp")
        if not raw:
            continue
        nb = None
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
            try:
                nb = datetime.strptime(str(raw)[:19], fmt)
                break
            except ValueError:
                continue
        if nb is not None and nb > since:
            return True
    return False


def crt_sh_has_new_cert(domain, since_utc: str, timeout: int = 30):
    """True if crt.sh shows a certificate not_before the given UTC timestamp.

    `since_utc` is a "YYYY-MM-DD HH:MM:SS" string (the enrollment time). Returns
    False when no newer cert is found, None on error (crt.sh is best effort).
    """
    if not since_utc:
        return None
    try:
        r = requests.get(CRTSH_URL.format(domain=quote(domain)),
                         headers={"User-Agent": USER_AGENT}, timeout=timeout)
    except requests.RequestException:
        return None
    if r.status_code != 200:
        return None
    try:
        data = r.json()
    except ValueError:
        return None
    if not isinstance(data, list):
        return None
    return cert_newer_than(data, since_utc)
