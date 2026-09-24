#!/usr/bin/env python3
"""Dormant-domain tracking signals (Intelligence).

`evaluate` / `compare_whois` are pure logic (unit-tested). The DNS and crt.sh
helpers reach the network; they use free, key-less services (Google DoH and
crt.sh) so no extra dependency is needed.
"""

import hashlib
import json
import re
from datetime import datetime
from urllib.parse import quote

import requests

USER_AGENT = "ThreatIntelligence-TDL-Worker/1.0"
DOH_URL = "https://dns.google/resolve?name={name}&type={type}"
CRTSH_URL = "https://crt.sh/?q=%25.{domain}&output=json"
HTTP_UA = "Mozilla/5.0 (compatible; ThreatIntelligence-TDL/1.0; +https://github.com/alex-milla/ThreatIntelligence-TDL)"

_LOGIN_RE = re.compile(r"<input[^>]*type\s*=\s*[\"']?password", re.IGNORECASE)
_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


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
             dns_started=False, dns_now=None, cert_new=False,
             http_brand=False, http_login=False, http_200=None,
             http_changed=False, http_activate_any_200=False):
    """Combine the tracking signals into a result dict.

    Activation signals: reputation malicious/suspicious (F1); a domain that
    starts resolving after not resolving at enrollment, a TLS certificate issued
    after enrollment (F2); and HTTP content with the brand keyword or a login
    form (F3). WHOIS/NS changes, a plain HTTP 200 and content-hash changes are
    informational.
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
    if http_brand:
        reasons.append("HTTP: brand content")
    if http_login:
        reasons.append("HTTP: login form")
    if http_activate_any_200 and http_200 is True and not (http_brand or http_login):
        reasons.append("HTTP: responds 200")

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
    if http_200 is not None:
        signals.append({
            "type": "http",
            "status": http_200,
            "brand": bool(http_brand),
            "login": bool(http_login),
            "changed": bool(http_changed),
        })

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


def has_login_form(html: str) -> bool:
    """True if the HTML contains a password input (login form)."""
    return bool(_LOGIN_RE.search(html or ""))


def extract_title(html: str) -> str:
    """Page <title> text (trimmed, capped), or an empty string."""
    m = _TITLE_RE.search(html or "")
    return m.group(1).strip()[:300] if m else ""


def content_hash(text: str) -> str:
    """Short stable hash of the page content (for change detection)."""
    if not text:
        return ""
    return hashlib.sha256(text.encode("utf-8", "ignore")).hexdigest()[:32]


def contains_keyword(title: str, body: str, keywords) -> bool:
    """True if any keyword appears (case-insensitive) in the title or body."""
    haystack = ((title or "") + " " + (body or "")).lower()
    for k in keywords or []:
        k = str(k).strip().lower()
        if k and k in haystack:
            return True
    return False


def http_probe(domain, timeout: int = 15, max_bytes: int = 200000) -> dict:
    """Best-effort HTTP(S) probe of a tracked domain.

    Tries HTTPS then HTTP. Reads at most `max_bytes` so a huge page cannot blow
    memory. Returns a result dict; never raises.
    """
    result = {
        "ok": False, "status": None, "final_url": "", "length": 0,
        "title": "", "has_login": False, "body_hash": "", "body": "",
    }
    headers = {"User-Agent": HTTP_UA, "Accept": "text/html,application/xhtml+xml"}
    for scheme in ("https", "http"):
        try:
            r = requests.get(scheme + "://" + str(domain) + "/", headers=headers,
                             timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            continue
        raw = (r.content or b"")[:max_bytes]
        text = raw.decode(r.encoding or "utf-8", "ignore")
        result["ok"] = r.status_code < 500
        result["status"] = r.status_code
        result["final_url"] = r.url or ""
        result["length"] = len(r.content or b"")
        result["title"] = extract_title(text)
        result["has_login"] = has_login_form(text)
        result["body_hash"] = content_hash(text)
        result["body"] = text
        return result
    return result
