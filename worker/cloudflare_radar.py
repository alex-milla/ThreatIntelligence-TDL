#!/usr/bin/env python3
"""Cloudflare Radar client: URL Scanner + DNS top locations.

Two independent, optional enrichments for a domain:

  * URL Scanner (account-scoped ``/urlscanner/v2``): a asynchronous page scan
    that returns a verdict (malicious), Cloudflare domain categories, the Radar
    rank, detected technologies, the phishing type, TLS certificate data, the
    hosting ASN/country and a public report URL. ``scan_domain`` submits it and
    ``fetch_result`` polls until the report is ready.
  * Radar DNS (``/radar/dns/top/locations``): the geographic distribution of
    DNS queries to the domain via the 1.1.1.1 resolver.

Authentication is a Cloudflare API token (``Authorization: Bearer``). The URL
Scanner needs ``Account > URL Scanner`` write and the Radar DNS call needs
``Account > Radar`` read; a single custom token can carry both permissions.
Both APIs are free; Radar data is licensed CC BY-NC 4.0 (non-commercial).
"""

import time

import requests

RADAR_BASE = "https://api.cloudflare.com/client/v4/radar"
URLSCANNER_BASE = "https://api.cloudflare.com/client/v4/accounts/{account_id}/urlscanner/v2"

# Cloudflare categories that, without a hard malicious verdict, still make a
# domain worth a second look.
_BAD_CATEGORIES = {
    "malicious", "phishing", "malware", "command and control",
    "compromised", "spam", "botnet",
}


class AuthError(Exception):
    """Missing or invalid Cloudflare token (surfaced to the UI)."""


class QuotaError(Exception):
    """Rate/quota limit reached (the batch should stop)."""


def _as_list(value) -> list[str]:
    """Normalise a str/list/dict (or None) into a list of non-empty strings."""
    if value is None:
        return []
    if isinstance(value, str):
        value = [value]
    out: list[str] = []
    if isinstance(value, list):
        for item in value:
            if isinstance(item, dict):
                # Wappalyzer entries look like {"name": "WordPress", ...}.
                item = item.get("name") or item.get("value") or item.get("label")
            if item is None:
                continue
            text = str(item).strip()
            if text:
                out.append(text)
    elif isinstance(value, dict):
        out = [str(k).strip() for k in value.keys() if str(k).strip()]
    return out


def _raise_http_error(response, service: str) -> None:
    """Turn a failed response into AuthError (bad token) or QuotaError."""
    if response.status_code in (401, 403):
        raise AuthError(f"{service} authentication failed (HTTP {response.status_code})")
    if response.status_code == 429:
        raise QuotaError(f"{service} rate limit reached (HTTP 429)")
    raise QuotaError(f"{service} HTTP {response.status_code}")


def _payload(response) -> dict:
    """Return the meaningful object of a Cloudflare response (wrapped or flat)."""
    try:
        data = response.json() or {}
    except ValueError:
        return {}
    result = data.get("result")
    if isinstance(result, dict):
        return result
    return data


def scan_domain(domain: str, token: str, account_id: str,
                visibility: str = "public", timeout: int = 30) -> dict:
    """Submit a URL scan. Returns {uuid, report_url, api_url, url}.

    Raises AuthError when the token/account is missing or rejected, QuotaError on
    any other failure.
    """
    if not token or not account_id:
        raise AuthError("Cloudflare URL Scanner not configured (urlscanner_token/account_id)")
    url = URLSCANNER_BASE.format(account_id=account_id) + "/scan"
    vis = "unlisted" if str(visibility or "").strip().lower() == "unlisted" else "public"
    body = {"url": f"https://{domain}", "visibility": vis.capitalize()}
    r = requests.post(url, headers={"Authorization": f"Bearer {token}"}, json=body, timeout=timeout)
    if r.status_code != 200:
        _raise_http_error(r, "URL Scanner")
    payload = _payload(r)
    return {
        "uuid": payload.get("uuid") or "",
        "report_url": payload.get("result") or "",
        "api_url": payload.get("api") or "",
        "url": payload.get("url") or f"https://{domain}",
    }


def fetch_result(token: str, account_id: str, scan_id: str, timeout: int = 30,
                 poll_interval: int = 15, max_wait: int = 180) -> dict:
    """Poll the scan report until it is ready. Returns the raw report object."""
    if not token or not account_id:
        raise AuthError("Cloudflare URL Scanner not configured (urlscanner_token/account_id)")
    url = URLSCANNER_BASE.format(account_id=account_id) + f"/result/{scan_id}"
    deadline = time.time() + max(1, int(max_wait))
    while True:
        r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=timeout)
        if r.status_code == 200:
            return _payload(r)
        if r.status_code == 404:  # scan still in progress
            if time.time() >= deadline:
                raise QuotaError("URL Scanner report timed out")
            time.sleep(max(1, int(poll_interval)))
            continue
        _raise_http_error(r, "URL Scanner")


def classify(report: dict, domain: str, report_url: str = "") -> dict:
    """Normalise a URL Scanner report into a flat, storable dict."""
    meta = (report.get("meta") or {}).get("processors") or {}
    verdicts = report.get("verdicts") or {}
    overall = verdicts.get("overall") or {}
    page = report.get("page") or {}
    task = report.get("task") or {}

    malicious = bool(overall.get("malicious"))
    categories = _as_list(meta.get("domainCategories"))
    phishing = _as_list(meta.get("phishing"))
    rank = meta.get("radarRank")
    technologies = _as_list(meta.get("wappa"))

    cert_issuer = ""
    certificates = ((report.get("lists") or {}).get("certificates"))
    if isinstance(certificates, list) and certificates and isinstance(certificates[0], dict):
        cert_issuer = str(certificates[0].get("issuer") or "")

    failed = task.get("success") is False or str(task.get("status") or "").lower() in ("failed", "error")
    bad_category = any(c.strip().lower() in _BAD_CATEGORIES for c in categories)

    if failed:
        status, verdict = "error", ""
    else:
        status = "ok"
        if malicious:
            verdict = "malicious"
        elif phishing or bad_category:
            verdict = "suspicious"
        else:
            verdict = "clean"

    return {
        "domain": domain,
        "status": status,
        "error": ("scan failed" if failed else ""),
        "verdict": verdict,
        "categories": ", ".join(categories),
        "phishing": ", ".join(phishing),
        "radar_rank": "" if rank in (None, "") else str(rank),
        "technologies": ", ".join(technologies),
        "asn": str(page.get("asn") or ""),
        "country": str(page.get("country") or ""),
        "cert_issuer": cert_issuer,
        "dom_struct_hash": str(page.get("domStructHash") or ""),
        "favicon_hash": str((page.get("favicon") or {}).get("hash") or "") if isinstance(page.get("favicon"), dict) else "",
        "report_url": report_url,
        "last_analysis_date": str(task.get("time") or ""),
    }


def dns_top_locations(domain: str, token: str, timeout: int = 30,
                      limit: int = 10, date_range: str = "7d") -> list[dict]:
    """Return the top countries for DNS queries to a domain (1.1.1.1).

    Each item: {"code", "name", "value"}. Raises AuthError/QuotaError on failure.
    """
    if not token:
        raise AuthError("Cloudflare Radar not configured (api_token)")
    url = f"{RADAR_BASE}/dns/top/locations"
    params = {"domain": domain, "dateRange": date_range, "format": "json", "limit": max(1, int(limit))}
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=timeout)
    if r.status_code != 200:
        _raise_http_error(r, "Radar DNS")
    try:
        data = r.json() or {}
    except ValueError:
        return []
    if not data.get("success", True):
        return []
    result = data.get("result") or {}
    rows = []
    for key, value in result.items():
        if isinstance(key, str) and key.startswith("top_") and isinstance(value, list):
            rows = value
            break
    out = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        out.append({
            "code": str(row.get("clientCountryAlpha2") or ""),
            "name": str(row.get("clientCountryName") or ""),
            "value": str(row.get("value") or ""),
        })
    return out


def error_result(domain: str, error: str) -> dict:
    """A storable entry for a domain whose lookup failed."""
    return {"domain": domain, "status": "error", "error": str(error)[:255], "verdict": ""}


def usage_count(db, period: str) -> int:
    row = db.execute("SELECT count FROM cf_usage WHERE period = ?", (period,)).fetchone()
    return int(row[0]) if row else 0


def usage_add(db, period: str, n: int = 1) -> None:
    db.execute(
        "INSERT INTO cf_usage (period, count) VALUES (?, ?) "
        "ON CONFLICT(period) DO UPDATE SET count = count + ?",
        (period, n, n),
    )
    db.commit()
