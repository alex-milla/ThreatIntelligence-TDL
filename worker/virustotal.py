#!/usr/bin/env python3
"""VirusTotal domain reputation lookup (API v3).

The free public API allows 4 requests/minute and 500/day; the caller
(scheduler.py) is responsible for spacing requests and enforcing the daily
limit. This module only performs one lookup and classifies the verdict.

Verdict priority: malicious > dga (VT tag) > suspicious > clean. VirusTotal
does not return an explicit DGA verdict in the free API; a domain is flagged
DGA only when it carries the "dga" tag, otherwise it is treated as clean.
"""

import requests

API_URL = "https://www.virustotal.com/api/v3/domains/"
USER_AGENT = "ThreatIntelligence-TDL-Worker/1.0"


class QuotaError(Exception):
    """Raised on 429/403 so the caller can stop the batch (quota exhausted)."""


def _int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def classify(attributes: dict) -> dict:
    """Build the stored result dict from a VT `data.attributes` object."""
    stats = attributes.get("last_analysis_stats") or {}
    malicious = _int(stats.get("malicious"))
    suspicious = _int(stats.get("suspicious"))
    harmless = _int(stats.get("harmless"))
    undetected = _int(stats.get("undetected"))

    tags = [str(t).strip().lower() for t in (attributes.get("tags") or []) if str(t).strip()]

    if malicious > 0:
        verdict = "malicious"
    elif "dga" in tags:
        verdict = "dga"
    elif suspicious > 0:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "reputation": _int(attributes.get("reputation")),
        "tags": ",".join(tags[:20]),
        "last_analysis_date": attributes.get("last_analysis_date"),
    }


def lookup_domain(domain: str, api_key: str, timeout: int = 20) -> dict:
    """Look up one domain. Returns a result dict.

    Raises QuotaError on 429/403 so the caller can stop the batch. Other errors
    are returned as `status="error"` (the domain is still counted against quota).
    """
    domain = (domain or "").strip().lower()
    result = {"domain": domain, "status": "error", "verdict": None}

    if not domain:
        result["error"] = "empty domain"
        return result
    if not api_key:
        result["error"] = "missing VirusTotal API key"
        return result

    try:
        r = requests.get(
            API_URL + domain,
            headers={"x-apikey": api_key, "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as e:
        result["error"] = str(e)[:200]
        return result

    if r.status_code in (429, 403):
        raise QuotaError(f"HTTP {r.status_code}")
    if r.status_code == 404:
        # VT has no record for the domain: treat as benign/harmless.
        result.update({"status": "not_found", "verdict": "clean",
                       "malicious": 0, "suspicious": 0, "harmless": 0,
                       "undetected": 0, "reputation": 0, "tags": "",
                       "last_analysis_date": None})
        return result
    if r.status_code != 200:
        result["error"] = f"HTTP {r.status_code}"
        return result

    try:
        attributes = (r.json().get("data") or {}).get("attributes") or {}
    except ValueError:
        result["error"] = "invalid JSON response"
        return result

    result.update(classify(attributes))
    result["status"] = "ok"
    return result
