#!/usr/bin/env python3
"""AlienVault OTX domain reputation lookup (DirectConnect API v1).

OTX is a community threat-intelligence exchange: a "pulse" is a threat report
that groups indicators (domains, IPs, URLs, hashes) related to a campaign,
malware family or adversary. A domain that appears in N pulses is referenced by
N threat reports. OTX does not scan the domain; the verdict is derived from the
pulse count, and domains explicitly whitelisted by OTX are treated as clean.

This module performs a single lookup against the `general` section (one request
per domain) and classifies the result. The caller (scheduler.py) spaces requests
and enforces the daily limit.

Verdict:
  whitelisted  -> clean
  0 pulses     -> clean (no OTX data)
  >= suspicious_pulses -> suspicious
  >= malicious_pulses  -> malicious
"""

import requests

API_URL = "https://otx.alienvault.com/api/v1/indicators/domain/"
USER_AGENT = "ThreatIntelligence-TDL-Worker/1.0"


class QuotaError(Exception):
    """Raised on 429/403 so the caller can stop the batch (quota exhausted)."""


def _int(value) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _unique(values, limit: int = 20):
    """Ordered unique, non-empty, capped list of strings."""
    out = []
    for v in values or []:
        s = str(v).strip()
        if s and s not in out:
            out.append(s)
        if len(out) >= limit:
            break
    return out


def classify(data: dict, suspicious_pulses: int = 1, malicious_pulses: int = 3) -> dict:
    """Build the stored result dict from an OTX `general` response."""
    pulse_info = data.get("pulse_info") or {}
    pulse_count = _int(pulse_info.get("count"))
    references = pulse_info.get("references") or []
    pulses = pulse_info.get("pulses") or []

    # OTX "whitelist" validation entries mark well-known / trusted domains.
    whitelisted = False
    for v in (data.get("validation") or []):
        if isinstance(v, dict) and str(v.get("source", "")).strip().lower() == "whitelist":
            whitelisted = True
            break

    adversaries = []
    families = []
    tags = []
    last_mod = None
    for p in pulses:
        if not isinstance(p, dict):
            continue
        adv = str(p.get("adversary") or "").strip()
        if adv:
            adversaries.append(adv)
        for mf in (p.get("malware_families") or []):
            if isinstance(mf, dict):
                name = str(mf.get("display_name") or "").strip()
                if name:
                    families.append(name)
            else:
                name = str(mf).strip()
                if name:
                    families.append(name)
        for t in (p.get("tags") or []):
            t = str(t).strip()
            if t:
                tags.append(t)
        mod = p.get("modified")
        if mod and (last_mod is None or str(mod) > str(last_mod)):
            last_mod = str(mod)

    # Aggregate adversaries/malware families OTX relates to the indicator.
    related = pulse_info.get("related") or {}
    for key in ("alienvault", "other"):
        rel = related.get(key) or {}
        for adv in (rel.get("adversary") or []):
            adv = str(adv).strip()
            if adv:
                adversaries.append(adv)
        for fam in (rel.get("malware_families") or []):
            fam = str(fam).strip()
            if fam:
                families.append(fam)

    if whitelisted or pulse_count <= 0:
        verdict = "clean"
    elif pulse_count >= malicious_pulses:
        verdict = "malicious"
    elif pulse_count >= suspicious_pulses:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "pulse_count": pulse_count,
        "references_count": len([r for r in references if str(r).strip()]),
        "whitelisted": 1 if whitelisted else 0,
        "adversary": ",".join(_unique(adversaries))[:255],
        "malware_families": ",".join(_unique(families))[:255],
        "tags": ",".join(_unique(tags))[:255],
        "last_analysis_date": last_mod,
    }


def lookup_domain(domain: str, api_key: str, timeout: int = 20,
                  suspicious_pulses: int = 1, malicious_pulses: int = 3) -> dict:
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
        result["error"] = "missing AlienVault OTX API key"
        return result

    try:
        r = requests.get(
            API_URL + domain + "/general",
            headers={"X-OTX-API-KEY": api_key, "User-Agent": USER_AGENT},
            timeout=timeout,
        )
    except requests.RequestException as e:
        result["error"] = str(e)[:200]
        return result

    if r.status_code in (429, 403):
        raise QuotaError(f"HTTP {r.status_code}")
    if r.status_code == 404:
        result.update({"status": "not_found", "verdict": "clean", "pulse_count": 0,
                       "references_count": 0, "whitelisted": 0, "adversary": "",
                       "malware_families": "", "tags": "", "last_analysis_date": None})
        return result
    if r.status_code != 200:
        result["error"] = f"HTTP {r.status_code}"
        return result

    try:
        data = r.json()
    except ValueError:
        result["error"] = "invalid JSON response"
        return result
    if not isinstance(data, dict):
        result["error"] = "unexpected response"
        return result

    result.update(classify(data, suspicious_pulses, malicious_pulses))
    result["status"] = "ok"
    return result
