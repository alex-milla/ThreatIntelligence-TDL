#!/usr/bin/env python3
"""abuse.ch domain validation (URLhaus + ThreatFox Community APIs).

abuse.ch is a non-profit that runs several free threat-intelligence services:

  * URLhaus     - malware distribution sites (URLs that serve a payload).
  * ThreatFox   - confirmed IOCs (botnet C2, payload delivery, ...) with a
                  malware family, threat type and confidence level.

Both use a single free Auth-Key (https://auth.abuse.ch/). For a domain this
module issues one URLhaus `host` lookup and one ThreatFox `search_ioc` lookup,
then derives a verdict:

  URLhaus host found:
    - Spamhaus DBL says phishing/botnet/abused malware, or the host is currently
      serving a payload (online)            -> malicious
    - Spamhaus DBL says spammer/abused spam/abused redirector, or the host only
      has offline/not-listed malware URLs   -> suspicious
  ThreatFox has a confirmed domain IOC       -> malicious
  Nothing on either service                  -> clean (not found)

The caller (scheduler.py) spaces requests and enforces the daily limit. Each
domain counts as one unit against the limit (it may be two HTTP requests).
"""

import requests

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
USER_AGENT = "ThreatIntelligence-TDL-Worker/1.0"

# Spamhaus DBL classifications returned by URLhaus for a host.
DBL_MALICIOUS = {
    "phishing_domain",
    "botnet_cc_domain",
    "abused_legit_phishing",
    "abused_legit_botnetcc",
    "abused_legit_malware",
}
DBL_SUSPICIOUS = {
    "spammer_domain",
    "abused_legit_spam",
    "abused_redirector",
}

THREATFOX_MALICIOUS_TYPES = {"botnet_cc", "payload_delivery", "cc_skimming"}


class QuotaError(Exception):
    """Raised on 401/403/429 so the caller can stop the batch (quota/key issue)."""


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


def _max_date(a, b):
    """Newest of two ISO-ish date strings (lexicographic order works here)."""
    a = str(a).strip() if a else None
    b = str(b).strip() if b else None
    if not a:
        return b
    if not b:
        return a
    return a if a >= b else b


def urlhaus_verdict(data: dict) -> dict:
    """Classification from a URLhaus `host` response."""
    status = str(data.get("query_status") or "").strip().lower()
    out = {
        "urlhaus_verdict": "clean",
        "urlhaus_url_count": 0,
        "urlhaus_online": 0,
        "urlhaus_dbl": "",
        "urlhaus_first_seen": None,
        "urlhaus_tags": "",
    }
    if status in ("no_results", "invalid_host", "http_post_expected", ""):
        return out

    out["urlhaus_url_count"] = _int(data.get("url_count"))
    out["urlhaus_first_seen"] = (str(data.get("firstseen")).strip() or None) if data.get("firstseen") else None

    blacklists = data.get("blacklists") or {}
    dbl = str(blacklists.get("spamhaus_dbl") or "").strip().lower()
    out["urlhaus_dbl"] = dbl

    tags = []
    online = 0
    for u in (data.get("urls") or []):
        if not isinstance(u, dict):
            continue
        if str(u.get("url_status") or "").strip().lower() == "online":
            online += 1
        for t in (u.get("tags") or []):
            t = str(t).strip()
            if t:
                tags.append(t)
    out["urlhaus_online"] = online
    out["urlhaus_tags"] = ",".join(_unique(tags))[:255]

    if dbl in DBL_MALICIOUS or online > 0:
        out["urlhaus_verdict"] = "malicious"
    elif dbl in DBL_SUSPICIOUS or out["urlhaus_url_count"] > 0:
        out["urlhaus_verdict"] = "suspicious"
    else:
        out["urlhaus_verdict"] = "clean"
    return out


def threatfox_verdict(data: dict) -> dict:
    """Classification from a ThreatFox `search_ioc` response."""
    status = str(data.get("query_status") or "").strip().lower()
    out = {
        "threatfox_verdict": "clean",
        "threatfox_matches": 0,
        "threat_type": "",
        "malware_family": "",
        "confidence": 0,
        "threatfox_last_seen": None,
        "threatfox_tags": "",
    }
    rows = data.get("data")
    if status != "ok" or not isinstance(rows, list) or not rows:
        return out

    threat_types = []
    families = []
    tags = []
    confidence = 0
    last_seen = None
    malware = False
    for row in rows:
        if not isinstance(row, dict):
            continue
        tt = str(row.get("threat_type") or "").strip().lower()
        if tt:
            threat_types.append(tt)
            if tt in THREATFOX_MALICIOUS_TYPES:
                malware = True
        fam = str(row.get("malware_printable") or row.get("malware") or "").strip()
        if fam:
            families.append(fam)
        for t in (row.get("tags") or []):
            t = str(t).strip()
            if t:
                tags.append(t)
        confidence = max(confidence, _int(row.get("confidence_level")))
        last_seen = _max_date(last_seen, row.get("last_seen") or row.get("first_seen"))

    out["threatfox_matches"] = len([r for r in rows if isinstance(r, dict)])
    out["threat_type"] = ",".join(_unique(threat_types))[:255]
    out["malware_family"] = ",".join(_unique(families))[:255]
    out["confidence"] = confidence
    out["threatfox_last_seen"] = last_seen
    out["threatfox_tags"] = ",".join(_unique(tags))[:255]
    # ThreatFox only accepts confirmed/vetted IOCs, so any match is malicious.
    out["threatfox_verdict"] = "malicious" if malware or out["threatfox_matches"] > 0 else "clean"
    return out


def classify(urlhaus: dict, threatfox: dict) -> dict:
    """Combine the two source classifications into the stored result dict."""
    u = urlhaus_verdict(urlhaus or {})
    t = threatfox_verdict(threatfox or {})

    if "malicious" in (u["urlhaus_verdict"], t["threatfox_verdict"]):
        verdict = "malicious"
    elif "suspicious" in (u["urlhaus_verdict"], t["threatfox_verdict"]):
        verdict = "suspicious"
    else:
        verdict = "clean"

    tags = _unique(
        [x for x in (u["urlhaus_tags"] + "," + t["threatfox_tags"]).split(",") if x.strip()]
    )
    last = _max_date(u["urlhaus_first_seen"], t["threatfox_last_seen"])

    return {
        "verdict": verdict,
        "urlhaus_verdict": u["urlhaus_verdict"],
        "urlhaus_url_count": u["urlhaus_url_count"],
        "urlhaus_online": u["urlhaus_online"],
        "urlhaus_dbl": u["urlhaus_dbl"],
        "threatfox_verdict": t["threatfox_verdict"],
        "threatfox_matches": t["threatfox_matches"],
        "threat_type": t["threat_type"],
        "malware_family": t["malware_family"],
        "confidence": t["confidence"],
        "tags": ",".join(tags)[:255],
        "last_analysis_date": last,
    }


def _empty_result(domain: str) -> dict:
    return {
        "domain": domain, "status": "error", "verdict": None,
        "urlhaus_verdict": None, "urlhaus_url_count": 0, "urlhaus_online": 0,
        "urlhaus_dbl": "", "threatfox_verdict": None, "threatfox_matches": 0,
        "threat_type": "", "malware_family": "", "confidence": 0, "tags": "",
        "last_analysis_date": None,
    }


def lookup_domain(domain: str, api_key: str, timeout: int = 20,
                  urlhaus_enabled: bool = True, threatfox_enabled: bool = True) -> dict:
    """Validate one domain against URLhaus and ThreatFox.

    Raises QuotaError on 401/403/429 so the caller can stop the batch. Other
    errors are returned as `status="error"` (the domain still counts against the
    daily limit).
    """
    domain = (domain or "").strip().lower()
    result = _empty_result(domain)

    if not domain:
        result["error"] = "empty domain"
        return result
    if not api_key:
        result["error"] = "missing abuse.ch Auth-Key"
        return result
    if not urlhaus_enabled and not threatfox_enabled:
        result["error"] = "no abuse.ch source enabled"
        return result

    headers = {"Auth-Key": api_key, "User-Agent": USER_AGENT}

    if urlhaus_enabled:
        try:
            r = requests.post(URLHAUS_URL, data={"host": domain}, headers=headers, timeout=timeout)
        except requests.RequestException as e:
            result["error"] = ("urlhaus: " + str(e))[:200]
            return result
        if r.status_code in (401, 403, 429):
            raise QuotaError(f"urlhaus HTTP {r.status_code}")
        if r.status_code != 200:
            result["error"] = f"urlhaus HTTP {r.status_code}"
            return result
        try:
            u_data = r.json()
        except ValueError:
            result["error"] = "urlhaus invalid JSON response"
            return result
        if not isinstance(u_data, dict):
            result["error"] = "urlhaus unexpected response"
            return result
    else:
        u_data = {"query_status": "no_results"}

    if threatfox_enabled:
        try:
            r = requests.post(
                THREATFOX_URL,
                json={"query": "search_ioc", "search_term": domain, "exact_match": True},
                headers=headers, timeout=timeout,
            )
        except requests.RequestException as e:
            result["error"] = ("threatfox: " + str(e))[:200]
            return result
        if r.status_code in (401, 403, 429):
            raise QuotaError(f"threatfox HTTP {r.status_code}")
        if r.status_code != 200:
            result["error"] = f"threatfox HTTP {r.status_code}"
            return result
        try:
            t_data = r.json()
        except ValueError:
            result["error"] = "threatfox invalid JSON response"
            return result
        if not isinstance(t_data, dict):
            result["error"] = "threatfox unexpected response"
            return result
    else:
        t_data = {"query_status": "no_results"}

    result.update(classify(u_data, t_data))
    result["status"] = "ok"
    return result
