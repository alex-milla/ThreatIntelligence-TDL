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

import csv
import io
import ipaddress
import zipfile
from datetime import datetime, timezone
from urllib.parse import urlsplit

import requests

URLHAUS_URL = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
URLHAUS_EXPORT = "https://urlhaus-api.abuse.ch/v2/files/exports/{key}/{name}"
THREATFOX_EXPORT = "https://threatfox-api.abuse.ch/v2/files/exports/{key}/full.csv.zip"
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

# `query_status` values that mean "the query worked, no record".
URLHAUS_OK_STATUS = {"ok", "no_results", "invalid_host", "http_post_expected", ""}
THREATFOX_OK_STATUS = {"ok", "no_result", "no_results", "illegal_search_term", ""}


class QuotaError(Exception):
    """Raised on a quota/rate limit so the caller can stop the batch."""


class AuthError(Exception):
    """Raised when the abuse.ch Auth-Key is missing/invalid/unknown."""


_AUTH_HINTS = ("unknown_auth_key", "unauthorized", "invalid auth", "invalid api",
               "missing auth", "auth key")


def is_auth_failure(status_code: int, body: str) -> bool:
    """Whether an HTTP error response is an authentication problem."""
    if status_code == 401:
        return True
    text = str(body or "").lower()
    return any(h in text for h in _AUTH_HINTS)


def _raise_http_error(r, service: str) -> None:
    """Turn a 401/403/429 response into AuthError or QuotaError."""
    if r.status_code == 429:
        raise QuotaError(f"{service} HTTP 429")
    try:
        body = r.text or ""
    except Exception:
        body = ""
    if is_auth_failure(r.status_code, body):
        raise AuthError(f"{service} authentication failed (HTTP {r.status_code})")
    raise QuotaError(f"{service} HTTP {r.status_code}")


def error_result(domain: str, error: str) -> dict:
    """A result dict flagged as an error (so the UI shows it, not a stale verdict)."""
    out = _empty_result(domain)
    out["error"] = str(error or "error")[:200]
    return out



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
            _raise_http_error(r, "urlhaus")
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
        u_status = str(u_data.get("query_status") or "").strip().lower()
        if u_status not in URLHAUS_OK_STATUS:
            # Never treat an unexpected status (bad key, etc.) as "clean".
            result["error"] = f"urlhaus query_status={u_status or 'unknown'}"
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
            _raise_http_error(r, "threatfox")
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
        t_status = str(t_data.get("query_status") or "").strip().lower()
        if t_status not in THREATFOX_OK_STATUS:
            result["error"] = f"threatfox query_status={t_status or 'unknown'}"
            return result
    else:
        t_data = {"query_status": "no_results"}

    result.update(classify(u_data, t_data))
    result["status"] = "ok"
    return result


# ---------------------------------------------------------------------------
# Bulk feed (full URLhaus + ThreatFox datasets, matched locally)
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _clean_tag_list(value) -> list:
    """Split a CSV tags field ("None", "a,b") into a clean list."""
    if value is None:
        return []
    parts = []
    for raw in str(value).split(","):
        t = raw.strip()
        if not t or t.lower() in ("none", "null", "na"):
            continue
        parts.append(t)
    return _unique(parts)


def _extract_host(url: str):
    """Hostname from a URL, or None for IPs / unparseable values."""
    try:
        host = (urlsplit(str(url)).hostname or "").strip().lower()
    except Exception:
        return None
    if not host:
        return None
    try:
        ipaddress.ip_address(host)
        return None  # a raw IP is not a domain we validate
    except ValueError:
        return host


def _min_date(a, b):
    if not a:
        return b
    if not b:
        return a
    return a if a <= b else b


def parse_urlhaus_csv(text: str) -> dict:
    """Aggregate the URLhaus CSV dump by host.

    Columns: id, dateadded, url, url_status, last_online, threat, tags,
    urlhaus_link, reporter. The dump has no host column and no Spamhaus DBL
    status, so each host is aggregated (URL count, currently-online count, tags,
    first/last dates).
    """
    by_host: dict = {}
    reader = csv.reader(io.StringIO(text), skipinitialspace=True)
    for row in reader:
        if not row or len(row) < 7:
            continue
        if str(row[0]).lstrip().startswith("#"):
            continue
        host = _extract_host(row[2])
        if not host:
            continue
        entry = by_host.setdefault(host, {
            "url_count": 0, "online": 0, "tags": [], "first_seen": None, "last_seen": None,
        })
        entry["url_count"] += 1
        if str(row[3]).strip().lower() == "online":
            entry["online"] += 1
        entry["tags"].extend(_clean_tag_list(row[6]))
        entry["first_seen"] = _min_date(entry["first_seen"], str(row[1]).strip() or None)
        last_online = str(row[4]).strip()
        if last_online:
            entry["last_seen"] = _max_date(entry["last_seen"], last_online)
    return by_host


def parse_threatfox_csv(text: str) -> dict:
    """Aggregate the ThreatFox CSV dump by domain (ioc_type == "domain").

    Columns: first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type,
    fk_malware, malware_alias, malware_printable, last_seen_utc,
    confidence_level, is_compromised, reference, tags, anonymous, reporter.
    """
    by_domain: dict = {}
    reader = csv.reader(io.StringIO(text), skipinitialspace=True)
    for row in reader:
        if not row or len(row) < 10:
            continue
        if str(row[0]).lstrip().startswith("#"):
            continue
        if str(row[3]).strip().lower() != "domain":
            continue
        domain = str(row[2]).strip().lower()
        if not domain or len(domain) > 253:
            continue
        family = str(row[7]).strip() if len(row) > 7 else ""
        if not family or family.lower() in ("none", "null"):
            family = str(row[5]).strip() if len(row) > 5 and str(row[5]).lower() not in ("none", "null") else ""
        entry = by_domain.setdefault(domain, {
            "threat_type": "", "malware": "", "confidence": 0, "tags": [],
            "first_seen": None, "last_seen": None,
        })
        tt = str(row[4]).strip()
        if tt:
            entry["threat_type"] = tt
        if family:
            entry["malware"] = family
        entry["confidence"] = max(entry["confidence"], _int(row[9]) if len(row) > 9 else 0)
        entry["tags"].extend(_clean_tag_list(row[12]) if len(row) > 12 else [])
        entry["first_seen"] = _min_date(entry["first_seen"], str(row[0]).strip() or None)
        last_seen = str(row[8]).strip() if len(row) > 8 else ""
        if last_seen:
            entry["last_seen"] = _max_date(entry["last_seen"], last_seen)
    return by_domain


def parse_threatfox_zip(content: bytes) -> dict:
    """Parse the ThreatFox `full.csv.zip` export from its raw bytes."""
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        names = [n for n in z.namelist() if n.lower().endswith(".csv")]
        if not names:
            return {}
        with z.open(names[0]) as f:
            text = f.read().decode("utf-8", "replace")
    return parse_threatfox_csv(text)


def _replace_feed_source(db, source: str, rows: list) -> int:
    """Swap all rows for one feed source inside the caller's transaction."""
    db.execute("DELETE FROM abusech_feed WHERE source = ?", (source,))
    if rows:
        db.executemany(
            "INSERT OR REPLACE INTO abusech_feed "
            "(domain, source, threat_type, malware, confidence, tags, first_seen, last_seen, "
            " url_count, online, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            rows,
        )
    return len(rows)


def feed_age_hours(db):
    """Hours since the last successful feed sync, or None if never synced."""
    try:
        row = db.execute("SELECT value FROM abusech_feed_meta WHERE key = 'synced_at'").fetchone()
    except Exception:
        return None
    if not row or not row[0]:
        return None
    try:
        ts = datetime.strptime(str(row[0]), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return (datetime.now(timezone.utc) - ts).total_seconds() / 3600.0


def sync_feed(db, cfg, auth_key: str, timeout: int = 120) -> int:
    """Download the URLhaus + ThreatFox full datasets into the local feed table.

    Best effort: a failing source leaves the previous rows in place. Returns the
    number of rows stored (0 if both sources failed).
    """
    if not auth_key:
        return 0
    headers = {"Auth-Key": auth_key, "User-Agent": USER_AGENT}
    now = _now_utc()
    stored = 0
    ok_sources = 0

    dump = "recent.csv"
    try:
        dump = cfg.get("abusech", "feed_urlhaus_dump", fallback="recent.csv").strip() or "recent.csv"
    except Exception:
        pass

    try:
        r = requests.get(URLHAUS_EXPORT.format(key=auth_key, name=dump), headers=headers, timeout=timeout)
        if r.status_code == 200:
            hosts = parse_urlhaus_csv(r.text)
            rows = [(
                host, "urlhaus", "malware_download", "", 0,
                ",".join(_unique(e["tags"]))[:255],
                e["first_seen"], e["last_seen"], e["url_count"], e["online"], now,
            ) for host, e in hosts.items()]
            stored += _replace_feed_source(db, "urlhaus", rows)
            ok_sources += 1
    except requests.RequestException:
        pass

    try:
        r = requests.get(THREATFOX_EXPORT.format(key=auth_key), headers=headers, timeout=timeout)
        if r.status_code == 200:
            domains = parse_threatfox_zip(r.content)
            rows = [(
                domain, "threatfox", e["threat_type"], e["malware"], e["confidence"],
                ",".join(_unique(e["tags"]))[:255],
                e["first_seen"], e["last_seen"], 0, 0, now,
            ) for domain, e in domains.items()]
            stored += _replace_feed_source(db, "threatfox", rows)
            ok_sources += 1
    except (requests.RequestException, zipfile.BadZipFile):
        pass

    if ok_sources:
        db.execute("INSERT OR REPLACE INTO abusech_feed_meta (key, value) VALUES ('synced_at', ?)", (now,))
        db.commit()
    return stored


def _feed_entry(domain: str, u: dict | None, t: dict | None) -> dict:
    """Build a stored result dict from the two per-domain feed rows."""
    if u:
        if u["online"] > 0:
            url_v = "malicious"
        elif u["url_count"] > 0:
            url_v = "suspicious"
        else:
            url_v = "clean"
    else:
        url_v = "clean"

    if t:
        tf_v = "malicious"
    else:
        tf_v = "clean"

    if "malicious" in (url_v, tf_v):
        verdict = "malicious"
    elif "suspicious" in (url_v, tf_v):
        verdict = "suspicious"
    else:
        verdict = "clean"

    tags = []
    if u:
        tags += str(u["tags"] or "").split(",")
    if t:
        tags += str(t["tags"] or "").split(",")
    tags = _unique([x.strip() for x in tags if x.strip()])

    return {
        "domain": domain,
        "verdict": verdict,
        "urlhaus_verdict": url_v,
        "urlhaus_url_count": u["url_count"] if u else 0,
        "urlhaus_online": u["online"] if u else 0,
        "urlhaus_dbl": "",  # the CSV dump has no Spamhaus DBL status
        "threatfox_verdict": tf_v,
        "threatfox_matches": 1 if t else 0,
        "threat_type": (t["threat_type"] if t else ""),
        "malware_family": (t["malware"] if t else ""),
        "confidence": (t["confidence"] if t else 0),
        "tags": ",".join(tags)[:255],
        "last_analysis_date": _max_date(u["first_seen"] if u else None, t["last_seen"] if t else None),
    }


def feed_lookup(db, domains: list, chunk: int = 500) -> list:
    """Match domains against the local abuse.ch feed; returns result entries."""
    clean = []
    seen = set()
    for d in domains or []:
        d = str(d).lower().strip()
        if d and d not in seen:
            seen.add(d)
            clean.append(d)
    if not clean:
        return []

    found: dict = {}
    for i in range(0, len(clean), chunk):
        part = clean[i:i + chunk]
        placeholders = ",".join("?" * len(part))
        rows = db.execute(
            "SELECT domain, source, threat_type, malware, confidence, tags, "
            "first_seen, last_seen, url_count, online FROM abusech_feed "
            f"WHERE domain IN ({placeholders})", part,
        ).fetchall()
        for r in rows:
            d = r[0]
            entry = found.setdefault(d, {"u": None, "t": None})
            if r[1] == "urlhaus":
                entry["u"] = {"url_count": r[8] or 0, "online": r[9] or 0,
                              "tags": r[5] or "", "first_seen": r[6]}
            elif r[1] == "threatfox":
                entry["t"] = {"threat_type": r[2] or "", "malware": r[3] or "",
                              "confidence": r[4] or 0, "tags": r[5] or "",
                              "last_seen": r[7]}

    return [_feed_entry(d, e["u"], e["t"]) for d, e in found.items()]


