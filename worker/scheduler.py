#!/usr/bin/env python3
"""Main orchestrator: download zones, parse, deduplicate, match keywords, sync to hosting.
Supports daemon mode with command polling from the web panel."""

import argparse
import configparser
import hashlib
import json
import logging
import os
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta

try:
    from zoneinfo import ZoneInfo
except ImportError:  # Python < 3.9
    ZoneInfo = None

try:
    import fcntl
except ImportError:  # pragma: no cover - planned for Linux workers only
    fcntl = None

import downloader
import logger
import parser
import matcher
import sync_client
import virustotal
import abusech
import cloudflare_radar
import intel
import whois

log = logging.getLogger("tdl_worker")


def init_local_db(db_path: str, cache_mb: int = 2048) -> sqlite3.Connection:
    """Create local worker SQLite database if not exists.

    cache_mb sets SQLite's page cache (PRAGMA cache_size, in KiB when negative).
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute(f"PRAGMA cache_size=-{max(int(cache_mb), 1) * 1024}")
    conn.execute("PRAGMA mmap_size=268435456")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS domains_cache (
            domain TEXT PRIMARY KEY,
            tld TEXT NOT NULL,
            first_seen TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_cache_tld ON domains_cache(tld);

        CREATE TABLE IF NOT EXISTS zone_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tld TEXT NOT NULL,
            run_date TEXT NOT NULL,
            records_total INTEGER DEFAULT 0,
            records_new INTEGER DEFAULT 0,
            status TEXT DEFAULT 'pending'
        );

        CREATE TABLE IF NOT EXISTS sync_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            retry_count INTEGER DEFAULT 0,
            next_retry TEXT NOT NULL,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS config (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        CREATE TABLE IF NOT EXISTS sync_dead_letter (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            retry_count INTEGER DEFAULT 0,
            error_reason TEXT,
            created_at TEXT NOT NULL,
            failed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS tld_meta (
            tld TEXT PRIMARY KEY,
            etag TEXT,
            last_modified TEXT,
            last_run_date TEXT,
            last_run_status TEXT
        );

        CREATE TABLE IF NOT EXISTS domains_cache_hash (
            domain_hash INTEGER PRIMARY KEY,
            tld TEXT NOT NULL,
            first_seen INTEGER NOT NULL
        ) WITHOUT ROWID;
        -- No index on tld: recheck excludes hash-cached TLDs, so it would only
        -- add time and disk on 100M+ row tables.

        CREATE TABLE IF NOT EXISTS tld_retry_queue (
            tld TEXT PRIMARY KEY,
            attempts INTEGER DEFAULT 0,
            next_retry TEXT,
            last_error TEXT,
            updated_at TEXT
        );

        CREATE TABLE IF NOT EXISTS vt_usage (
            day TEXT PRIMARY KEY,
            count INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS abusech_usage (
            day TEXT PRIMARY KEY,
            count INTEGER DEFAULT 0
        );

        -- Local abuse.ch blacklist (URLhaus + ThreatFox full dumps), matched
        -- against freshly detected domains after each TLD sync.
        CREATE TABLE IF NOT EXISTS abusech_feed (
            domain TEXT NOT NULL,
            source TEXT NOT NULL,
            threat_type TEXT,
            malware TEXT,
            confidence INTEGER DEFAULT 0,
            tags TEXT,
            first_seen TEXT,
            last_seen TEXT,
            url_count INTEGER DEFAULT 0,
            online INTEGER DEFAULT 0,
            updated_at TEXT,
            PRIMARY KEY (domain, source)
        );
        CREATE TABLE IF NOT EXISTS abusech_feed_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        -- Intelligence tracking pass guard (last run timestamp).
        CREATE TABLE IF NOT EXISTS tracking_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        );

        -- Cloudflare URL Scanner usage counters (period = day:YYYY-MM-DD or
        -- month:YYYY-MM), to respect the plan quota (Free: 5,000/month).
        CREATE TABLE IF NOT EXISTS cf_usage (
            period TEXT PRIMARY KEY,
            count INTEGER DEFAULT 0
        );
    """)
    # Migration: drop the unused tld index on the hash cache (older versions).
    try:
        conn.execute("DROP INDEX IF EXISTS idx_cache_hash_tld")
    except sqlite3.OperationalError:
        pass

    # Migration: per-TLD baseline state. A TLD is not emitted until its first
    # successful scan has populated the cache; from then on only delegations
    # added since the previous validation produce matches. cache_mode records
    # whether the TLD was cached as text or as hashes, so a mode switch does not
    # anti-join against an empty table and re-flood old domains.
    try:
        conn.execute("ALTER TABLE tld_meta ADD COLUMN baselined INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        pass
    try:
        conn.execute("ALTER TABLE tld_meta ADD COLUMN cache_mode TEXT")
    except sqlite3.OperationalError:
        pass
    # TLDs already processed successfully were baselined by an earlier version.
    try:
        conn.execute("UPDATE tld_meta SET baselined = 1 WHERE baselined = 0 AND last_run_status = 'ok'")
    except sqlite3.OperationalError:
        pass

    conn.commit()
    return conn


def _domain_hash(domain: str) -> int:
    """Stable 64-bit hash of a domain, used by the compact cache for huge TLDs."""
    digest = hashlib.blake2b(domain.encode("utf-8"), digest_size=8).digest()
    return int.from_bytes(digest, "big", signed=True)


def _parse_tld_map(value: str) -> dict:
    """Parse ``tld=value, tld2=value2`` (WHOIS/RDAP overrides) into a dict."""
    out: dict = {}
    for item in (value or "").split(","):
        item = item.strip()
        if "=" not in item:
            continue
        key, val = item.split("=", 1)
        key = key.strip().lower().lstrip(".")
        val = val.strip()
        if key and val:
            out[key] = val
    return out


def _parse_tld_set(value: str) -> set:
    """Parse ``es, de`` (restricted TLDs) into a set of lowercased TLD names."""
    return {t.strip().lower().lstrip(".") for t in (value or "").split(",") if t.strip()}


def whois_lookup_entries(cfg: configparser.ConfigParser, data_dir: str,
                         domains: list[str]) -> list[dict]:
    """Look up WHOIS/RDAP for ``domains`` using the ``[whois]`` settings.

    Shared by the on-demand ``whois_lookup`` command and the automatic lookup
    performed after a download. Returns a list of result dicts (never raises).
    """
    timeout, connect_timeout, rdap_only, whois_fallback, rate_delay = 20, 6, False, True, 1.0
    rdap_overrides: dict = {}
    whois_overrides: dict = {}
    disabled_tlds = None
    if cfg.has_section("whois"):
        timeout = cfg.getint("whois", "timeout", fallback=20)
        connect_timeout = cfg.getint("whois", "connect_timeout", fallback=6)
        rdap_only = cfg.getboolean("whois", "rdap_only", fallback=False)
        whois_fallback = cfg.getboolean("whois", "whois_fallback", fallback=True)
        rate_delay = cfg.getfloat("whois", "rate_delay", fallback=1.0)
        rdap_overrides = _parse_tld_map(cfg.get("whois", "rdap_overrides", fallback=""))
        whois_overrides = _parse_tld_map(cfg.get("whois", "whois_overrides", fallback=""))
        if cfg.has_option("whois", "disabled_tlds"):
            disabled_tlds = _parse_tld_set(cfg.get("whois", "disabled_tlds", fallback=""))
    entries = []
    for d in domains:
        entries.append(whois.lookup_domain(d, data_dir, timeout=timeout,
                                           rdap_only=rdap_only,
                                           whois_fallback=whois_fallback,
                                           connect_timeout=connect_timeout,
                                           overrides=rdap_overrides,
                                           whois_overrides=whois_overrides,
                                           disabled_tlds=disabled_tlds))
        if rate_delay > 0:
            time.sleep(rate_delay)
    return entries


def auto_whois_new_matches(cfg: configparser.ConfigParser, host_url: str, api_key: str,
                           matches: list[dict]) -> int:
    """Cache WHOIS/RDAP for freshly matched domains right after a download.

    Enabled by default (``[worker] auto_whois``) and capped by
    ``[worker] auto_whois_max``. Only new (non-historical) matches are considered,
    so rechecks never trigger it. Best effort: never raises, so a registry
    problem cannot abort the worker cycle. Returns the number of lookups sent.
    """
    if not matches or not cfg.getboolean("worker", "auto_whois", fallback=True):
        return 0
    max_lookups = max(0, cfg.getint("worker", "auto_whois_max", fallback=200))
    if max_lookups == 0:
        return 0

    domains: list[str] = []
    seen: set = set()
    for m in matches:
        if m.get("is_historical"):
            continue
        d = str(m.get("domain", "")).lower().strip()
        if not d or d in seen:
            continue
        seen.add(d)
        domains.append(d)
    domains = domains[:max_lookups]
    if not domains:
        return 0

    data_dir = cfg.get("worker", "data_dir", fallback="./data")
    try:
        entries = whois_lookup_entries(cfg, data_dir, domains)
        ok = sync_client.send_whois_results(host_url, api_key, entries)
        log.info("Auto-WHOIS after download: %s domain(s), sent=%s", len(entries), ok)
        return len(entries)
    except Exception as e:  # never abort the cycle for an enrichment failure
        log.warning("Auto-WHOIS failed: %s", e)
        return 0


def auto_abusech_new_matches(cfg: configparser.ConfigParser, db: sqlite3.Connection,
                             host_url: str, api_key: str, matches: list[dict]) -> int:
    """Validate freshly matched domains against the local abuse.ch feed.

    Runs after the TLD sync: refreshes the local URLhaus/ThreatFox dump when it
    is older than ``feed_sync_hours`` and then matches the new (non-historical)
    domains against it, sending only the malicious/suspicious hits (a feed "not
    found" must never overwrite a richer on-demand result). Best effort: never
    raises, so a feed problem cannot abort the worker cycle. Returns the number
    of hits sent.
    """
    if not cfg.has_section("abusech") or not cfg.getboolean("abusech", "feed_enabled", fallback=True):
        return 0
    auth_key = cfg.get("abusech", "auth_key", fallback="").strip()
    if not auth_key or auth_key.upper().startswith("TU_"):
        return 0

    sync_hours = cfg.getfloat("abusech", "feed_sync_hours", fallback=24)
    try:
        age = abusech.feed_age_hours(db)
        if age is None or sync_hours <= 0 or age >= sync_hours:
            stored = abusech.sync_feed(db, cfg, auth_key,
                                       timeout=cfg.getint("abusech", "feed_timeout", fallback=120))
            log.info("abuse.ch feed refreshed: %s row(s)", stored)
    except Exception as e:  # never abort the cycle for a feed failure
        log.warning("abuse.ch feed sync failed: %s", e)

    max_lookups = max(0, cfg.getint("abusech", "auto_abusech_max", fallback=200))
    if not matches or max_lookups == 0:
        return 0

    domains: list[str] = []
    seen: set = set()
    for m in matches:
        if m.get("is_historical"):
            continue
        d = str(m.get("domain", "")).lower().strip()
        if not d or d in seen:
            continue
        seen.add(d)
        domains.append(d)
        if len(domains) >= max_lookups:
            break
    if not domains:
        return 0

    try:
        hits = [e for e in abusech.feed_lookup(db, domains)
                if e.get("verdict") in ("malicious", "suspicious")]
        if hits and sync_client.send_abusech_results(host_url, api_key, hits):
            log.info("abuse.ch feed validation: %s hit(s) out of %s domain(s)", len(hits), len(domains))
        return len(hits)
    except Exception as e:  # never abort the cycle
        log.warning("abuse.ch feed lookup failed: %s", e)
        return 0


def _cf_raw(cfg: configparser.ConfigParser, key: str, default: str = "") -> str:
    """Read a [cloudflare] value, ignoring anything after an inline comment."""
    value = cfg.get("cloudflare", key, fallback=default)
    for sep in (";", "#"):
        if sep in value:
            value = value.split(sep, 1)[0]
    return value.strip()


def _cf_int(cfg: configparser.ConfigParser, key: str, default: int) -> int:
    try:
        return int(float(_cf_raw(cfg, key, str(default))))
    except (TypeError, ValueError):
        return default


def _cf_float(cfg: configparser.ConfigParser, key: str, default: float) -> float:
    try:
        return float(_cf_raw(cfg, key, str(default)))
    except (TypeError, ValueError):
        return default


def _cf_bool(cfg: configparser.ConfigParser, key: str, default: bool) -> bool:
    raw = _cf_raw(cfg, key, "1" if default else "0").lower()
    return raw in ("1", "true", "yes", "on")


def _cf_config(cfg: configparser.ConfigParser) -> dict:
    """Read the optional [cloudflare] Radar/URL Scanner settings."""
    if not cfg.has_section("cloudflare"):
        return {}
    api_token = _cf_raw(cfg, "api_token")
    scanner_token = _cf_raw(cfg, "urlscanner_token")
    # A single token with both permissions is valid: fall back to the other one.
    scanner_token = scanner_token or api_token
    api_token = api_token or scanner_token
    return {
        "enabled": _cf_bool(cfg, "radar_enabled", True),
        "api_token": api_token,
        "urlscanner_token": scanner_token,
        "account_id": _cf_raw(cfg, "account_id"),
        "visibility": _cf_raw(cfg, "visibility", "public"),
        "rate_delay": _cf_float(cfg, "rate_delay_seconds", 10.0),
        "daily_limit": _cf_int(cfg, "daily_limit", 150),
        "monthly_limit": _cf_int(cfg, "monthly_limit", 5000),
        "timeout": _cf_int(cfg, "timeout", 30),
        "poll_interval": _cf_int(cfg, "poll_interval", 15),
        "poll_max_wait": _cf_int(cfg, "poll_max_wait", 180),
        "dns_locations": _cf_bool(cfg, "dns_locations_enabled", True),
        "dns_limit": _cf_int(cfg, "dns_locations_limit", 10),
        "dns_rate_delay": _cf_float(cfg, "dns_rate_delay_seconds", 1.0),
        "cache_days": _cf_int(cfg, "cache_days", 7),
        "auto_scan": _cf_bool(cfg, "auto_scan", False),
        "auto_scan_max": _cf_int(cfg, "auto_scan_max", 50),
    }


def _cf_periods() -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    return now.strftime("day:%Y-%m-%d"), now.strftime("month:%Y-%m")


def run_cfscan_batch(cfg: configparser.ConfigParser, db: sqlite3.Connection,
                     host_url: str, api_key: str, domains: list[str]) -> dict:
    """Scan ``domains`` with the Cloudflare URL Scanner (+ Radar DNS locations).

    Sequential and rate limited (the Free plan allows one scan every 10 s). Each
    result is sent to the hosting as soon as it is ready. Best effort per domain;
    an auth failure or a quota hit stops the batch. Returns stats.
    """
    stats = {"requested": len(domains), "scanned": 0, "errors": 0, "error": None}
    cf = _cf_config(cfg)
    if not cf.get("enabled") or not cf.get("urlscanner_token") or not cf.get("account_id"):
        stats["error"] = "Cloudflare URL Scanner not configured ([cloudflare] urlscanner_token/account_id)."
        return stats

    day_key, month_key = _cf_periods()
    daily_limit = cf["daily_limit"] or 0
    monthly_limit = cf["monthly_limit"] or 0

    for domain in domains:
        if daily_limit and cloudflare_radar.usage_count(db, day_key) >= daily_limit:
            stats["error"] = f"Cloudflare daily scan limit reached ({daily_limit})."
            break
        if monthly_limit and cloudflare_radar.usage_count(db, month_key) >= monthly_limit:
            stats["error"] = f"Cloudflare monthly scan limit reached ({monthly_limit})."
            break
        try:
            scan = cloudflare_radar.scan_domain(
                domain, cf["urlscanner_token"], cf["account_id"],
                visibility=cf["visibility"], timeout=cf["timeout"])
            report = cloudflare_radar.fetch_result(
                cf["urlscanner_token"], cf["account_id"], scan.get("uuid", ""),
                timeout=cf["timeout"], poll_interval=cf["poll_interval"],
                max_wait=cf["poll_max_wait"])
            entry = cloudflare_radar.classify(report, domain, scan.get("report_url", ""))
            sync_client.send_cfscan_results(host_url, api_key, [entry])
            cloudflare_radar.usage_add(db, day_key)
            cloudflare_radar.usage_add(db, month_key)
            stats["scanned"] += 1
            log.info("Cloudflare scan: %s -> %s", domain, entry.get("verdict") or entry.get("status"))
        except cloudflare_radar.AuthError as e:
            sync_client.send_cfscan_results(host_url, api_key, [cloudflare_radar.error_result(domain, str(e))])
            stats["error"] = str(e)
            stats["errors"] += 1
            break
        except cloudflare_radar.QuotaError as e:
            sync_client.send_cfscan_results(host_url, api_key, [cloudflare_radar.error_result(domain, str(e))])
            stats["error"] = str(e)
            stats["errors"] += 1
            break
        except Exception as e:  # never abort the caller for one domain
            sync_client.send_cfscan_results(host_url, api_key, [cloudflare_radar.error_result(domain, str(e))])
            stats["errors"] += 1
            log.warning("Cloudflare scan failed for %s: %s", domain, e)
        if cf["rate_delay"] > 0:
            time.sleep(cf["rate_delay"])
    return stats


def run_cfdns_batch(cfg: configparser.ConfigParser, db: sqlite3.Connection,
                    host_url: str, api_key: str, domains: list[str]) -> dict:
    """Fetch the Radar DNS top-locations distribution for ``domains``.

    Cheap (one Radar API request per domain, no scan quota); used by the separate
    "Cloudflare DNS" action. The results are merged into the existing
    ``domain_cfscan`` row without touching the URL Scanner verdict.
    """
    stats = {"requested": len(domains), "checked": 0, "errors": 0, "error": None}
    cf = _cf_config(cfg)
    if not cf.get("enabled") or not cf.get("api_token"):
        stats["error"] = "Cloudflare Radar not configured ([cloudflare] api_token)."
        return stats

    for domain in domains:
        try:
            locations = cloudflare_radar.dns_top_locations(
                domain, cf["api_token"], timeout=cf["timeout"], limit=cf["dns_limit"])
            sync_client.send_cfscan_results(host_url, api_key, [{
                "domain": domain, "dns_only": True, "dns_countries": locations,
            }])
            stats["checked"] += 1
        except cloudflare_radar.AuthError as e:
            stats["error"] = str(e)
            stats["errors"] += 1
            break
        except Exception as e:  # never abort the caller for one domain
            stats["errors"] += 1
            log.warning("Cloudflare DNS locations failed for %s: %s", domain, e)
        if cf["dns_rate_delay"] > 0:
            time.sleep(cf["dns_rate_delay"])
    return stats


def auto_cfscan_new_matches(cfg: configparser.ConfigParser, db: sqlite3.Connection,
                            host_url: str, api_key: str, matches: list[dict]) -> int:
    """Scan the freshly matched domains after a download (``[cloudflare] auto_scan``)."""
    cf = _cf_config(cfg)
    if not matches or not cf.get("enabled") or not cf.get("auto_scan"):
        return 0
    max_n = max(0, cf.get("auto_scan_max", 0))
    if max_n == 0:
        return 0
    domains: list[str] = []
    seen: set = set()
    for m in matches:
        if m.get("is_historical"):
            continue
        d = str(m.get("domain", "")).lower().strip()
        if not d or d in seen:
            continue
        seen.add(d)
        domains.append(d)
        if len(domains) >= max_n:
            break
    if not domains:
        return 0
    stats = run_cfscan_batch(cfg, db, host_url, api_key, domains)
    log.info("Cloudflare auto-scan: %s scanned, %s error(s)", stats.get("scanned", 0), stats.get("errors", 0))
    return stats.get("scanned", 0)


_WEEKDAYS = {
    "monday": 0, "mon": 0, "tuesday": 1, "tue": 1, "wednesday": 2, "wed": 2,
    "thursday": 3, "thu": 3, "friday": 4, "fri": 4, "saturday": 5, "sat": 5,
    "sunday": 6, "sun": 6,
}


def resolve_weekly_schedule(cfg: configparser.ConfigParser):
    """Resolve the weekly Intelligence tracking schedule.

    Returns (enabled, weekday, hour, minute, tzinfo), weekday Monday=0..Sunday=6.
    Defaults to Sunday 03:00 Europe/Madrid.
    """
    enabled = cfg.getboolean("tracking", "weekly_enabled", fallback=True) if cfg.has_section("tracking") else False
    day_str = (cfg.get("tracking", "weekly_day", fallback="sunday") or "sunday").strip().lower() if cfg.has_section("tracking") else "sunday"
    weekday = _WEEKDAYS.get(day_str)
    if weekday is None:
        try:
            weekday = int(day_str) % 7
        except ValueError:
            weekday = 6
    time_str = (cfg.get("tracking", "weekly_run_time", fallback="03:00") or "03:00").strip() if cfg.has_section("tracking") else "03:00"
    tz_name = (cfg.get("tracking", "weekly_run_timezone", fallback="Europe/Madrid") or "Europe/Madrid").strip() if cfg.has_section("tracking") else "Europe/Madrid"
    tz = timezone.utc
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            log.warning("Unknown weekly_run_timezone '%s'; using UTC.", tz_name)
    else:
        log.warning("zoneinfo is not available; using UTC for the weekly schedule.")
    try:
        hour, minute = (int(part) for part in time_str.split(":")[:2])
        if not (0 <= hour < 24 and 0 <= minute < 60):
            raise ValueError(time_str)
    except Exception:
        log.warning("Invalid weekly_run_time '%s'; using 03:00.", time_str)
        hour, minute = 3, 0
    return enabled, weekday, hour, minute, tz


def get_weekly_attempt(db: sqlite3.Connection) -> str | None:
    cursor = db.cursor()
    cursor.execute("SELECT value FROM config WHERE key = 'last_weekly_attempt'")
    row = cursor.fetchone()
    return row[0] if row else None


def set_weekly_attempt(db: sqlite3.Connection, week_key: str) -> None:
    cursor = db.cursor()
    cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('last_weekly_attempt', ?)", (week_key,))
    db.commit()


def weekly_tracking_due(cfg: configparser.ConfigParser, db: sqlite3.Connection) -> tuple[bool, str, object]:
    """Decide whether the daemon must run the weekly Intelligence pass now.

    Returns (due, week_key, tzinfo). Due once per ISO week, after the configured
    weekday/time; if the host was off then it runs on the next poll.
    """
    enabled, weekday, hour, minute, tz = resolve_weekly_schedule(cfg)
    if not enabled:
        return False, "", tz
    now = datetime.now(tz)
    monday = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    target = (monday + timedelta(days=weekday)).replace(hour=hour, minute=minute)
    if now < target:
        return False, "", tz
    week_key = now.strftime("%G-W%V")
    return get_weekly_attempt(db) != week_key, week_key, tz


def enroll_tracking_matches(cfg: configparser.ConfigParser, host_url: str, api_key: str,
                            matches: list[dict]) -> int:
    """Send recently matched domains to the hosting API for Intelligence tracking.

    The web applies the per-keyword policy (tracking enabled, recent WHOIS age,
    not flagged) and also sweeps domains already tagged `excluded`. Always calls
    the endpoint (even with no new matches) so that sweep runs each cycle. Best
    effort: never raises. Returns the number of candidates sent.
    """
    if cfg.has_section("tracking") and not cfg.getboolean("tracking", "enroll_enabled", fallback=True):
        return 0

    entries = []
    seen = set()
    for m in (matches or []):
        if m.get("is_historical"):
            continue
        d = str(m.get("domain", "")).lower().strip()
        try:
            kid = int(m.get("keyword_id") or 0)
        except (TypeError, ValueError):
            kid = 0
        if not d or kid <= 0 or (d, kid) in seen:
            continue
        seen.add((d, kid))
        entries.append({"domain": d, "keyword_id": kid, "first_seen": m.get("first_seen")})
        if len(entries) >= 2000:
            break
    try:
        return len(entries) if sync_client.send_tracking_enroll(host_url, api_key, entries) else 0
    except Exception as e:
        log.warning("Tracking enrollment failed: %s", e)
        return 0


def run_tracking_check(cfg: configparser.ConfigParser, db: sqlite3.Connection,
                       host_url: str, api_key: str, domains: list | None = None) -> dict:
    """Validate the due tracked domains and report activation signals.

    Signals: reputation (abuse.ch + VirusTotal), WHOIS/NS changes, DNS
    resolution and a TLS certificate issued after enrollment. Best effort per
    domain; never raises. Returns stats.
    """
    stats = {"due": 0, "checked": 0, "activated": 0, "sent": False, "batches": 0}
    if not cfg.has_section("tracking") or not cfg.getboolean("tracking", "enabled", fallback=True):
        return stats

    # Informational last-run stamp (the weekly cadence uses the config marker).
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    try:
        db.execute("INSERT OR REPLACE INTO tracking_meta (key, value) VALUES ('last_run', ?)", (now,))
        db.commit()
    except sqlite3.OperationalError:
        pass

    batch = max(1, cfg.getint("tracking", "batch_max", fallback=200))
    max_total = max(1, cfg.getint("tracking", "weekly_batch_max", fallback=5000))

    reputation_on = cfg.getboolean("tracking", "reputation_enabled", fallback=True)
    whois_on = cfg.getboolean("tracking", "whois_enabled", fallback=True)
    dns_on = cfg.getboolean("tracking", "dns_enabled", fallback=True)
    cert_on = cfg.getboolean("tracking", "cert_enabled", fallback=True)
    http_on = cfg.getboolean("tracking", "http_enabled", fallback=True)
    http_activate_any = cfg.getboolean("tracking", "http_activate_any_200", fallback=False)
    dns_timeout = cfg.getint("tracking", "dns_timeout", fallback=10)
    cert_timeout = cfg.getint("tracking", "cert_timeout", fallback=30)
    http_timeout = cfg.getint("tracking", "http_timeout", fallback=15)
    http_max_bytes = cfg.getint("tracking", "http_max_bytes", fallback=200000)
    rate = cfg.getfloat("tracking", "rate_delay_seconds", fallback=1.0)
    data_dir = cfg.get("worker", "data_dir", fallback="./data")

    abuse_key = ""
    abuse_timeout = 20
    if cfg.has_section("abusech"):
        abuse_key = cfg.get("abusech", "auth_key", fallback="").strip()
        abuse_timeout = cfg.getint("abusech", "timeout", fallback=20)
    abuse_on = reputation_on and bool(abuse_key) and not abuse_key.upper().startswith("TU_")

    vt_key = ""
    if cfg.has_section("virustotal"):
        vt_key = cfg.get("virustotal", "api_key", fallback="").strip()
    vt_on = reputation_on and bool(vt_key) and not vt_key.upper().startswith("TU_")

    def process_batch(due_entries):
        # Deduplicate by domain (a domain may be tracked under several keywords);
        # keep every keyword so the HTTP brand match can use them.
        unique: dict = {}
        for e in due_entries:
            d = str(e.get("domain", "")).lower().strip()
            if not d:
                continue
            if d not in unique:
                unique[d] = {"entry": e, "keywords": set()}
            kw = str(e.get("keyword") or "").strip()
            if kw:
                unique[d]["keywords"].add(kw)

        out = []
        for d, info in unique.items():
            e = info["entry"]
            keywords = info["keywords"]
            baseline = e.get("baseline") or {}
            if not isinstance(baseline, dict):
                baseline = {}
            baseline_dns = baseline.get("dns")

            abuse_res = vt_res = whois_now = None
            if abuse_on:
                try:
                    abuse_res = abusech.lookup_domain(d, abuse_key, timeout=abuse_timeout)
                except Exception:
                    abuse_res = None
            if vt_on:
                try:
                    vt_res = virustotal.lookup_domain(d, vt_key)
                except Exception:
                    vt_res = None
            if whois_on:
                try:
                    entries = whois_lookup_entries(cfg, data_dir, [d])
                    if entries:
                        whois_now = entries[0]
                except Exception:
                    whois_now = None

            dns_now = None
            if dns_on:
                dns_now = intel.dns_resolves(d, timeout=dns_timeout)
            dns_started = (dns_now is True and baseline_dns is False)

            cert_new = False
            if cert_on:
                enrolled_at = str(e.get("enrolled_at") or "")
                cert_new = intel.crt_sh_has_new_cert(d, enrolled_at, timeout=cert_timeout) is True

            # HTTP content (F3): brand keyword, login form, plain 200 and hash change.
            http_brand = http_login = False
            http_200 = None
            http_changed = False
            http_hash = None
            if http_on:
                probe = intel.http_probe(d, timeout=http_timeout, max_bytes=http_max_bytes)
                if probe.get("status") is not None:
                    http_200 = (probe["status"] == 200)
                    http_hash = probe.get("body_hash") or None
                    http_login = bool(probe.get("has_login"))
                    http_brand = intel.contains_keyword(probe.get("title"), probe.get("body"), keywords)
                    baseline_hash = baseline.get("http_hash")
                    http_changed = bool(baseline_hash and http_hash and baseline_hash != http_hash)

            # Refresh the local caches so the UI shows the fresh data.
            try:
                if abuse_res and abuse_res.get("status") == "ok":
                    sync_client.send_abusech_results(host_url, api_key, [abuse_res])
                if vt_res and vt_res.get("status") in ("ok", "not_found"):
                    sync_client.send_vt_results(host_url, api_key, [vt_res])
                if whois_now and whois_now.get("status") == "ok":
                    sync_client.send_whois_results(host_url, api_key, [whois_now])
            except Exception:
                pass

            changed, detail = intel.compare_whois(baseline, whois_now)
            ev = intel.evaluate(abuse_res, vt_res, changed, detail,
                                dns_started=dns_started, dns_now=dns_now, cert_new=cert_new,
                                http_brand=http_brand, http_login=http_login, http_200=http_200,
                                http_changed=http_changed, http_activate_any_200=http_activate_any)
            ev["domain"] = d
            # The first reading of a signal establishes its baseline.
            baseline_update = {}
            if dns_on and baseline_dns is None and dns_now is not None:
                baseline_update["dns"] = bool(dns_now)
            if http_on and baseline.get("http_hash") is None and http_hash:
                baseline_update["http_hash"] = http_hash
            if baseline_update:
                ev["baseline_update"] = baseline_update
            out.append(ev)
            stats["checked"] += 1
            if ev["activated"]:
                stats["activated"] += 1
            if rate > 0:
                time.sleep(rate)
        return out

    # The weekly pass loops over the due domains in batches (each batch is
    # rescheduled by the results, so it is not fetched again); a manual check
    # processes exactly the requested domains.
    manual = domains is not None
    processed = 0
    while True:
        try:
            due = sync_client.get_tracking_due(host_url, api_key, limit=batch, domains=domains)
        except Exception as e:
            log.warning("Tracking: could not fetch due list: %s", e)
            break
        if not due:
            break
        stats["due"] += len(due)
        results = process_batch(due)
        if not results:
            break
        try:
            ok = sync_client.send_tracking_results(host_url, api_key, results)
        except Exception as e:
            log.warning("Tracking: could not send results: %s", e)
            break
        stats["sent"] = stats["sent"] or bool(ok)
        stats["batches"] += 1
        processed += len(results)
        if manual or processed >= max_total:
            break

    log.info("Intelligence tracking: %s checked, %s activated (sent=%s, batches=%s)",
             stats["checked"], stats["activated"], stats["sent"], stats["batches"])
    return stats


def _timing_add(timing: dict | None, key: str, seconds: float) -> None:
    if timing is not None:
        timing[key] = timing.get(key, 0.0) + seconds


def _baseline_decision(meta: dict, use_hash: bool) -> tuple[bool, bool, str]:
    """Decide whether a TLD run may emit matches.

    Returns (is_baseline, mode_changed, cache_mode). A TLD that never completed a
    scan is a baseline (cache only). A change of cache mode also suppresses
    matches for that run, because the anti-join would otherwise run against an
    empty table and re-report the whole zone as new.
    """
    is_baseline = int(meta.get("baselined") or 0) != 1
    cache_mode = "hash" if use_hash else "text"
    mode_changed = (not is_baseline) and meta.get("cache_mode") not in (None, cache_mode)
    return is_baseline, mode_changed, cache_mode


def _stage_and_diff_batch(cursor: sqlite3.Cursor, tld: str, now: str, batch: list[str],
                          keyword_matcher, matches: list[dict], use_hash: bool = False,
                          timing: dict | None = None, emit_matches: bool = True) -> int:
    """Stage a parsed batch, insert genuinely new domains and match them.

    Uses a TEMP table plus a SQL anti-join so the full known-domain set is never
    loaded into Python, keeping peak memory bounded on very large TLDs. When
    use_hash is set, only a 64-bit hash per domain is persisted (compact cache)
    but matching still runs on the real domain text.

    When `timing` is given, accumulates wall time per phase under the keys
    "stage" (dedupe + temp insert + anti-join), "insert" (new rows) and "match".
    When `emit_matches` is False the domains are still cached but not matched
    (used for the first baseline scan of a TLD so historical domains are not
    reported as new). Returns the number of new domains found.
    """
    t0 = time.perf_counter()
    if use_hash:
        cursor.execute("DELETE FROM zone_batch_hash")
        mapping: dict[int, str] = {}
        for domain in batch:
            mapping[_domain_hash(domain)] = domain
        cursor.executemany(
            "INSERT OR IGNORE INTO zone_batch_hash (domain_hash) VALUES (?)",
            ((h,) for h in mapping)
        )
        cursor.execute(
            "SELECT z.domain_hash FROM zone_batch_hash z "
            "LEFT JOIN domains_cache_hash c ON c.domain_hash = z.domain_hash "
            "WHERE c.domain_hash IS NULL"
        )
        new_hashes = [row[0] for row in cursor.fetchall()]
        t_stage = time.perf_counter()
        _timing_add(timing, "stage", t_stage - t0)
        if not new_hashes:
            return 0
        first_seen = int(time.time())
        cursor.executemany(
            "INSERT OR IGNORE INTO domains_cache_hash (domain_hash, tld, first_seen) VALUES (?, ?, ?)",
            ((h, tld, first_seen) for h in new_hashes)
        )
        t_insert = time.perf_counter()
        _timing_add(timing, "insert", t_insert - t_stage)
        if emit_matches and keyword_matcher is not None:
            matches.extend(keyword_matcher.match(mapping[h] for h in new_hashes))
        _timing_add(timing, "match", time.perf_counter() - t_insert)
        return len(new_hashes)

    cursor.execute("DELETE FROM zone_batch")
    cursor.executemany(
        "INSERT OR IGNORE INTO zone_batch (domain) VALUES (?)",
        ((domain,) for domain in batch)
    )
    cursor.execute(
        "SELECT z.domain FROM zone_batch z "
        "LEFT JOIN domains_cache c ON c.domain = z.domain "
        "WHERE c.domain IS NULL"
    )
    new_domains = [row[0] for row in cursor.fetchall()]
    t_stage = time.perf_counter()
    _timing_add(timing, "stage", t_stage - t0)
    if not new_domains:
        return 0
    cursor.executemany(
        "INSERT OR IGNORE INTO domains_cache (domain, tld, first_seen) VALUES (?, ?, ?)",
        ((domain, tld, now) for domain in new_domains)
    )
    t_insert = time.perf_counter()
    _timing_add(timing, "insert", t_insert - t_stage)
    if emit_matches and keyword_matcher is not None:
        matches.extend(keyword_matcher.match(new_domains))
    _timing_add(timing, "match", time.perf_counter() - t_insert)
    return len(new_domains)


def enqueue_tld_retry(db: sqlite3.Connection, tld: str, error: str, base_delay: int) -> tuple[int, str]:
    """Schedule a retry for a failed/incomplete TLD. Returns (attempts, next_retry ISO)."""
    cursor = db.cursor()
    cursor.execute("SELECT attempts FROM tld_retry_queue WHERE tld = ?", (tld,))
    row = cursor.fetchone()
    attempts = (row[0] if row else 0) + 1
    delay = min(base_delay * attempts, 3600)
    next_retry = (datetime.now(timezone.utc) + timedelta(seconds=delay)).isoformat()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "INSERT OR REPLACE INTO tld_retry_queue (tld, attempts, next_retry, last_error, updated_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (tld, attempts, next_retry, (error or "")[:500], now)
    )
    db.commit()
    return attempts, next_retry


def clear_tld_retry(db: sqlite3.Connection, tld: str) -> None:
    db.execute("DELETE FROM tld_retry_queue WHERE tld = ?", (tld,))
    db.commit()


def get_due_tld_retries(db: sqlite3.Connection) -> list[str]:
    """Return TLDs whose retry is due now."""
    now = datetime.now(timezone.utc).isoformat()
    rows = db.execute(
        "SELECT tld FROM tld_retry_queue WHERE next_retry IS NULL OR next_retry <= ? ORDER BY next_retry ASC",
        (now,)
    ).fetchall()
    return [row[0] for row in rows]


def get_tld_meta(db: sqlite3.Connection, tld: str) -> dict:
    """Return the stored download/run metadata for a TLD."""
    cursor = db.cursor()
    cursor.execute(
        "SELECT etag, last_modified, last_run_date, last_run_status, baselined, cache_mode "
        "FROM tld_meta WHERE tld = ?",
        (tld,)
    )
    row = cursor.fetchone()
    if not row:
        return {"etag": None, "last_modified": None, "last_run_date": None,
                "last_run_status": None, "baselined": 0, "cache_mode": None}
    return {"etag": row[0], "last_modified": row[1], "last_run_date": row[2],
            "last_run_status": row[3], "baselined": row[4], "cache_mode": row[5]}


def update_tld_meta(db: sqlite3.Connection, tld: str, etag: str | None,
                    last_modified: str | None, run_date: str | None, status: str,
                    baselined: int | None = None, cache_mode: str | None = None) -> None:
    """Persist download validators and the last successful run date for a TLD.

    `baselined` / `cache_mode` are preserved when not supplied, so callers that
    only update the run date (e.g. not_modified) do not wipe the baseline state.
    """
    current = get_tld_meta(db, tld)
    if baselined is None:
        baselined = current.get("baselined", 0)
    if cache_mode is None:
        cache_mode = current.get("cache_mode")
    cursor = db.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO tld_meta (tld, etag, last_modified, last_run_date, last_run_status, baselined, cache_mode) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (tld, etag, last_modified, run_date, status, int(baselined or 0), cache_mode)
    )
    db.commit()


def _zone_info(filepath: str) -> tuple[int, str | None]:
    """Return (size_bytes, iso_mtime_utc) for a retained zone file, or (0, None)."""
    try:
        size = os.path.getsize(filepath)
        mtime = datetime.fromtimestamp(os.path.getmtime(filepath), tz=timezone.utc).isoformat()
        return size, mtime
    except OSError:
        return 0, None


def _tld_report(tld: str, status: str, filepath: str | None = None,
                records_total: int = 0, records_new: int = 0,
                error: str | None = None, attempts: int = 0,
                next_retry: str | None = None) -> dict:
    """Build a per-TLD report entry for the hosting UI."""
    zone_size, zone_mtime = _zone_info(filepath) if filepath else (0, None)
    return {
        "tld": tld,
        "status": status,
        "records_total": records_total,
        "records_new": records_new,
        "zone_size": zone_size,
        "zone_file_mtime": zone_mtime,
        "error": error,
        "attempts": attempts,
        "next_retry": next_retry,
    }


def process_tld(tld: str, token: str, download_dir: str, db: sqlite3.Connection,
                keywords: list[dict], force: bool = False,
                refresh: bool = False, settings: dict | None = None,
                progress_callback=None) -> tuple[list[dict], dict]:
    """Download, parse, deduplicate and match a single TLD.

    Returns (matches, info) where info reports what happened to the TLD so the
    web UI can show it.

    To minimise load on the ICANN CZDS API this function:
      - skips a TLD already successfully processed today (unless force/refresh),
      - performs a conditional request (ETag / Last-Modified) so an unchanged
        zone is not transferred again (refresh keeps the validators, force drops
        them and re-downloads unconditionally),
      - resumes an interrupted download (HTTP Range) and validates the final
        size against Content-Length,
      - keeps the last downloaded zone file on disk instead of deleting it
        (except for huge TLDs cached by hash, where disk is at a premium).
    """
    settings = settings or {}
    today_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    now = datetime.now(timezone.utc).isoformat()
    meta = get_tld_meta(db, tld)

    os.makedirs(download_dir, exist_ok=True)
    filepath = os.path.join(download_dir, f"{tld}.zone.gz")

    # 1. Daily idempotency guard: never re-scan a TLD already done today.
    #    `refresh` bypasses the guard but keeps the conditional validators, so
    #    the zone is only transferred again if it actually changed.
    if not force and not refresh and meta["last_run_date"] == today_date and meta["last_run_status"] == "ok":
        print(f"[=] .{tld} already processed today ({today_date}). Skipping to avoid re-scanning.", flush=True)
        return [], _tld_report(tld, "skipped_today", filepath=filepath)

    # 2. Know the remote size first (also used for the hash-cache decision) and
    #    apply the size / free-disk guards before transferring anything.
    content_length, _head_etag, _head_lm = downloader.head_zone(tld, token)

    max_zone_gb = settings.get("max_zone_size_gb", 0) or 0
    if max_zone_gb and content_length and content_length > max_zone_gb * (1 << 30):
        msg = f"zone too large ({content_length / (1 << 30):.2f} GB > limit {max_zone_gb} GB)"
        print(f"[!] .{tld} skipped: {msg}", flush=True)
        return [], _tld_report(tld, "skipped_large", filepath=filepath, error=msg)

    min_free_gb = settings.get("min_free_disk_gb", 0) or 0
    if content_length:
        try:
            free = shutil.disk_usage(download_dir).free
        except OSError:
            free = None
        if free is not None and free - content_length < min_free_gb * (1 << 30):
            msg = (f"not enough disk: {free / (1 << 30):.1f} GB free, "
                   f"need {content_length / (1 << 30):.1f} GB + {min_free_gb:.1f} GB reserve")
            print(f"[!] .{tld} skipped: {msg}", flush=True)
            return [], _tld_report(tld, "no_space", filepath=filepath, error=msg)

    # 3. Very large zones are cached as 64-bit hashes to bound disk usage.
    hash_min_mb = settings.get("hash_cache_min_mb", 0) or 0
    use_hash = bool(content_length and hash_min_mb and content_length >= hash_min_mb * (1 << 20))
    if use_hash:
        print(f"[*] .{tld}: large zone ({content_length / (1 << 30):.2f} GB) -> compact hash cache.", flush=True)

    # Only emit matches when the TLD was already baselined and the cache mode did
    # not change. A mode switch (text <-> hash) would otherwise anti-join against
    # an empty table and re-report the whole zone as new.
    is_baseline, mode_changed, cache_mode = _baseline_decision(meta, use_hash)
    emit_matches = not is_baseline and not mode_changed
    if is_baseline:
        print(f"[*] .{tld}: first scan -> caching only, no notifications (baseline).", flush=True)
    elif mode_changed:
        print(f"[*] .{tld}: cache mode changed ({meta.get('cache_mode')} -> {cache_mode}); "
              f"re-populating without notifications to avoid a flood.", flush=True)

    # 4. Conditional, resumable download with immediate retries.
    prev_etag = None if force else meta["etag"]
    prev_last_modified = None if force else meta["last_modified"]
    retry_delay = settings.get("retry_delay_seconds", 300)
    t_dl0 = time.perf_counter()
    status, etag, last_modified, error = downloader.download_zone(
        tld, token, filepath, etag=prev_etag, last_modified=prev_last_modified,
        progress_callback=progress_callback,
        max_retries=settings.get("max_download_retries", 3),
    )
    t_download = time.perf_counter() - t_dl0
    if status == "failed":
        attempts, next_retry = enqueue_tld_retry(db, tld, error or "download failed", retry_delay)
        return [], _tld_report(tld, "failed", filepath=filepath, error=error,
                               attempts=attempts, next_retry=next_retry)
    if status == "not_modified":
        print(f"[=] .{tld} zone unchanged since last run. Skipping parse.", flush=True)
        update_tld_meta(db, tld, meta["etag"], meta["last_modified"], today_date, "ok")
        clear_tld_retry(db, tld)
        return [], _tld_report(tld, "not_modified", filepath=filepath)

    # 5. Parse and find new domains. The comparison against the cache is done
    #    entirely in SQLite (batched + anti-join) so the full known-domain set
    #    is never loaded into Python: peak memory stays bounded on huge TLDs.
    print(f"[*] Parsing {tld}.zone ...", flush=True)
    keyword_matcher = matcher.Matcher(keywords) if keywords else None
    total = 0
    new_count = 0
    matches: list[dict] = []
    cursor = db.cursor()
    batch = []
    batch_size = 50000
    last_progress = time.time()
    commit_batches = settings.get("commit_every_batches", 10) or 10
    min_free_bytes = (min_free_gb or 0) * (1 << 30)
    batches_since_commit = 0
    space_abort = False
    # Phase timings (wall clock) for the [timing] log line.
    timing = {"stage": 0.0, "insert": 0.0, "match": 0.0, "commit": 0.0}
    # Optional durability trade-off for the bulk parse only: with synchronous=OFF
    # SQLite skips fsync on commits/checkpoints. worker.db is a rebuildable cache.
    sync_off = settings.get("sqlite_synchronous_parse", "NORMAL") == "OFF"
    if sync_off:
        try:
            db.execute("PRAGMA synchronous=OFF")
        except sqlite3.OperationalError:
            sync_off = False
    t_parse0 = time.perf_counter()

    try:
        if use_hash:
            cursor.execute("CREATE TEMP TABLE IF NOT EXISTS zone_batch_hash (domain_hash INTEGER PRIMARY KEY)")
        else:
            cursor.execute("CREATE TEMP TABLE IF NOT EXISTS zone_batch (domain TEXT PRIMARY KEY)")
        for domain in parser.parse_zone_gz(filepath, tld):
            total += 1
            batch.append(domain)
            if len(batch) >= batch_size:
                new_count += _stage_and_diff_batch(cursor, tld, now, batch, keyword_matcher,
                                                   matches, use_hash=use_hash, timing=timing,
                                                   emit_matches=emit_matches)
                batch = []
                batches_since_commit += 1
                if progress_callback and time.time() - last_progress >= 5:
                    last_progress = time.time()
                    progress_callback("parse", total, None)
                if batches_since_commit >= commit_batches:
                    # Huge zones (e.g. .com, ~160M inserts) must not grow the WAL
                    # unbounded: commit and checkpoint regularly.
                    t_commit = time.perf_counter()
                    db.commit()
                    batches_since_commit = 0
                    try:
                        cursor.execute("PRAGMA wal_checkpoint(PASSIVE)")
                    except sqlite3.OperationalError:
                        pass
                    _timing_add(timing, "commit", time.perf_counter() - t_commit)
                    if min_free_bytes and shutil.disk_usage(download_dir).free < min_free_bytes:
                        space_abort = True
                        print(f"[!] .{tld}: stopping mid-parse, free disk below the "
                              f"{min_free_bytes / (1 << 30):.1f} GB reserve.", flush=True)
                        break
        if batch and not space_abort:
            new_count += _stage_and_diff_batch(cursor, tld, now, batch, keyword_matcher,
                                               matches, use_hash=use_hash, timing=timing,
                                               emit_matches=emit_matches)
        t_commit = time.perf_counter()
        db.commit()
        _timing_add(timing, "commit", time.perf_counter() - t_commit)
        cursor.execute("DROP TABLE IF EXISTS zone_batch")
        cursor.execute("DROP TABLE IF EXISTS zone_batch_hash")
    except Exception:
        db.rollback()
        raise
    finally:
        if sync_off:
            try:
                db.execute("PRAGMA synchronous=NORMAL")
            except sqlite3.OperationalError:
                pass
    t_parse_total = time.perf_counter() - t_parse0

    if space_abort:
        msg = (f"no_space: stopped after {total:,} domains; free disk below the "
               f"{min_free_bytes / (1 << 30):.1f} GB reserve")
        # Drop the multi-GB zone to recover space; the TLD is queued for retry.
        try:
            os.remove(filepath)
        except OSError:
            pass
        attempts, next_retry = enqueue_tld_retry(db, tld, msg, retry_delay)
        print(f"[!] .{tld}: {msg}", flush=True)
        return [], _tld_report(tld, "no_space", error=msg,
                               attempts=attempts, next_retry=next_retry)

    print(f"[+] {tld}: {total:,} total, {new_count:,} new.", flush=True)

    sql_time = timing["stage"] + timing["insert"] + timing["match"] + timing["commit"]
    parse_time = max(t_parse_total - sql_time, 0.0)
    print(f"[timing] .{tld} parse={parse_time:.1f}s stage={timing['stage']:.1f}s "
          f"insert={timing['insert']:.1f}s match={timing['match']:.1f}s "
          f"commit={timing['commit']:.1f}s download={t_download:.1f}s "
          f"total={t_parse_total:.1f}s", flush=True)

    # Safety net: a non-trivial zone that yields no domains means the parser is
    # broken (e.g. the v1.3.39 case-sensitive pre-filter). Do not mark the TLD as
    # done, do not delete the zone and flag it for retry so it is visible.
    zone_bytes = content_length or _zone_info(filepath)[0]
    if total == 0 and zone_bytes > (1 << 20):
        msg = f"parse_error: 0 domains parsed from a {zone_bytes / (1 << 20):.1f} MB zone"
        attempts, next_retry = enqueue_tld_retry(db, tld, msg, retry_delay)
        print(f"[!] .{tld}: {msg}", flush=True)
        return [], _tld_report(tld, "parse_error", filepath=filepath, error=msg,
                               attempts=attempts, next_retry=next_retry)

    cursor.execute(
        "INSERT INTO zone_runs (tld, run_date, records_total, records_new, status) VALUES (?, ?, ?, ?, ?)",
        (tld, now, total, new_count, "ok")
    )
    db.commit()

    # Zone parsed and cached successfully: persist validators + today's date so
    # subsequent runs can skip this TLD via a conditional request / daily guard.
    # baselined=1 enables notifications from the next changed zone onwards.
    update_tld_meta(db, tld, etag, last_modified, today_date, "ok",
                    baselined=1, cache_mode=cache_mode)
    clear_tld_retry(db, tld)

    if matches:
        for m in matches:
            m["first_seen"] = now
        print(f"[+] {len(matches)} matches found for .{tld}.", flush=True)

    report = _tld_report(tld, "baselined" if not emit_matches else "downloaded",
                         filepath=filepath, records_total=total, records_new=new_count)

    # Huge hash-cached TLDs: drop the multi-GB zone unless retention is enabled.
    if use_hash and not settings.get("retain_zone_hash_tlds", False):
        try:
            os.remove(filepath)
            print(f"[i] .{tld}: zone file removed after parse "
                  f"(compact hash cache; set retain_zone_hash_tlds=true to keep it).", flush=True)
        except OSError:
            pass

    return matches, report


def retry_sync_queue(db: sqlite3.Connection, host_url: str, api_key: str, max_retries: int) -> None:
    """Attempt to send any queued payloads. Move exhausted items to dead letter queue."""
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "SELECT id, payload, retry_count FROM sync_queue WHERE next_retry <= ?",
        (now,)
    )
    rows = cursor.fetchall()
    if not rows:
        return

    dead_letter_logs = []
    print(f"[*] Retrying {len(rows)} queued sync item(s) ...")
    for row_id, payload_json, retry_count in rows:
        if retry_count >= max_retries:
            # Legacy protection: move any row already at/exceeding limit to dead letter
            cursor.execute(
                "INSERT INTO sync_dead_letter (payload, retry_count, error_reason, created_at, failed_at) VALUES (?, ?, ?, ?, ?)",
                (payload_json, retry_count, "Retries exhausted (legacy)", now, now)
            )
            cursor.execute("DELETE FROM sync_queue WHERE id = ?", (row_id,))
            db.commit()
            dead_letter_logs.append({
                "level": "error",
                "message": f"Sync queue item {row_id} moved to dead letter (retries exhausted, legacy)",
                "timestamp": now
            })
            continue

        payload = json.loads(payload_json)
        ok = sync_client.send_matches(host_url, api_key, payload)
        if ok:
            cursor.execute("DELETE FROM sync_queue WHERE id = ?", (row_id,))
            db.commit()
        else:
            new_retry_count = retry_count + 1
            if new_retry_count >= max_retries:
                cursor.execute(
                    "INSERT INTO sync_dead_letter (payload, retry_count, error_reason, created_at, failed_at) VALUES (?, ?, ?, ?, ?)",
                    (payload_json, new_retry_count, "Retries exhausted", now, now)
                )
                cursor.execute("DELETE FROM sync_queue WHERE id = ?", (row_id,))
                db.commit()
                dead_letter_logs.append({
                    "level": "error",
                    "message": f"Sync queue item {row_id} moved to dead letter after {new_retry_count} retries",
                    "timestamp": now
                })
                print(f"[!] Queue item {row_id} moved to dead letter after {new_retry_count} retries.")
            else:
                next_retry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
                cursor.execute(
                    "UPDATE sync_queue SET retry_count = ?, next_retry = ? WHERE id = ?",
                    (new_retry_count, next_retry, row_id)
                )
                db.commit()

    if dead_letter_logs:
        sync_client.send_logs(host_url, api_key, dead_letter_logs)


def queue_matches(db: sqlite3.Connection, matches: list[dict]) -> None:
    """Store matches locally for later retry."""
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()
    next_retry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
    payload = json.dumps(matches)
    cursor.execute(
        "INSERT INTO sync_queue (payload, retry_count, next_retry, created_at) VALUES (?, ?, ?, ?)",
        (payload, 0, next_retry, now)
    )
    db.commit()
    print(f"[!] Queued {len(matches)} matches for retry.")


def report_icann_failure(host_url: str, api_key: str, stage: str, error: str,
                         active_tlds: list[str] | None = None) -> list[dict]:
    """Surface a fatal ICANN (CZDS) cycle failure to the web panel.

    The ICANN cycle aborts early (bad credentials, no approved TLDs, no active
    selection, no keywords) and previously returned without reporting anything,
    so the TLDs page kept showing the previous status and `run_worker` looked
    'completed' with 0 TLDs. This records an error log and flags the active
    CZDS TLDs as failed (with the reason) so the failure is visible.

    Returns the per-TLD report entries that were sent (for tests/introspection).
    """
    message = f"ICANN cycle aborted ({stage}): {error}"
    try:
        sync_client.send_logs(host_url, api_key, [{"level": "error", "message": message}])
    except Exception as e:
        log.warning("Could not send ICANN failure log: %s", e)

    entries: list[dict] = []
    try:
        tlds = active_tlds
        if tlds is None:
            # The hosting API does not need the ICANN token, so the active CZDS
            # TLD list can still be fetched to flag them as failed.
            tlds = sync_client.get_active_tlds(host_url, api_key)
        entries = [_tld_report(t, "failed", error=message) for t in (tlds or [])]
        if entries:
            sync_client.report_tld_sync(host_url, api_key, entries)
    except Exception as e:
        log.warning("Could not report ICANN failure to hosting: %s", e)
    return entries


def _cycle_summary_log(worker_stats: dict, label: str) -> dict:
    """Build the worker_log entry for a finished cycle (success or fatal error)."""
    if worker_stats.get("error"):
        return {
            "level": "error",
            "message": f"{label} aborted at {worker_stats.get('stage', 'unknown')}: {worker_stats['error']}",
        }
    return {
        "level": "info",
        "message": (f"{label} completed: {worker_stats['tlds_processed']} TLDs, "
                    f"{worker_stats['matches_found']} matches"),
    }


def run_worker_cycle(db: sqlite3.Connection, cfg: configparser.ConfigParser, host_url: str, api_key: str, version: str, force: bool = False, refresh: bool = False, command_label: str | None = None, command_id: int | None = None) -> dict:
    """Run one full worker cycle. Returns stats dict."""
    download_dir = cfg.get("worker", "download_dir", fallback="./zones")
    data_dir = cfg.get("worker", "data_dir", fallback="./data")
    max_retries = cfg.getint("worker", "max_retries", fallback=5)
    icann_user = cfg.get("icann", "username")
    icann_pass = cfg.get("icann", "password")

    settings = {
        "max_zone_size_gb": cfg.getfloat("worker", "max_zone_size_gb", fallback=0),
        "min_free_disk_gb": cfg.getfloat("worker", "min_free_disk_gb", fallback=5),
        "hash_cache_min_mb": cfg.getfloat("worker", "hash_cache_min_mb", fallback=512),
        "retain_zone_hash_tlds": cfg.getboolean("worker", "retain_zone_hash_tlds", fallback=False),
        "max_download_retries": cfg.getint("worker", "max_download_retries", fallback=3),
        "retry_delay_seconds": cfg.getint("worker", "retry_delay_seconds", fallback=300),
        "commit_every_batches": cfg.getint("worker", "commit_every_batches", fallback=10),
        "sqlite_synchronous_parse": cfg.get("worker", "sqlite_synchronous_parse", fallback="OFF").strip().upper(),
    }

    stats = {
        "tlds_processed": 0,
        "domains_processed": 0,
        "matches_found": 0,
        "whois_looked_up": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    log.info(f"Start: {datetime.now(timezone.utc).isoformat()}")

    # 1. Retry queued items first
    retry_sync_queue(db, host_url, api_key, max_retries)

    # 2. Get ICANN token
    token, token_error = downloader.get_token(icann_user, icann_pass)
    if not token:
        stats["error"] = token_error or "ICANN authentication failed"
        stats["stage"] = "auth"
        report_icann_failure(host_url, api_key, "auth", stats["error"])
        return stats

    # 3. Get approved TLDs
    tlds, tlds_error = downloader.get_approved_tlds(token)
    if not tlds:
        stats["error"] = tlds_error or "No approved TLDs returned by ICANN CZDS"
        stats["stage"] = "approved_tlds"
        print("[-] No TLDs to process.")
        report_icann_failure(host_url, api_key, "approved_tlds", stats["error"])
        return stats

    # 3b. Send TLD list to hosting and get active ones
    try:
        sync_client.send_tlds(host_url, api_key, tlds)
        active_tlds = sync_client.get_active_tlds(host_url, api_key)
        if active_tlds:
            sent_count = len(tlds)
            active_count = len(active_tlds)
            if active_count < sent_count:
                log.info(f"Hosting returned {active_count}/{sent_count} active TLDs.")
            tlds = [t for t in tlds if t in active_tlds]
            log.info(f"Active TLDs from hosting: {len(tlds)}")
        else:
            # No active TLDs selected in web — check config whitelist
            whitelist_raw = cfg.get("tlds", "whitelist", fallback="").strip()
            if whitelist_raw:
                whitelist = [t.strip().lower() for t in whitelist_raw.split(",") if t.strip()]
                tlds = [t for t in tlds if t in whitelist]
                log.info(f"Fallback whitelist applied: {len(tlds)} TLDs to process.")
            else:
                stats["error"] = ("No active TLDs selected in the web panel and no whitelist configured. "
                                  "Mark at least one TLD in /admin/tlds.php or set a whitelist in config.ini.")
                stats["stage"] = "no_active_tlds"
                log.warning(stats["error"])
                print(f"[-] {stats['error']}", flush=True)
                try:
                    sync_client.send_logs(host_url, api_key, [{"level": "warning", "message": stats["error"]}])
                except Exception:
                    pass
                return stats
    except Exception as e:
        log.error(f"Failed to sync TLDs with hosting: {e}")
        # Fallback to config whitelist
        whitelist_raw = cfg.get("tlds", "whitelist", fallback="").strip()
        if whitelist_raw:
            whitelist = [t.strip().lower() for t in whitelist_raw.split(",") if t.strip()]
            tlds = [t for t in tlds if t in whitelist]

    if not tlds:
        stats["error"] = "No TLDs to process (none active and none matching the whitelist)."
        stats["stage"] = "no_tlds"
        log.warning(stats["error"])
        print(f"[-] {stats['error']}", flush=True)
        try:
            sync_client.send_logs(host_url, api_key, [{"level": "warning", "message": stats["error"]}])
        except Exception:
            pass
        return stats

    # 3c. Include TLDs whose retry is due, even if they are no longer active
    #     (a failed download should still be completed).
    due_retries = get_due_tld_retries(db)
    for rt in due_retries:
        if rt not in tlds:
            tlds.append(rt)
    if due_retries:
        log.info(f"Due TLD retries added to this cycle: {len(due_retries)}")

    # 4. Get keywords from hosting
    print("[*] Fetching keywords from hosting ...")
    try:
        keywords = sync_client.get_keywords(host_url, api_key)
        log.info(f"Keywords loaded: {len(keywords)}")
    except Exception as e:
        stats["error"] = f"Failed to fetch keywords from hosting: {e}"
        stats["stage"] = "keywords_fetch"
        log.error(stats["error"])
        report_icann_failure(host_url, api_key, "keywords_fetch", stats["error"])
        return stats

    if not keywords:
        stats["error"] = "No active keywords configured on the hosting. Nothing to match."
        stats["stage"] = "no_keywords"
        print(f"[!] {stats['error']}")
        try:
            sync_client.send_logs(host_url, api_key, [{"level": "warning", "message": stats["error"]}])
        except Exception:
            pass
        return stats

    total_tlds = len(tlds)
    # Send initial heartbeat before TLD loop
    sync_client.send_heartbeat(host_url, api_key, {
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "is_running": 1,
        "version": version,
        "current_action": f"Processing {total_tlds} TLDs",
        "total_tlds": total_tlds,
        "tlds_processed": 0,
        "domains_processed": 0,
        "current_tld": None,
        "current_command": command_label,
        "current_command_id": command_id,
    })

    # 5. Process each TLD
    all_matches = []
    domains_processed = 0
    report_batch: list[dict] = []
    # On small selections (e.g. a few TLDs) report after every TLD so the web
    # UI updates live instead of only at the end of the cycle.
    small_run = total_tlds <= 50

    def flush_reports(force_flush: bool = False) -> None:
        if report_batch and (force_flush or len(report_batch) >= 25):
            sync_client.report_tld_sync(host_url, api_key, list(report_batch))
            report_batch.clear()

    def make_progress_callback(tld_name: str):
        """Throttled callback so long downloads/parses show live progress."""
        last = {"t": 0.0}

        def cb(phase: str, current: int, total: int | None) -> None:
            now_ts = time.time()
            if now_ts - last["t"] < 10:
                return
            last["t"] = now_ts
            if phase == "download":
                if total:
                    action = f"Downloading .{tld_name} {current / 1e9:.2f}/{total / 1e9:.2f} GB"
                else:
                    action = f"Downloading .{tld_name} {current / 1e6:.0f} MB"
            else:
                action = f"Parsing .{tld_name} ({current:,} domains)"
            sync_client.send_heartbeat(host_url, api_key, {
                "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                "is_running": 1,
                "version": version,
                "current_action": action,
                "current_tld": tld_name,
                "total_tlds": total_tlds,
                "tlds_processed": stats["tlds_processed"],
                "domains_processed": domains_processed,
                "current_command": command_label,
                "current_command_id": command_id,
            })

        return cb

    for tld in tlds:
        try:
            matches, info = process_tld(tld, token, download_dir, db, keywords,
                                        force=force, refresh=refresh,
                                        settings=settings,
                                        progress_callback=make_progress_callback(tld))
            all_matches.extend(matches)
            stats["tlds_processed"] += 1
            domains_processed += int(info.get("records_total", 0))
            report_batch.append(info)
            flush_reports(force_flush=small_run)

            # Send incremental heartbeat + log after each TLD
            sync_client.send_heartbeat(host_url, api_key, {
                "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                "is_running": 1,
                "version": version,
                "current_action": f".{tld} {info['status']}",
                "current_tld": tld,
                "total_tlds": total_tlds,
                "tlds_processed": stats["tlds_processed"],
                "domains_processed": domains_processed,
                "current_command": command_label,
                "current_command_id": command_id,
            })
            sync_client.send_logs(host_url, api_key, [{
                "level": "info",
                "message": f"TLD {stats['tlds_processed']}/{total_tlds}: .{tld} {info['status']} "
                           f"({info.get('records_total', 0)} domains, {info.get('records_new', 0)} new)"
            }])
        except Exception as e:
            print(f"[-] Exception processing {tld}: {e}")
            # Roll back any partially inserted cache rows so the TLD is retried
            # cleanly on the next run instead of silently losing its matches.
            try:
                db.rollback()
            except Exception:
                pass
            report_batch.append(_tld_report(tld, "failed", error=str(e)))
            flush_reports()
            sync_client.send_logs(host_url, api_key, [{
                "level": "error",
                "message": f"Exception processing .{tld}: {e}"
            }])

    flush_reports(force_flush=True)

    # 6. Send all matches to hosting
    if all_matches:
        print(f"[*] Sending total of {len(all_matches)} matches to hosting ...")
        ok = sync_client.send_matches(host_url, api_key, all_matches)
        if not ok:
            queue_matches(db, all_matches)
        stats["matches_found"] = len(all_matches)
    else:
        print("[*] No new matches to send.")

    # 6b. Automatically cache the WHOIS/RDAP data for the new matches so the web
    # panel and reports already show creation dates without a manual lookup.
    if all_matches:
        stats["whois_looked_up"] = auto_whois_new_matches(cfg, host_url, api_key, all_matches)

    # 6c. Validate the new matches against the local abuse.ch feed (URLhaus +
    # ThreatFox full dumps), refreshed after the TLD sync when it is stale.
    try:
        stats["abusech_validated"] = auto_abusech_new_matches(cfg, db, host_url, api_key, all_matches)
    except Exception as e:  # never abort the cycle for an enrichment failure
        log.warning("Auto-abuse.ch validation failed: %s", e)
        stats["abusech_validated"] = 0

    # 6c-bis. Optionally scan the new matches with the Cloudflare URL Scanner
    # (best effort; off by default, capped by auto_scan_max).
    try:
        stats["cloudflare_scanned"] = auto_cfscan_new_matches(cfg, db, host_url, api_key, all_matches)
    except Exception as e:  # never abort the cycle for an enrichment failure
        log.warning("Cloudflare auto-scan failed: %s", e)
        stats["cloudflare_scanned"] = 0

    # 6d. Add recently registered clean matches to Intelligence tracking (the
    # web applies the per-keyword policy).
    try:
        stats["tracking_enrolled"] = enroll_tracking_matches(cfg, host_url, api_key, all_matches)
    except Exception as e:  # never abort the cycle for an enrichment failure
        log.warning("Tracking enrollment failed: %s", e)
        stats["tracking_enrolled"] = 0

    stats["domains_processed"] = domains_processed
    set_last_run(db)
    # Send final heartbeat clearing progress
    sync_client.send_heartbeat(host_url, api_key, {
        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
        "is_running": 0,
        "version": version,
        "current_action": "Idle",
        "current_tld": None,
        "total_tlds": 0,
        "tlds_processed": stats["tlds_processed"],
        "domains_processed": domains_processed,
        "matches_found": stats["matches_found"],
        "current_command": None,
        "current_command_id": None,
    })
    log.info(f"End: {datetime.now(timezone.utc).isoformat()}")
    return stats


def recheck_all_domains(db: sqlite3.Connection, host_url: str, api_key: str,
                        max_age_days: int = 30, tlds: list | None = None,
                        max_domains: int = 0, source: str = "czds",
                        keyword_ids: list | None = None) -> dict:
    """Re-check cached CZDS domains against current keywords. Returns stats.

    `tlds` limits the scan to the given TLDs (None/empty = all) and
    `max_domains` caps the number of domains checked (0 = no cap).
    `keyword_ids` limits the matching to those keyword ids (None/empty = all).
    """
    stats = {
        "domains_checked": 0,
        "matches_found": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    log.info("Starting keyword recheck against cached domains...")

    # Huge TLDs use the compact hash cache (no domain text), so they cannot be
    # matched offline; report how many are excluded.
    try:
        hashed = db.execute("SELECT COUNT(*) FROM domains_cache_hash").fetchone()[0]
        if hashed:
            log.info(f"Compact hash cache holds {hashed:,} domains (huge TLDs); excluded from recheck.")
    except sqlite3.OperationalError:
        pass

    try:
        keywords = sync_client.get_keywords(host_url, api_key)
        keywords = matcher.filter_keywords(keywords, keyword_ids)
        log.info(f"Keywords loaded: {len(keywords)}")
    except Exception as e:
        log.error(f"Failed to fetch keywords: {e}")
        return stats

    if not keywords:
        log.warning("No active keywords. Nothing to recheck.")
        return stats

    tld_list = [str(t).lower() for t in (tlds or []) if t]
    where_parts: list[str] = []
    where_params: list = []
    if max_age_days > 0:
        where_parts.append("first_seen >= datetime('now', '-' || ? || ' days')")
        where_params.append(max_age_days)
    if tld_list:
        where_parts.append("tld IN (" + ",".join("?" for _ in tld_list) + ")")
        where_params.extend(tld_list)
    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    total_domains = db.execute(
        f"SELECT COUNT(*) FROM domains_cache{where_sql}", tuple(where_params)
    ).fetchone()[0]
    if max_domains:
        total_domains = min(total_domains, max_domains)
    log.info(f"Cached domains to check (max {max_age_days} days, tlds={tld_list or 'all'}): {total_domains:,}")
    started_at = datetime.now(timezone.utc).isoformat()

    if total_domains == 0:
        log.warning("No cached domains found. Run the worker at least once to download zones before rechecking.")
        sync_client.send_recheck_status(host_url, api_key, {
            "is_running": 0,
            "source": source,
            "total_domains": 0,
            "checked_domains": 0,
            "matches_found": 0,
            "started_at": started_at,
            "completed_at": datetime.now(timezone.utc).isoformat(),
        })
        stats["domains_checked"] = 0
        return stats

    sync_client.send_recheck_status(host_url, api_key, {
        "is_running": 1,
        "source": source,
        "total_domains": total_domains,
        "checked_domains": 0,
        "matches_found": 0,
        "started_at": started_at,
        "completed_at": None,
    })

    batch_size = 50000
    last_domain = ""  # keyset pagination cursor
    all_matches = []
    last_progress_report = 0
    batches_since_stop_check = 0
    keyword_matcher = matcher.Matcher(keywords, for_recheck=True)

    # Keyset pagination: WHERE domain > last ORDER BY domain avoids the O(n^2)
    # cost of deep OFFSET scans on large caches.
    batch_sql = ("SELECT domain, tld, first_seen FROM domains_cache WHERE "
                 + " AND ".join(where_parts + ["domain > ?"]) + " ORDER BY domain LIMIT ?")
    while True:
        cursor = db.cursor()
        cursor.execute(batch_sql, tuple(where_params) + (last_domain, batch_size))
        rows = cursor.fetchall()
        if not rows:
            break
        last_domain = rows[-1][0]

        domains = []
        tld_map = {}
        first_seen_map = {}
        for domain, tld, first_seen in rows:
            domains.append(domain)
            tld_map[domain] = tld
            first_seen_map[domain] = first_seen

        matches = keyword_matcher.match(domains)
        for m in matches:
            m["tld"] = tld_map.get(m["domain"], m["tld"])
            m["first_seen"] = first_seen_map.get(m["domain"], started_at)
            # Recheck revisits already-cached (old) domains, so flag them as
            # historical: the web UI hides them from the "new" listings by default.
            m["is_historical"] = 1
            all_matches.append(m)

        stats["domains_checked"] += len(domains)
        batches_since_stop_check += 1

        if max_domains and stats["domains_checked"] >= max_domains:
            log.info(f"Recheck reached the {max_domains:,}-domain cap.")
            break

        # Check for stop request every 3 batches (~150k domains)
        if batches_since_stop_check >= 3:
            batches_since_stop_check = 0
            try:
                pending = sync_client.get_commands(host_url, api_key)
                for cmd in pending:
                    if cmd.get("command") == "stop_recheck":
                        sync_client.mark_command_done(host_url, api_key, cmd["id"], "completed", "Recheck stopped by user request")
                        log.warning("Recheck stopped by user request.")
                        sync_client.send_recheck_status(host_url, api_key, {
                            "is_running": 0,
                            "source": source,
                            "total_domains": total_domains,
                            "checked_domains": stats["domains_checked"],
                            "matches_found": len(all_matches),
                            "started_at": started_at,
                            "completed_at": datetime.now(timezone.utc).isoformat(),
                        })
                        if all_matches:
                            log.info(f"Sending {len(all_matches)} partial recheck matches to hosting...")
                            ok = sync_client.send_matches(host_url, api_key, all_matches)
                            if not ok:
                                queue_matches(db, all_matches)
                            stats["matches_found"] = len(all_matches)
                        return stats
            except Exception as e:
                log.debug(f"Could not poll stop_recheck commands: {e}")

        progress_threshold = max(total_domains // 20, 500000)
        if stats["domains_checked"] - last_progress_report >= progress_threshold:
            last_progress_report = stats["domains_checked"]
            pct = (stats["domains_checked"] / total_domains * 100) if total_domains else 0
            log.info(f"Checked {stats['domains_checked']:,} / {total_domains:,} domains ({pct:.1f}%)")
            sync_client.send_recheck_status(host_url, api_key, {
                "is_running": 1,
                "source": source,
                "total_domains": total_domains,
                "checked_domains": stats["domains_checked"],
                "matches_found": len(all_matches),
                "started_at": started_at,
                "completed_at": None,
            })

    if all_matches:
        log.info(f"Sending {len(all_matches)} recheck matches to hosting...")
        ok = sync_client.send_matches(host_url, api_key, all_matches)
        if not ok:
            queue_matches(db, all_matches)
        stats["matches_found"] = len(all_matches)
    else:
        log.info("No new matches found during recheck.")

    sync_client.send_recheck_status(host_url, api_key, {
        "is_running": 0,
        "source": source,
        "total_domains": total_domains,
        "checked_domains": stats["domains_checked"],
        "matches_found": stats["matches_found"],
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })

    log.info(f"Recheck complete. Domains checked: {stats['domains_checked']:,}, Matches: {stats['matches_found']}")
    return stats


def recheck_cctld(db: sqlite3.Connection, cfg: configparser.ConfigParser, host_url: str,
                  api_key: str, tlds: list | None = None, max_domains: int = 0,
                  keyword_ids: list | None = None) -> dict:
    """Recheck the OpenINTEL ccTLD cache (cctld_seen) against current keywords.

    `keyword_ids` limits the matching to those keyword ids (None/empty = all).
    """
    stats = {"domains_checked": 0, "matches_found": 0}
    oi_db = get_openintel_db_path(cfg)
    if not os.path.exists(oi_db):
        log.warning("OpenINTEL cache not found (%s); skipping ccTLD recheck.", oi_db)
        return stats
    try:
        import openintel
    except Exception as e:
        log.error("Could not import the openintel module: %s", e)
        return stats

    settings = openintel.load_settings()[1]
    tld_list = [str(t).lower() for t in (tlds or []) if t]
    conn = sqlite3.connect(oi_db)
    try:
        if not tld_list:
            tld_list = [r[0] for r in conn.execute("SELECT DISTINCT tld FROM cctld_seen").fetchall()]
        if not tld_list:
            return stats

        started_at = datetime.now(timezone.utc).isoformat()
        total = 0
        for t in tld_list:
            total += int(conn.execute("SELECT COUNT(*) FROM cctld_seen WHERE tld = ?", (t,)).fetchone()[0])
        if max_domains:
            total = min(total, max_domains)

        sync_client.send_recheck_status(host_url, api_key, {
            "is_running": 1, "source": "openintel", "total_domains": total,
            "checked_domains": 0, "matches_found": 0,
            "started_at": started_at, "completed_at": None,
        })

        def progress(checked, total_, matches):
            sync_client.send_recheck_status(host_url, api_key, {
                "is_running": 1, "source": "openintel", "total_domains": total_,
                "checked_domains": checked, "matches_found": matches,
                "started_at": started_at, "completed_at": None,
            })

        r = openintel.recheck_cached(conn, tld_list, host_url, api_key, settings,
                                     progress_cb=progress, max_domains=max_domains,
                                     keyword_ids=keyword_ids)
        stats["domains_checked"] = r.get("domains_checked", 0)
        stats["matches_found"] = r.get("matches_found", 0)
        sync_client.send_recheck_status(host_url, api_key, {
            "is_running": 0, "source": "openintel", "total_domains": total,
            "checked_domains": stats["domains_checked"], "matches_found": stats["matches_found"],
            "started_at": started_at, "completed_at": datetime.now(timezone.utc).isoformat(),
        })
    finally:
        conn.close()
    return stats


def perform_worker_update() -> tuple[str, str]:
    """Update the worker checkout to origin/main. Returns (message, status).

    Untracked files (config.ini, data/, zones/) are never touched. A hard reset
    is used so a deployment checkout always matches the published main branch.
    """
    repo_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        return ("This worker is not a git checkout; cannot self-update. Run update.sh on the server.", "failed")

    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"

    try:
        fetch = subprocess.run(
            ["git", "-C", repo_dir, "fetch", "--prune", "origin"],
            capture_output=True, text=True, timeout=180, env=env
        )
        if fetch.returncode != 0:
            detail = (fetch.stderr or fetch.stdout).strip()[:300]
            return (f"git fetch failed: {detail}", "failed")

        reset = subprocess.run(
            ["git", "-C", repo_dir, "reset", "--hard", "origin/main"],
            capture_output=True, text=True, timeout=180, env=env
        )
        if reset.returncode != 0:
            detail = (reset.stderr or reset.stdout).strip()[:300]
            return (f"git reset failed: {detail}", "failed")
    except Exception as e:
        return (f"Update error: {e}", "failed")

    new_version = get_version()
    return (f"Worker source updated to {new_version}. Restart required to load it.", "completed")


HASH_SEARCH_NOTE = ("Prefix/contains/glob search only covers text-cached TLDs; huge TLDs "
                    "cached as hashes (e.g. .com) are excluded. Exact search covers both.")


def _search_glob_cache(conn: sqlite3.Connection, table: str, sqlite_glob: str | None,
                       regex, limit: int, timeout: float,
                       after: str | None = None, before: str | None = None) -> tuple[list[tuple], bool]:
    """Search a (domain, tld, first_seen) table with a glob. Returns (rows, partial).

    Uses SQLite's native GLOB (C-level) when the pattern has no ``{n,m}``; a
    repetition falls back to a Python regex scan for full parity with the keyword
    matcher. Both paths are bounded by a deadline so a broad pattern cannot hang
    the worker. `table` is a fixed internal literal (never user input).

    `after`/`before` are inclusive ``YYYY-MM-DD`` dates compared against the
    discovery date; every text cache stores ``first_seen`` as ISO8601 text, so
    its first 10 characters are the date.
    """
    date_sql = ""
    date_params: list = []
    if after:
        date_sql += " AND substr(first_seen,1,10) >= ?"
        date_params.append(after)
    if before:
        date_sql += " AND substr(first_seen,1,10) <= ?"
        date_params.append(before)

    deadline = time.perf_counter() + max(1.0, float(timeout))

    if sqlite_glob is not None:
        def _progress() -> int:
            return 1 if time.perf_counter() > deadline else 0

        conn.set_progress_handler(_progress, 10000)
        try:
            # GLOB matches the whole string, so wrap the pattern to emulate the
            # unanchored substring semantics of the keyword matcher.
            rows = conn.execute(
                f"SELECT domain, tld, first_seen FROM {table} WHERE domain GLOB ?{date_sql} LIMIT ?",
                ("*" + sqlite_glob + "*", *date_params, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            return [], True
        finally:
            conn.set_progress_handler(None, 0)
        return rows, False

    # {n,m}: bounded regex scan with keyset pagination.
    rows: list[tuple] = []
    last = ""
    batch = 10000
    while len(rows) < limit:
        if time.perf_counter() > deadline:
            return rows, True
        try:
            chunk = conn.execute(
                f"SELECT domain, tld, first_seen FROM {table} WHERE domain > ?{date_sql} "
                f"ORDER BY domain LIMIT ?",
                (last, *date_params, batch),
            ).fetchall()
        except sqlite3.OperationalError:
            return rows, True
        if not chunk:
            break
        last = chunk[-1][0]
        for d, t, fs in chunk:
            if regex.search(d):
                rows.append((d, t, fs))
                if len(rows) >= limit:
                    break
    return rows, False


def get_openintel_db_path(cfg: configparser.ConfigParser) -> str:
    """Resolve the OpenINTEL local cache path from the worker config."""
    data_dir = cfg.get("openintel", "data_dir", fallback="./data/openintel")
    db_path = cfg.get("openintel", "db_path", fallback="").strip()
    return db_path or os.path.join(data_dir, "openintel.db")


def _search_text_cache(conn: sqlite3.Connection, table: str, query: str, mode: str,
                       limit: int, timeout: float) -> tuple[list[tuple], bool]:
    """Search a (domain, tld, first_seen) table. Returns (rows, partial).

    `table` is a fixed internal literal (never user input). `contains` is bounded
    by a SQLite progress handler so a full scan cannot hang the worker.
    """
    if mode == "exact":
        row = conn.execute(
            f"SELECT domain, tld, first_seen FROM {table} WHERE domain = ?", (query,)
        ).fetchone()
        return ([row] if row else []), False

    escaped = query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    pattern = escaped + "%" if mode == "prefix" else "%" + escaped + "%"
    sql = f"SELECT domain, tld, first_seen FROM {table} WHERE domain LIKE ? ESCAPE '\\' LIMIT ?"
    if mode == "contains":
        deadline = time.perf_counter() + max(1.0, float(timeout))

        def _progress() -> int:
            return 1 if time.perf_counter() > deadline else 0

        conn.set_progress_handler(_progress, 10000)
        try:
            rows = conn.execute(sql, (pattern, limit)).fetchall()
        except sqlite3.OperationalError:
            return [], True
        finally:
            conn.set_progress_handler(None, 0)
        return rows, False
    return conn.execute(sql, (pattern, limit)).fetchall(), False


def search_cached_domains(db: sqlite3.Connection, query: str, mode: str = "exact",
                          limit: int = 100, timeout: float = 5.0,
                          openintel_db_path: str | None = None,
                          after: str | None = None, before: str | None = None) -> dict:
    """Search the worker's caches and return a unified result list.

    Aggregates the CZDS gTLD cache (domains_cache + compact hash cache) and, when
    `openintel_db_path` is given, the OpenINTEL ccTLD cache (cctld_seen). Results
    carry a `source` of "zone" (CZDS) or "ct" (OpenINTEL). `contains` is bounded
    by a timeout per cache so a full scan can never hang the worker.

    For the `glob` mode, `after`/`before` (inclusive ``YYYY-MM-DD``) filter by the
    discovery date (`first_seen`).
    """
    query = (query or "").strip().lower()
    limit = max(1, min(int(limit or 100), 200))
    note = HASH_SEARCH_NOTE

    if not query:
        return {"results": [], "partial": False, "note": "Empty query."}
    if mode not in ("exact", "prefix", "contains", "glob"):
        mode = "exact"
    if mode == "contains" and len(query) < 4:
        return {"results": [], "partial": False,
                "note": "Contains search requires at least 4 characters."}

    results: list[dict] = []
    seen: set[str] = set()
    partial = False

    def _add(domain, tld, first_seen, source, **extra):
        if domain not in seen:
            seen.add(domain)
            entry = {"domain": domain, "tld": tld, "first_seen": first_seen, "source": source}
            entry.update(extra)
            results.append(entry)

    # Glob: text caches only (the hash cache stores no text). Requires a usable
    # literal anchor so a bare '*' cannot trigger a full scan of every cache.
    if mode == "glob":
        glob_rx, anchor = matcher.glob_to_regex(query)
        if len(anchor) < 3:
            return {"results": [], "partial": False,
                    "note": ("Glob search needs at least 3 literal characters "
                             "(e.g. banco*santander); a bare '*' is too broad.")}
        sqlite_glob = matcher.glob_to_sqlite(query)

        rows, p = _search_glob_cache(db, "domains_cache", sqlite_glob, glob_rx,
                                     limit, timeout, after=after, before=before)
        partial = partial or p
        for d, t, fs in rows:
            _add(d, t, fs, "zone")

        if openintel_db_path and os.path.exists(openintel_db_path):
            try:
                oi = sqlite3.connect(f"file:{openintel_db_path}?mode=ro", uri=True, timeout=10)
                try:
                    orows, p = _search_glob_cache(oi, "cctld_seen", sqlite_glob, glob_rx,
                                                  limit, timeout, after=after, before=before)
                finally:
                    oi.close()
                partial = partial or p
                for d, t, fs in orows:
                    _add(d, t, fs, "ct", ccTLD=True)
            except sqlite3.Error:
                pass

        return {"results": results[:limit], "partial": partial, "note": note}

    # CZDS text cache
    rows, p = _search_text_cache(db, "domains_cache", query, mode, limit, timeout)
    partial = partial or p
    for d, t, fs in rows:
        _add(d, t, fs, "zone")

    # CZDS compact hash cache (exact only: it stores no text)
    if mode == "exact" and query not in seen:
        hrow = db.execute(
            "SELECT tld, first_seen FROM domains_cache_hash WHERE domain_hash = ?",
            (_domain_hash(query),)
        ).fetchone()
        if hrow:
            try:
                fs = datetime.fromtimestamp(int(hrow[1]), tz=timezone.utc).isoformat()
            except (TypeError, ValueError, OSError):
                fs = None
            _add(query, hrow[0], fs, "zone", hash_cached=True)

    # OpenINTEL ccTLD cache (separate DB, read-only)
    if openintel_db_path and os.path.exists(openintel_db_path):
        try:
            oi = sqlite3.connect(f"file:{openintel_db_path}?mode=ro", uri=True, timeout=10)
            try:
                orows, p = _search_text_cache(oi, "cctld_seen", query, mode, limit, timeout)
            finally:
                oi.close()
            partial = partial or p
            for d, t, fs in orows:
                _add(d, t, fs, "ct", ccTLD=True)
        except sqlite3.Error:
            pass

    return {"results": results[:limit], "partial": partial, "note": note}


def handle_commands(db: sqlite3.Connection, cfg: configparser.ConfigParser, host_url: str, api_key: str, version: str, force: bool = False, refresh: bool = False) -> tuple[list[dict], dict | None, bool, bool]:
    """Poll and execute pending commands from the hosting.

    Returns (log entries, worker_stats, commands_processed, restart_requested).
    """
    logs = []
    worker_stats = None
    commands_processed = False
    restart_requested = False
    try:
        commands = sync_client.get_commands(host_url, api_key)
    except Exception as e:
        logs.append({"level": "error", "message": f"Failed to fetch commands: {e}"})
        return logs, worker_stats, commands_processed, restart_requested

    if not commands:
        return logs, worker_stats, commands_processed, restart_requested

    # If a stop_recheck is present in this batch, cancel any recheck_keywords
    # in the same batch to prevent a relaunch after stopping.
    has_stop = any(cmd.get("command") == "stop_recheck" for cmd in commands)
    if has_stop:
        filtered = []
        for cmd in commands:
            if cmd.get("command") == "recheck_keywords":
                try:
                    sync_client.mark_command_done(host_url, api_key, cmd["id"], "cancelled", "Cancelled by stop_recheck in same batch")
                    logs.append({"level": "warning", "message": f"Cancelled recheck command {cmd['id']} because stop_recheck was received in the same batch"})
                    commands_processed = True
                except Exception as e:
                    logs.append({"level": "error", "message": f"Failed to cancel recheck command {cmd['id']}: {e}"})
            else:
                filtered.append(cmd)
        commands = filtered

    config_path = os.path.join(os.path.dirname(__file__), "config.ini")

    for cmd in commands:
        commands_processed = True
        cmd_id = cmd["id"]
        command = cmd["command"]
        payload = cmd.get("payload", "")
        logs.append({"level": "info", "message": f"Executing command {cmd_id}: {command}"})

        try:
            status = "completed"
            # Mark as running right away so the UI can show the command in progress.
            try:
                sync_client.update_command_status(host_url, api_key, cmd_id, "running", "")
            except Exception as e:
                logs.append({"level": "warning", "message": f"Could not mark command {cmd_id} as running: {e}"})

            if command == "run_worker":
                # Payload may request a refresh (bypass daily guard, keep
                # conditional validators) or a force (full re-download).
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                cmd_force = force or bool(opts.get("force"))
                cmd_refresh = refresh or bool(opts.get("refresh"))
                mode = "force" if cmd_force else ("refresh" if cmd_refresh else "normal")
                sync_client.send_heartbeat(host_url, api_key, {
                    "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                    "is_running": 1,
                    "version": version,
                    "current_command": f"run_worker ({mode})",
                    "current_command_id": cmd_id,
                })
                worker_stats = run_worker_cycle(db, cfg, host_url, api_key, version,
                                                force=cmd_force, refresh=cmd_refresh,
                                                command_label=f"run_worker ({mode})",
                                                command_id=cmd_id)
                result = json.dumps(worker_stats)
                if worker_stats.get("error"):
                    status = "failed"
                logs.append(_cycle_summary_log(worker_stats, f"Worker cycle ({mode})"))

            elif command == "recheck_keywords":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                sources = opts.get("sources")
                if not isinstance(sources, list) or not sources:
                    # Default to the fast ccTLD cache so a quick recheck never
                    # scans the whole ICANN (CZDS) cache.
                    sources = ["openintel"]
                sources = [str(s).lower() for s in sources if str(s).lower() in ("openintel", "czds")]
                tlds = opts.get("tlds") if isinstance(opts.get("tlds"), list) else []
                # Optional subset of keywords to recheck (ids). Empty/absent = all.
                keyword_ids = None
                raw_ids = opts.get("keyword_ids")
                if isinstance(raw_ids, list):
                    parsed_ids = []
                    for v in raw_ids:
                        try:
                            parsed_ids.append(int(v))
                        except (TypeError, ValueError):
                            continue
                    if parsed_ids:
                        keyword_ids = parsed_ids
                try:
                    max_age = int(opts.get("max_age_days",
                                           cfg.getint("worker", "max_domain_age_days", fallback=30)))
                except (TypeError, ValueError):
                    max_age = 30
                try:
                    max_domains = int(opts.get("max_domains",
                                               cfg.getint("worker", "recheck_max_domains", fallback=0)))
                except (TypeError, ValueError):
                    max_domains = 0

                sync_client.send_heartbeat(host_url, api_key, {
                    "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                    "is_running": 1,
                    "version": version,
                    "current_command": "recheck_keywords",
                    "current_command_id": cmd_id,
                })

                total = {"domains_checked": 0, "matches_found": 0, "sources": sources, "tlds": tlds,
                         "keyword_ids": keyword_ids or []}
                if "openintel" in sources:
                    s = recheck_cctld(db, cfg, host_url, api_key, tlds=tlds, max_domains=max_domains,
                                      keyword_ids=keyword_ids)
                    total["domains_checked"] += int(s.get("domains_checked", 0))
                    total["matches_found"] += int(s.get("matches_found", 0))
                if "czds" in sources:
                    if not tlds and not max_domains and max_age <= 0:
                        logs.append({"level": "warning", "message":
                                     "CZDS recheck skipped: select ICANN TLDs, set a max_domains cap, "
                                     "or set a max age to bound the scan."})
                    else:
                        s = recheck_all_domains(db, host_url, api_key, max_age,
                                                tlds=tlds, max_domains=max_domains, source="czds",
                                                keyword_ids=keyword_ids)
                        total["domains_checked"] += int(s.get("domains_checked", 0))
                        total["matches_found"] += int(s.get("matches_found", 0))
                result = json.dumps(total)
                logs.append({"level": "info", "message":
                             f"Recheck done ({', '.join(sources) or 'none'}): "
                             f"{total['domains_checked']:,} domains, {total['matches_found']} matches"})

            elif command == "update_whitelist":
                if not cfg.has_section("tlds"):
                    cfg.add_section("tlds")
                cfg.set("tlds", "whitelist", payload)
                with open(config_path, "w") as f:
                    cfg.write(f)
                result = f"Whitelist updated to: {payload}"
                logs.append({"level": "info", "message": result})

            elif command == "update_worker":
                result, status = perform_worker_update()
                logs.append({"level": "info" if status == "completed" else "error", "message": result})
                if status == "completed":
                    restart_requested = True

            elif command == "whois_lookup":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                domains = opts.get("domains")
                if not domains and opts.get("domain"):
                    domains = [opts["domain"]]
                if not isinstance(domains, list):
                    domains = []
                domains = [str(d).lower().strip() for d in domains if d][:200]
                data_dir = cfg.get("worker", "data_dir", fallback="./data")
                entries = whois_lookup_entries(cfg, data_dir, domains)
                ok = sync_client.send_whois_results(host_url, api_key, entries)
                result = json.dumps({"requested": len(domains), "looked_up": len(entries), "sent": ok})
                logs.append({"level": "info", "message": f"WHOIS lookup: {len(entries)} domain(s), sent={ok}"})
                if not ok:
                    status = "failed"

            elif command == "vt_lookup":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                domains = opts.get("domains")
                if not isinstance(domains, list):
                    domains = []
                domains = [str(d).lower().strip() for d in domains if d][:200]

                if cfg.has_section("virustotal"):
                    vt_key = cfg.get("virustotal", "api_key", fallback="").strip()
                    vt_rate = cfg.getfloat("virustotal", "rate_delay_seconds", fallback=16.0)
                    vt_daily = cfg.getint("virustotal", "daily_limit", fallback=500)
                    vt_timeout = cfg.getint("virustotal", "timeout", fallback=20)
                else:
                    vt_key, vt_rate, vt_daily, vt_timeout = "", 16.0, 500, 20

                if not vt_key or vt_key.upper().startswith("TU_"):
                    result = "VirusTotal API key not configured ([virustotal] api_key)."
                    status = "failed"
                    logs.append({"level": "error", "message": result})
                else:
                    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    row = db.execute("SELECT count FROM vt_usage WHERE day = ?", (today,)).fetchone()
                    used = int(row[0]) if row else 0
                    remaining = max(0, vt_daily - used)
                    if remaining <= 0:
                        result = f"VirusTotal daily limit reached ({vt_daily}). Try again tomorrow."
                        status = "failed"
                        logs.append({"level": "warning", "message": result})
                    else:
                        batch = domains[:remaining]
                        entries = []
                        quota_hit = False
                        for d in batch:
                            try:
                                entries.append(virustotal.lookup_domain(d, vt_key, timeout=vt_timeout))
                            except virustotal.QuotaError:
                                quota_hit = True
                                break
                            if vt_rate > 0:
                                time.sleep(vt_rate)
                        db.execute("INSERT OR REPLACE INTO vt_usage (day, count) VALUES (?, ?)",
                                   (today, used + len(entries)))
                        db.commit()
                        ok = sync_client.send_vt_results(host_url, api_key, entries)
                        result = json.dumps({
                            "requested": len(domains), "looked_up": len(entries), "sent": ok,
                            "quota_hit": quota_hit, "remaining_today": max(0, vt_daily - (used + len(entries))),
                        })
                        logs.append({"level": "info", "message":
                                     f"VirusTotal lookup: {len(entries)} domain(s), sent={ok}"
                                     + (" [quota reached]" if quota_hit else "")})
                        if not ok:
                            status = "failed"

            elif command == "abusech_lookup":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                domains = opts.get("domains")
                if not isinstance(domains, list):
                    domains = []
                domains = [str(d).lower().strip() for d in domains if d][:200]

                if cfg.has_section("abusech"):
                    abuse_key = cfg.get("abusech", "auth_key", fallback="").strip()
                    abuse_rate = cfg.getfloat("abusech", "rate_delay_seconds", fallback=1.0)
                    abuse_daily = cfg.getint("abusech", "daily_limit", fallback=10000)
                    abuse_timeout = cfg.getint("abusech", "timeout", fallback=20)
                    abuse_urlhaus = cfg.getboolean("abusech", "urlhaus_enabled", fallback=True)
                    abuse_tf = cfg.getboolean("abusech", "threatfox_enabled", fallback=True)
                else:
                    abuse_key, abuse_rate, abuse_daily, abuse_timeout, abuse_urlhaus, abuse_tf = "", 1.0, 10000, 20, True, True

                if not abuse_key or abuse_key.upper().startswith("TU_"):
                    result = "abuse.ch Auth-Key not configured ([abusech] auth_key)."
                    status = "failed"
                    logs.append({"level": "error", "message": result})
                else:
                    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                    row = db.execute("SELECT count FROM abusech_usage WHERE day = ?", (today,)).fetchone()
                    used = int(row[0]) if row else 0
                    remaining = max(0, abuse_daily - used)
                    if remaining <= 0:
                        result = f"abuse.ch daily limit reached ({abuse_daily}). Try again tomorrow."
                        status = "failed"
                        logs.append({"level": "warning", "message": result})
                    else:
                        batch = domains[:remaining]
                        entries = []
                        quota_hit = False
                        auth_error = None
                        for d in batch:
                            try:
                                entries.append(abusech.lookup_domain(
                                    d, abuse_key, timeout=abuse_timeout,
                                    urlhaus_enabled=abuse_urlhaus, threatfox_enabled=abuse_tf))
                            except abusech.AuthError as e:
                                # Bad/unknown key: record an error entry for this domain so
                                # the UI shows the failure instead of a stale verdict.
                                auth_error = str(e)[:200]
                                entries.append(abusech.error_result(d, auth_error))
                                break
                            except abusech.QuotaError:
                                quota_hit = True
                                break
                            if abuse_rate > 0:
                                time.sleep(abuse_rate)
                        db.execute("INSERT OR REPLACE INTO abusech_usage (day, count) VALUES (?, ?)",
                                   (today, used + len(entries)))
                        db.commit()
                        ok = sync_client.send_abusech_results(host_url, api_key, entries)
                        result = json.dumps({
                            "requested": len(domains), "looked_up": len(entries), "sent": ok,
                            "quota_hit": quota_hit, "auth_error": auth_error,
                            "remaining_today": max(0, abuse_daily - (used + len(entries))),
                        })
                        if auth_error:
                            status = "failed"
                            logs.append({"level": "error", "message":
                                         f"abuse.ch authentication failed: {auth_error}. Check [abusech] auth_key."})
                        else:
                            logs.append({"level": "info", "message":
                                         f"abuse.ch lookup: {len(entries)} domain(s), sent={ok}"
                                         + (" [quota reached]" if quota_hit else "")})
                            if not ok:
                                status = "failed"

            elif command == "cf_scan_lookup":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                domains = opts.get("domains")
                if not domains and opts.get("domain"):
                    domains = [opts["domain"]]
                if not isinstance(domains, list):
                    domains = []
                domains = [str(d).lower().strip() for d in domains if d][:50]

                cf = _cf_config(cfg)
                if not cf.get("urlscanner_token") or not cf.get("account_id"):
                    result = "Cloudflare URL Scanner not configured ([cloudflare] urlscanner_token/account_id)."
                    status = "failed"
                    logs.append({"level": "error", "message": result})
                else:
                    stats = run_cfscan_batch(cfg, db, host_url, api_key, domains)
                    result = json.dumps(stats)
                    if stats.get("error"):
                        status = "failed"
                        logs.append({"level": "error", "message":
                                     f"Cloudflare scan: {stats['error']}"})
                    else:
                        logs.append({"level": "info", "message":
                                     f"Cloudflare scan: {stats['scanned']} domain(s), "
                                     f"{stats['errors']} error(s)"})

            elif command == "cf_dns_lookup":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                domains = opts.get("domains")
                if not domains and opts.get("domain"):
                    domains = [opts["domain"]]
                if not isinstance(domains, list):
                    domains = []
                domains = [str(d).lower().strip() for d in domains if d][:200]

                cf = _cf_config(cfg)
                if not cf.get("enabled") or not cf.get("api_token"):
                    result = "Cloudflare Radar not configured ([cloudflare] api_token)."
                    status = "failed"
                    logs.append({"level": "error", "message": result})
                else:
                    stats = run_cfdns_batch(cfg, db, host_url, api_key, domains)
                    result = json.dumps(stats)
                    if stats.get("error"):
                        status = "failed"
                        logs.append({"level": "error", "message":
                                     f"Cloudflare DNS: {stats['error']}"})
                    else:
                        logs.append({"level": "info", "message":
                                     f"Cloudflare DNS: {stats['checked']} domain(s), "
                                     f"{stats['errors']} error(s)"})

            elif command == "tracking_check":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                domains = opts.get("domains")
                if not isinstance(domains, list) or not domains:
                    domains = None
                domains = [str(d).lower().strip() for d in (domains or []) if str(d).strip()][:200] or None
                try:
                    tstats = run_tracking_check(cfg, db, host_url, api_key, domains=domains)
                    result = json.dumps(tstats)
                    logs.append({"level": "info", "message":
                                 f"Intelligence tracking: {tstats['checked']} checked, {tstats['activated']} activated"})
                    if tstats["checked"] and not tstats["sent"]:
                        status = "failed"
                except Exception as e:
                    result = f"tracking_check failed: {e}"
                    status = "failed"
                    logs.append({"level": "error", "message": result})

            elif command == "search_domain":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                q = str(opts.get("q", "")).strip().lower()
                mode = str(opts.get("mode", "exact"))
                after = str(opts.get("after", "")).strip() or None
                before = str(opts.get("before", "")).strip() or None
                try:
                    limit = int(opts.get("limit", 100) or 100)
                except (TypeError, ValueError):
                    limit = 100
                search_result = search_cached_domains(
                    db, q, mode=mode, limit=limit, after=after, before=before,
                    openintel_db_path=get_openintel_db_path(cfg))
                result = json.dumps(search_result)
                logs.append({"level": "info", "message":
                             f"Domain search '{q}' ({mode}): {len(search_result['results'])} result(s)"
                             + (" [partial]" if search_result.get("partial") else "")})

            elif command == "run_openintel":
                # Launch the OpenINTEL ccTLD importer as a detached background
                # process so this long (weekly) job never blocks the daemon.
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                tlds = opts.get("tlds")
                script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "openintel.py")
                if not os.path.exists(script):
                    result = "openintel.py not found; update the worker."
                    status = "failed"
                    logs.append({"level": "error", "message": result})
                else:
                    data_dir = cfg.get("worker", "data_dir", fallback="./data")
                    log_dir = os.path.join(data_dir, "openintel", "logs")
                    os.makedirs(log_dir, exist_ok=True)
                    out_path = os.path.join(
                        log_dir, "run-" + datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S") + ".log")
                    cmd = [sys.executable, script]
                    if isinstance(tlds, list) and tlds:
                        cmd += ["--tlds", ",".join(str(t).lower() for t in tlds if t)]
                    if opts.get("recheck"):
                        cmd.append("--recheck")
                    cmd += ["--command-id", str(cmd_id)]
                    try:
                        with open(out_path, "a", encoding="utf-8") as out:
                            subprocess.Popen(cmd, cwd=os.path.dirname(script),
                                             stdout=out, stderr=out, start_new_session=True)
                        result = json.dumps({"started": True, "tlds": tlds or "config",
                                             "recheck": bool(opts.get("recheck"))})
                        # Keep the command 'running': the detached child reports
                        # progress and marks it completed/failed when it ends.
                        status = "running"
                        logs.append({"level": "info", "message":
                                     f"OpenINTEL run started in background ({', '.join(tlds) if tlds else 'config TLDs'})."})
                    except Exception as e:
                        result = f"Failed to start OpenINTEL import: {e}"
                        status = "failed"
                        logs.append({"level": "error", "message": result})

            elif command == "stop_recheck":
                result = "Stop recheck command acknowledged. If a recheck is running it will stop at the next batch boundary."
                logs.append({"level": "info", "message": result})

            else:
                result = f"Unknown command: {command}"
                logs.append({"level": "warning", "message": result})

            try:
                sync_client.mark_command_done(host_url, api_key, cmd_id, status, result)
                logs.append({"level": "info", "message": f"Command {cmd_id} marked as {status}"})
            except Exception as e:
                # A failed status update must not abort the daemon loop; the
                # startup recovery will close any command left 'running'.
                logs.append({"level": "error", "message": f"Could not mark command {cmd_id} as {status}: {e}"})

        except Exception as e:
            error_msg = str(e)
            logs.append({"level": "error", "message": f"Command {cmd_id} failed: {error_msg}"})
            try:
                sync_client.mark_command_done(host_url, api_key, cmd_id, "failed", error_msg)
            except Exception as e2:
                logs.append({"level": "error", "message": f"Could not mark command {cmd_id} as failed: {e2}"})

        # Stop processing further commands so we can restart cleanly with the
        # freshly pulled code (systemd `Restart=always` relaunches the service).
        if restart_requested:
            logs.append({"level": "info", "message": "Worker update applied; restarting to load the new code."})
            break

    return logs, worker_stats, commands_processed, restart_requested


def get_version() -> str:
    version_path = os.path.join(os.path.dirname(__file__), "..", "VERSION")
    if os.path.exists(version_path):
        with open(version_path, "r") as f:
            return f.read().strip()
    return "unknown"


def get_last_run(db: sqlite3.Connection) -> str | None:
    cursor = db.cursor()
    cursor.execute("SELECT value FROM config WHERE key = 'last_run'")
    row = cursor.fetchone()
    return row[0] if row else None


def set_last_run(db: sqlite3.Connection) -> None:
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.cursor()
    cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('last_run', ?)", (now,))
    db.commit()


def get_daily_attempt(db: sqlite3.Connection) -> str | None:
    """Local date (YYYY-MM-DD) of the last automatic daily attempt, if any."""
    cursor = db.cursor()
    cursor.execute("SELECT value FROM config WHERE key = 'last_daily_attempt'")
    row = cursor.fetchone()
    return row[0] if row else None


def set_daily_attempt(db: sqlite3.Connection, day: str) -> None:
    cursor = db.cursor()
    cursor.execute("INSERT OR REPLACE INTO config (key, value) VALUES ('last_daily_attempt', ?)", (day,))
    db.commit()


def resolve_daily_schedule(cfg: configparser.ConfigParser):
    """Resolve the automatic daily cycle settings.

    Returns (enabled, hour, minute, tzinfo). Defaults to 04:00 Europe/Madrid.
    """
    enabled = cfg.getboolean("worker", "auto_daily", fallback=True)
    time_str = (cfg.get("worker", "daily_run_time", fallback="04:00") or "04:00").strip()
    tz_name = (cfg.get("worker", "daily_run_timezone", fallback="Europe/Madrid") or "Europe/Madrid").strip()
    tz = timezone.utc
    if ZoneInfo is not None:
        try:
            tz = ZoneInfo(tz_name)
        except Exception:
            log.warning("Unknown daily_run_timezone '%s'; using UTC.", tz_name)
    else:
        log.warning("zoneinfo is not available (Python < 3.9?); using UTC for the daily schedule.")
    try:
        hour, minute = (int(part) for part in time_str.split(":")[:2])
        if not (0 <= hour < 24 and 0 <= minute < 60):
            raise ValueError(time_str)
    except Exception:
        log.warning("Invalid daily_run_time '%s'; using 04:00.", time_str)
        hour, minute = 4, 0
    return enabled, hour, minute, tz


def daily_cycle_due(cfg: configparser.ConfigParser, db: sqlite3.Connection) -> tuple[bool, str, object]:
    """Decide whether the daemon must run the automatic daily cycle now.

    Returns (due, local_date, tzinfo). It is due once per local day, after the
    configured time, until an attempt is recorded (even if the run fails, so a
    broken ICANN token does not cause a hot retry loop).
    """
    enabled, hour, minute, tz = resolve_daily_schedule(cfg)
    if not enabled:
        return False, "", tz
    now_local = datetime.now(tz)
    today = now_local.strftime("%Y-%m-%d")
    if (now_local.hour, now_local.minute) < (hour, minute):
        return False, today, tz
    return get_daily_attempt(db) != today, today, tz


def acquire_worker_lock(data_dir: str):
    """Acquire an exclusive, non-blocking lock so two worker runs never overlap.

    Returns the open file handle on success, or None if another run holds it.
    On platforms without fcntl (e.g. Windows dev machines) locking is skipped.
    """
    os.makedirs(data_dir, exist_ok=True)
    lock_path = os.path.join(data_dir, "worker.lock")
    handle = open(lock_path, "w")
    if fcntl is None:
        return handle
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        handle.close()
        return None
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def release_worker_lock(handle) -> None:
    if handle is None:
        return
    if fcntl is not None:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        except OSError:
            pass
    handle.close()


def reap_children() -> None:
    """Reap finished detached children (e.g. the OpenINTEL importer).

    The OpenINTEL job is launched with subprocess.Popen and never waited on, so
    without this its process would stay as a zombie until the daemon exits.
    """
    try:
        while True:
            pid, _status = os.waitpid(-1, os.WNOHANG)
            if pid == 0:
                break
    except ChildProcessError:
        pass
    except OSError:
        pass


def main() -> int:
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    parser_args = argparse.ArgumentParser(description="ThreatIntelligence-TDL Worker")
    parser_args.add_argument("--daemon", action="store_true", help="Run in daemon mode with command polling")
    parser_args.add_argument("--interval", type=int, default=None,
                             help="Polling interval in seconds (daemon mode); overrides [worker] poll_interval")
    parser_args.add_argument("--once", action="store_true", help="Run one worker cycle and exit (legacy)")
    parser_args.add_argument("--status", action="store_true", help="Show last run status and exit")
    parser_args.add_argument("--force", action="store_true",
                             help="Ignore the daily guard and conditional cache, reprocessing all TLDs")
    parser_args.add_argument("--refresh", action="store_true",
                             help="Bypass the daily guard but keep conditional validators (download only if changed)")
    args = parser_args.parse_args()

    config_path = os.path.join(os.path.dirname(__file__), "config.ini")
    if not os.path.exists(config_path):
        print(f"[-] Config file not found: {config_path}")
        print("    Copy config.ini.example to config.ini and fill in your credentials.")
        return 1

    cfg = configparser.ConfigParser()
    cfg.read(config_path)

    host_url = cfg.get("hosting", "url").rstrip("/")
    api_key = cfg.get("hosting", "api_key")
    data_dir = cfg.get("worker", "data_dir", fallback="./data")
    poll_interval = args.interval if args.interval is not None else cfg.getint("worker", "poll_interval", fallback=20)
    version = get_version()

    # Setup logging with 90-day rotation
    log = logger.setup_logger(os.path.join(data_dir, "logs"))

    if api_key == "TU_API_KEY":
        log.error("Please edit config.ini with real credentials.")
        return 1

    db_path = os.path.join(data_dir, "worker.db")
    cache_mb = cfg.getint("worker", "sqlite_cache_mb", fallback=2048)
    db = init_local_db(db_path, cache_mb=cache_mb)
    log.info(f"SQLite page cache: {max(int(cache_mb), 1)} MB")

    last_run = get_last_run(db)
    if last_run:
        log.info(f"Last run: {last_run}")
    else:
        log.info("No previous run recorded locally.")

    if args.status:
        db.close()
        return 0

    lock_handle = acquire_worker_lock(data_dir)
    if lock_handle is None:
        log.warning("Another worker instance is already running. Exiting to avoid overlapping runs.")
        print("[!] Another worker instance is already running. Exiting.")
        db.close()
        return 0
    log.info(f"Worker lock acquired (pid {os.getpid()}).")

    # Close commands left in 'running' by a previous crash/restart so they do
    # not hang forever in the UI (get_commands only returns 'pending').
    try:
        stale = sync_client.get_running_commands(host_url, api_key)
        for cmd in stale:
            try:
                sync_client.mark_command_done(host_url, api_key, cmd["id"], "failed",
                                              "Worker restarted while the command was running")
                log.warning(f"Closed orphaned running command {cmd['id']} ({cmd.get('command')}).")
            except Exception as e:
                log.error(f"Failed to close orphaned command {cmd['id']}: {e}")
    except Exception as e:
        log.debug(f"Could not recover running commands: {e}")

    if args.daemon:
        log.info(f"Daemon mode started. Polling every {poll_interval}s. Press Ctrl+C to stop.")
        restart_requested = False
        try:
            while True:
                logs = []
                worker_stats = None
                try:
                    cmd_logs, worker_stats, _, restart_requested = handle_commands(db, cfg, host_url, api_key, version,
                                                                                   force=args.force, refresh=args.refresh)
                    logs.extend(cmd_logs)

                    # Automatic daily cycle (e.g. 04:00 Europe/Madrid). Runs at
                    # most once per local day; the daily guard still skips TLDs
                    # already processed today.
                    if worker_stats is None:
                        due, today, _tz = daily_cycle_due(cfg, db)
                        if due:
                            log.info("Automatic daily cycle triggered (scheduled).")
                            set_daily_attempt(db, today)
                            worker_stats = run_worker_cycle(db, cfg, host_url, api_key, version,
                                                            force=args.force, refresh=args.refresh,
                                                            command_label="auto-daily")
                            logs.append(_cycle_summary_log(worker_stats, "Scheduled daily cycle"))

                    # Intelligence weekly pass (Sunday night by default,
                    # independent of the heavy daily TLD cycle).
                    try:
                        due_w, week_key, _wtz = weekly_tracking_due(cfg, db)
                        if due_w:
                            set_weekly_attempt(db, week_key)
                            tstats = run_tracking_check(cfg, db, host_url, api_key)
                            if tstats["checked"]:
                                logs.append({"level": "info", "message":
                                             f"Intelligence tracking: {tstats['checked']} checked, "
                                             f"{tstats['activated']} activated"})
                    except Exception as e:
                        log.error(f"Tracking pass error: {e}")

                    heartbeat_payload = {
                        "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                        "is_running": 0,
                        "version": version,
                    }
                    if worker_stats:
                        heartbeat_payload["last_run"] = worker_stats.get("timestamp")
                        heartbeat_payload["tlds_processed"] = worker_stats["tlds_processed"]
                        heartbeat_payload["domains_processed"] = worker_stats["domains_processed"]
                        heartbeat_payload["matches_found"] = worker_stats["matches_found"]

                    sync_client.send_heartbeat(host_url, api_key, heartbeat_payload)

                    if logs:
                        sync_client.send_logs(host_url, api_key, logs)

                except Exception as e:
                    log.error(f"Daemon loop error: {e}")

                reap_children()

                if restart_requested:
                    log.info("Worker updated on disk; exiting so systemd restarts it with the new code.")
                    break

                time.sleep(poll_interval)
        except KeyboardInterrupt:
            log.info("Daemon mode stopped by user.")
    else:
        # One-shot mode: process commands first, then run worker cycle if nothing was processed
        logs, worker_stats, commands_processed, restart_requested = handle_commands(db, cfg, host_url, api_key, version,
                                                                                    force=args.force, refresh=args.refresh)

        if not commands_processed and not worker_stats:
            # No commands pending → legacy cron behavior: run full cycle
            worker_stats = run_worker_cycle(db, cfg, host_url, api_key, version,
                                            force=args.force, refresh=args.refresh)
            logs.append(_cycle_summary_log(worker_stats, "Worker cycle"))

        # Intelligence weekly pass (Sunday night by default).
        try:
            due_w, week_key, _wtz = weekly_tracking_due(cfg, db)
            if due_w:
                set_weekly_attempt(db, week_key)
                run_tracking_check(cfg, db, host_url, api_key)
        except Exception as e:
            log.error(f"Tracking pass error: {e}")

        heartbeat_payload = {
            "last_run": datetime.now(timezone.utc).isoformat(),
            "is_running": 0,
            "version": version,
        }
        if worker_stats:
            heartbeat_payload["tlds_processed"] = worker_stats["tlds_processed"]
            heartbeat_payload["domains_processed"] = worker_stats["domains_processed"]
            heartbeat_payload["matches_found"] = worker_stats["matches_found"]

        sync_client.send_heartbeat(host_url, api_key, heartbeat_payload)
        if logs:
            sync_client.send_logs(host_url, api_key, logs)

        if restart_requested:
            log.info("Worker updated on disk; cron mode will use the new code on the next run.")

    reap_children()
    release_worker_lock(lock_handle)
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
