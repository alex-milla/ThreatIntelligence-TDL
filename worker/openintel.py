#!/usr/bin/env python3
"""OpenINTEL ccTLD weekly importer (independent from the CZDS worker).

Downloads the latest weekly ccTLD apex-domain lists published by OpenINTEL,
diffs them against a local seen-set, matches the new domains against the user
keywords fetched from the hosting API, optionally confirms the WHOIS/RDAP
creation date, and sends the matches to the web UI.

Data: https://www.openintel.nl/data/domain-lists/cctld-names/
License: CC BY-NC-SA 4.0 (non-commercial, attribution required).

The research leading to these results was made possible by OpenINTEL
(https://www.openintel.nl/), a joint project of the University of Twente,
SIDN, NLnet Labs and SURF.

This module uses its own SQLite database (data/openintel.db by default) so it
never competes with the CZDS worker database for writes.
"""

import argparse
import configparser
import gzip
import logging
import os
import re
import shutil
import sqlite3
import sys
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urljoin

try:
    import fcntl
except ImportError:  # pragma: no cover - Linux workers only
    fcntl = None

import requests

WORKER_DIR = os.path.dirname(os.path.abspath(__file__))
if WORKER_DIR not in sys.path:
    sys.path.insert(0, WORKER_DIR)

import logger  # noqa: E402
import matcher  # noqa: E402
import sync_client  # noqa: E402
import whois  # noqa: E402

log = logging.getLogger("tdl_worker")

BASE_URL = "https://www.openintel.nl/download/domain-lists/cctlds"
SITE = "https://www.openintel.nl"
COOKIES = {"openintel-data-agreement-accepted": "true"}
ATTRIBUTION = ("The research leading to these results was made possible by OpenINTEL "
               "(https://www.openintel.nl/), a joint project of the University of Twente, "
               "SIDN, NLnet Labs and SURF.")

OK_STATUSES = ("updated", "unchanged", "baselined")
BATCH_SIZE = 50000


def _abspath(path: str) -> str:
    return path if os.path.isabs(path) else os.path.join(WORKER_DIR, path)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_date(value) -> datetime | None:
    """Best-effort parse of a WHOIS/RDAP date into an aware UTC datetime."""
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _version_key(name: str):
    return [int(p) if p.isdigit() else p for p in re.split(r"(\d+)", name)]


def init_db(db_path: str) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS cctld_seen (
            domain TEXT PRIMARY KEY,
            tld TEXT NOT NULL,
            first_seen TEXT NOT NULL
        ) WITHOUT ROWID;
        CREATE INDEX IF NOT EXISTS idx_cctld_seen_tld ON cctld_seen(tld);

        CREATE TABLE IF NOT EXISTS cctld_runs (
            tld TEXT PRIMARY KEY,
            last_file TEXT,
            last_run TEXT,
            status TEXT,
            records_total INTEGER DEFAULT 0,
            records_new INTEGER DEFAULT 0,
            last_error TEXT
        );
    """)
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS oi_batch (domain TEXT PRIMARY KEY)")
    conn.commit()
    return conn


def acquire_lock(data_dir: str):
    """Exclusive, non-blocking lock so two imports never run at once."""
    os.makedirs(data_dir, exist_ok=True)
    handle = open(os.path.join(data_dir, "openintel.lock"), "w")
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


def release_lock(handle) -> None:
    if handle is None:
        return
    if fcntl is not None:
        try:
            fcntl.flock(handle, fcntl.LOCK_UN)
        except OSError:
            pass
    handle.close()


# --------------------------------------------------------------------------
# OpenINTEL index / download
# --------------------------------------------------------------------------

def _links(session: requests.Session, url: str, sleep_http: float) -> list[str]:
    """GET a page (accepting the terms cookie and following redirects) and
    return its hrefs absolutized against the final URL."""
    r = session.get(url, timeout=60, cookies=COOKIES, allow_redirects=True)
    r.raise_for_status()
    time.sleep(max(0.0, sleep_http))
    links: list[str] = []
    for href in re.findall(r'''href=["']([^"']+)["']''', r.text):
        if href.startswith(("#", "javascript:", "mailto:", "data:")):
            continue
        links.append(urljoin(r.url, href))
    return links


def _file_links(links: list[str]) -> list[str]:
    """Keep data-file links (OpenINTEL serves .csv.gz; parquet/zip also accepted)."""
    return [u for u in links if re.search(
        r"\.(csv\.gz|csv|parquet\.gz|parquet|json\.gz|txt\.gz|gz|zip)$",
        unquote(u), re.IGNORECASE)]


def _pick(files: list[str], index: int) -> dict | None:
    files = sorted(files, key=lambda u: _version_key(os.path.basename(unquote(u))))
    if len(files) <= index:
        return None
    target = files[-(index + 1)]
    return {"url": target, "filename": os.path.basename(unquote(target))}


def _find_tld_link(session: requests.Session, tld: str, sleep_http: float) -> str | None:
    """Locate the TLD directory link in the root index (encoding-agnostic)."""
    want = f"tld={tld.lower()}"
    for link in _links(session, f"{BASE_URL}/", sleep_http):
        segment = unquote(link).rstrip("/").rsplit("/", 1)[-1].lower()
        if segment == want:
            return link
    return None


def resolve_latest(session: requests.Session, tld: str, index: int,
                   sleep_http: float) -> dict | None:
    """Return the {index}-th most recent weekly file for a TLD (0 = latest).

    Navigates the real index links (which use unencoded '=', e.g.
    ``tld=io/year=2026/month=09``) instead of constructing URLs, so it is robust
    to encoding changes and redirects (``tld=io`` -> ``tld%3Dio/``).
    """
    tld = tld.lower()
    tld_url = _find_tld_link(session, tld, sleep_http) or f"{BASE_URL}/tld={tld}"
    tld_links = _links(session, tld_url, sleep_http)

    years: dict[str, str] = {}
    for link in tld_links:
        m = re.search(r"year(?:%3D|=)(\d{4})", unquote(link), re.IGNORECASE)
        if m:
            years.setdefault(m.group(1), link)

    if not years:
        # Some layouts list files directly under the TLD.
        files = _file_links(tld_links)
        found = _pick(files, index)
        if found:
            return found
        log.warning("OpenINTEL .%s: no year links found (%d links on the TLD page)",
                    tld, len(tld_links))
        return None

    collected: list[str] = []
    for year in sorted(years, reverse=True):
        year_links = _links(session, years[year], sleep_http)
        months: dict[str, str] = {}
        for link in year_links:
            m = re.search(r"month(?:%3D|=)(\d{2})", unquote(link), re.IGNORECASE)
            if m:
                months.setdefault(m.group(1), link)
        if not months:
            collected = _file_links(year_links) + collected
            if len(collected) > index:
                break
            continue
        for month in sorted(months, reverse=True):
            month_links = _links(session, months[month], sleep_http)
            files = _file_links(month_links)
            if not files:
                # The month level holds day=NN directories with the files inside.
                days: dict[str, str] = {}
                for link in month_links:
                    m = re.search(r"day(?:%3D|=)(\d{2})", unquote(link), re.IGNORECASE)
                    if m:
                        days.setdefault(m.group(1), link)
                for day in sorted(days, reverse=True):
                    files.extend(_file_links(_links(session, days[day], sleep_http)))
                    if len(collected) + len(files) > index:
                        break
            collected = files + collected
            if len(collected) > index:
                break
        if len(collected) > index:
            break

    found = _pick(collected, index)
    if not found:
        log.warning("OpenINTEL .%s: fewer than %d weekly file(s) found (%d)",
                    tld, index + 1, len(collected))
    return found


def download_file(session: requests.Session, url: str, dest: str,
                  sleep_between: float, retries: int = 3) -> bool:
    """Resumable download to `dest` (uses a .part file, renamed on success)."""
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    part = dest + ".part"
    for attempt in range(1, retries + 1):
        try:
            existing = os.path.getsize(part) if os.path.exists(part) else 0
            headers = {"Range": f"bytes={existing}-"} if existing else {}
            mode = "ab"
            with session.get(url, headers=headers, stream=True, timeout=180,
                             cookies=COOKIES) as r:
                if existing and r.status_code == 200:
                    existing = 0
                    mode = "wb"
                elif existing and r.status_code == 206:
                    mode = "ab"
                else:
                    r.raise_for_status()
                    mode = "wb"
                remaining = int(r.headers.get("Content-Length") or 0)
                written = 0
                with open(part, mode) as fh:
                    for chunk in r.iter_content(1 << 20):
                        if chunk:
                            fh.write(chunk)
                            written += len(chunk)
            if remaining and written != remaining:
                raise IOError(f"incomplete download ({written}/{remaining} bytes)")
            os.replace(part, dest)
            return True
        except (requests.RequestException, IOError, OSError) as e:
            log.warning("Download attempt %s/%s failed: %s", attempt, retries, e)
            time.sleep(5 * attempt)
    return False


# --------------------------------------------------------------------------
# Domain list reading (OpenINTEL serves .csv.gz; parquet is also supported)
# --------------------------------------------------------------------------

def _parquet_source(path: str):
    """Return (path_to_read, temp_path_to_delete). Handles an outer gzip wrapper."""
    with open(path, "rb") as fh:
        wrapped = fh.read(2) == b"\x1f\x8b"
    if not wrapped:
        return path, None
    tmp = path + ".inner.parquet"
    with gzip.open(path, "rb") as src, open(tmp, "wb") as dst:
        shutil.copyfileobj(src, dst, 1 << 20)
    return tmp, tmp


def _read_parquet(path: str, batch_size: int = BATCH_SIZE):
    import pyarrow.parquet as pq  # optional dependency, only for parquet datasets

    source, tmp = _parquet_source(path)
    try:
        pf = pq.ParquetFile(source)
        column = pf.schema_arrow.names[0]
        for batch in pf.iter_batches(batch_size=batch_size, columns=[column]):
            for value in batch.column(0).to_pylist():
                if value is None:
                    continue
                domain = str(value).strip().lower().rstrip(".")
                if domain:
                    yield domain
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)


def _is_gzip(path: str) -> bool:
    with open(path, "rb") as fh:
        return fh.read(2) == b"\x1f\x8b"


def _read_text_domains(path: str):
    """Yield domains from a plain or gzipped text/CSV file (one per line).

    OpenINTEL ccTLD lists are ``ccTLD-domain-names-list.<tld>.<date>.csv.gz``
    without a header; if a row has extra columns, the first one is used.
    """
    opener = gzip.open if _is_gzip(path) else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            field = re.split(r"[,\t;]", line, 1)[0].strip().strip('"').lower().rstrip(".")
            if field and (field != "domain"):  # tolerate a 'domain' header
                yield field


def read_domains(path: str, batch_size: int = BATCH_SIZE):
    """Yield lowercased apex domains from an OpenINTEL data file.

    Parses parquet (optionally gzipped) when the file is parquet, and the
    CSV/text format otherwise. The ccTLD name lists are CSV gzip, so pyarrow is
    not required for them.
    """
    lower = path.lower()
    if lower.endswith((".parquet", ".parquet.gz")):
        return _read_parquet(path, batch_size)
    return _read_text_domains(path)


# --------------------------------------------------------------------------
# Diff / baseline
# --------------------------------------------------------------------------

def _stage_batch(conn, cursor, tld: str, batch: list[str], emit: bool,
                 keyword_matcher, matches: list[dict], now: str) -> int:
    cursor.execute("DELETE FROM oi_batch")
    cursor.executemany("INSERT OR IGNORE INTO oi_batch (domain) VALUES (?)",
                       ((d,) for d in batch))
    cursor.execute(
        "SELECT z.domain FROM oi_batch z "
        "LEFT JOIN cctld_seen c ON c.domain = z.domain "
        "WHERE c.domain IS NULL"
    )
    new_domains = [row[0] for row in cursor.fetchall()]
    if not new_domains:
        return 0
    cursor.executemany(
        "INSERT OR IGNORE INTO cctld_seen (domain, tld, first_seen) VALUES (?, ?, ?)",
        ((d, tld, now) for d in new_domains)
    )
    if emit and keyword_matcher is not None:
        matches.extend(keyword_matcher.match(new_domains))
    return len(new_domains)


def process_domains(conn: sqlite3.Connection, tld: str, domains, emit: bool,
                    keyword_matcher, matches: list[dict]) -> tuple[int, int]:
    """Cache all domains; return (total, new). Emit matches only when asked."""
    cursor = conn.cursor()
    now = _now()
    total = 0
    new_count = 0
    batch: list[str] = []
    for domain in domains:
        total += 1
        batch.append(domain)
        if len(batch) >= BATCH_SIZE:
            new_count += _stage_batch(conn, cursor, tld, batch, emit, keyword_matcher, matches, now)
            batch = []
    if batch:
        new_count += _stage_batch(conn, cursor, tld, batch, emit, keyword_matcher, matches, now)
    conn.commit()
    return total, new_count


def tld_baselined(conn: sqlite3.Connection, tld: str) -> bool:
    row = conn.execute("SELECT 1 FROM cctld_runs WHERE tld = ?", (tld,)).fetchone()
    return row is not None


def record_run(conn: sqlite3.Connection, tld: str, filename: str | None, status: str,
               total: int, new_count: int, error: str | None = None) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO cctld_runs "
        "(tld, last_file, last_run, status, records_total, records_new, last_error) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (tld, filename, _now(), status, total, new_count, error)
    )
    conn.commit()


# --------------------------------------------------------------------------
# WHOIS confirmation
# --------------------------------------------------------------------------

def confirm_recent(matches: list[dict], data_dir: str, whois_cfg: dict,
                   max_age_days: int, max_lookups: int) -> list[dict]:
    """Drop candidates whose registration date is older than max_age_days.

    Candidates without a parseable date are kept (we do not want to lose a
    potentially new domain because a registry did not answer).
    """
    if not matches:
        return []
    by_domain: dict[str, list[dict]] = {}
    for m in matches:
        by_domain.setdefault(m["domain"], []).append(m)

    cutoff = datetime.now(timezone.utc) - timedelta(days=max(1, max_age_days))
    kept: list[dict] = []
    lookups = 0
    rate_delay = float(whois_cfg.get("rate_delay", 1.0) or 0)

    for domain, rows in by_domain.items():
        keep = True
        if lookups < max_lookups:
            try:
                info = whois.lookup_domain(
                    domain, data_dir,
                    timeout=int(whois_cfg.get("timeout", 20)),
                    rdap_only=bool(whois_cfg.get("rdap_only", False)),
                    whois_fallback=bool(whois_cfg.get("whois_fallback", True)),
                )
                lookups += 1
                created = _parse_date(info.get("creation_date"))
                if created and created < cutoff:
                    keep = False
            except Exception as e:  # never let enrichment abort the run
                log.warning("WHOIS confirm failed for %s: %s", domain, e)
            if rate_delay > 0:
                time.sleep(rate_delay)
        if keep:
            kept.extend(rows)
    return kept


# --------------------------------------------------------------------------
# Per-TLD run
# --------------------------------------------------------------------------

def run_tld(tld: str, session: requests.Session, conn: sqlite3.Connection,
            host_url: str, api_key: str, settings: dict, args) -> dict:
    report = {"tld": tld, "status": "pending", "records_total": 0, "records_new": 0,
              "last_sync": _now(), "error": None}
    cleanup_path = None
    try:
        if args.file:
            source_path = _abspath(args.file)
            filename = os.path.basename(source_path)
        else:
            resolved = resolve_latest(session, tld, args.index, settings["sleep_http"])
            if not resolved:
                report["status"] = "no_data"
                report["error"] = "no OpenINTEL data for this TLD (check the index/cookie)"
                log.warning("OpenINTEL .%s: no data found", tld)
                record_run(conn, tld, None, "no_data", 0, 0, report["error"])
                return report
            filename = resolved["filename"]
            source_path = os.path.join(settings["download_dir"], f"tld={tld}", filename)
            cleanup_path = source_path

            if not args.force:
                row = conn.execute("SELECT last_file, status FROM cctld_runs WHERE tld = ?", (tld,)).fetchone()
                if row and row[0] == filename and row[1] in OK_STATUSES:
                    report["status"] = "unchanged"
                    return report
            if args.force or not os.path.exists(source_path) or os.path.getsize(source_path) == 0:
                if not download_file(session, resolved["url"], source_path, settings["sleep_between"]):
                    report["status"] = "failed"
                    report["error"] = "download failed"
                    record_run(conn, tld, filename, "failed", 0, 0, report["error"])
                    return report

        baseline = not tld_baselined(conn, tld)
        emit = not baseline and not args.dry_run

        keywords = sync_client.get_keywords(host_url, api_key)
        keyword_matcher = matcher.Matcher(keywords) if keywords else None
        matches: list[dict] = []

        total, new_count = process_domains(conn, tld, read_domains(source_path),
                                           emit, keyword_matcher, matches)

        if baseline:
            report["status"] = "baselined"
        elif new_count == 0:
            report["status"] = "unchanged"
        else:
            report["status"] = "updated"

        report["records_total"] = total
        report["records_new"] = new_count

        if matches and not args.dry_run:
            if settings["whois_confirm"]:
                matches = confirm_recent(matches, settings["worker_data_dir"], settings["whois"],
                                         settings["whois_max_age_days"], settings["whois_max_lookups"])
            for m in matches:
                m["first_seen"] = _now()
                m["source"] = "ct"
            if matches and not sync_client.send_matches(host_url, api_key, matches):
                report["error"] = "matches send failed (will be lost; no local queue)"

        record_run(conn, tld, filename, report["status"], total, new_count, report["error"])
        log.info("OpenINTEL .%s: %s total=%s new=%s matches=%s",
                 tld, report["status"], total, new_count, len(matches))
        return report
    except Exception as e:
        log.error("OpenINTEL .%s failed: %s", tld, e)
        report["status"] = "failed"
        report["error"] = str(e)[:500]
        try:
            record_run(conn, tld, None, "failed", 0, 0, report["error"])
        except Exception:
            pass
        return report
    finally:
        if cleanup_path and not settings["keep_files"] and not args.file:
            try:
                os.remove(cleanup_path)
            except OSError:
                pass


def recheck_cached(conn: sqlite3.Connection, tlds: list[str], host_url: str,
                   api_key: str, settings: dict, progress_cb=None) -> dict:
    """Match already-cached ccTLD domains against the current keywords.

    The cached domains are existing registrations, so the matches are flagged
    as historical (hidden from the default "new" listings; visible with the
    "Include tagged / historical" toggle), mirroring the CZDS recheck.

    `progress_cb(checked, total, matches)` is called periodically so the web UI
    can show progress while a long recheck runs.
    """
    stats = {"domains_checked": 0, "total_domains": 0, "matches_found": 0}
    try:
        keywords = sync_client.get_keywords(host_url, api_key)
    except Exception as e:
        log.error("OpenINTEL recheck: could not fetch keywords: %s", e)
        return stats

    keyword_matcher = matcher.Matcher(keywords) if keywords else None
    if not keyword_matcher or not keyword_matcher.keyword_list:
        log.warning("OpenINTEL recheck: no active keywords.")
        return stats

    for tld in tlds:
        stats["total_domains"] += int(
            conn.execute("SELECT COUNT(*) FROM cctld_seen WHERE tld = ?", (tld,)).fetchone()[0]
        )

    last_progress = 0
    for tld in tlds:
        last = ""
        checked = 0
        tld_matches = 0
        while True:
            rows = conn.execute(
                "SELECT domain, first_seen FROM cctld_seen WHERE tld = ? AND domain > ? "
                "ORDER BY domain LIMIT ?",
                (tld, last, BATCH_SIZE)
            ).fetchall()
            if not rows:
                break
            last = rows[-1][0]
            first_seen = {}
            domains = []
            for domain, fs in rows:
                domains.append(domain)
                first_seen[domain] = fs

            matches = keyword_matcher.match(domains)
            if matches:
                for m in matches:
                    m["first_seen"] = first_seen.get(m["domain"])
                    m["is_historical"] = 1
                    m["source"] = "ct"
                if sync_client.send_matches(host_url, api_key, matches):
                    stats["matches_found"] += len(matches)
                    tld_matches += len(matches)
                else:
                    log.warning("OpenINTEL recheck .%s: failed to send %d matches", tld, len(matches))
            stats["domains_checked"] += len(domains)
            checked += len(domains)
            if progress_cb and stats["domains_checked"] - last_progress >= 50000:
                last_progress = stats["domains_checked"]
                progress_cb(stats["domains_checked"], stats["total_domains"], stats["matches_found"])
        log.info("OpenINTEL recheck .%s: checked=%d matches=%d", tld, checked, tld_matches)

    if progress_cb:
        progress_cb(stats["domains_checked"], stats["total_domains"], stats["matches_found"])
    return stats


# --------------------------------------------------------------------------
# Config / main
# --------------------------------------------------------------------------

def load_settings() -> tuple[configparser.ConfigParser, dict]:
    config_path = os.path.join(WORKER_DIR, "config.ini")
    if not os.path.exists(config_path):
        print(f"[-] Config file not found: {config_path}")
        sys.exit(1)
    cfg = configparser.ConfigParser()
    cfg.read(config_path)

    data_dir = _abspath(cfg.get("openintel", "data_dir", fallback="./data/openintel"))
    db_path = cfg.get("openintel", "db_path", fallback="").strip() or os.path.join(data_dir, "openintel.db")
    whois_cfg = dict(cfg["whois"]) if cfg.has_section("whois") else {}
    settings = {
        "data_dir": data_dir,
        "download_dir": os.path.join(data_dir, "files"),
        "db_path": _abspath(db_path),
        "worker_data_dir": _abspath(cfg.get("worker", "data_dir", fallback="./data")),
        "sleep_http": cfg.getfloat("openintel", "sleep_http", fallback=3.0),
        "sleep_between": cfg.getfloat("openintel", "sleep_between", fallback=10.0),
        "keep_files": cfg.getboolean("openintel", "keep_files", fallback=False),
        "whois_confirm": cfg.getboolean("openintel", "whois_confirm", fallback=True),
        "whois_max_age_days": cfg.getint("openintel", "whois_max_age_days", fallback=30),
        "whois_max_lookups": cfg.getint("openintel", "whois_max_lookups", fallback=200),
        "whois": whois_cfg,
    }
    return cfg, settings


def resolve_tlds(cfg: configparser.ConfigParser, args, session: requests.Session,
                 host_url: str, api_key: str) -> list[str]:
    if args.tlds:
        return [t.strip().lower() for t in args.tlds.split(",") if t.strip()]
    configured = cfg.get("openintel", "tlds", fallback="").strip()
    if configured:
        return [t.strip().lower() for t in configured.split(",") if t.strip()]
    try:
        return sync_client.get_openintel_tlds(host_url, api_key)
    except Exception as e:
        log.warning("Could not fetch OpenINTEL TLDs from the hosting API: %s", e)
        return []


def main() -> int:
    parser = argparse.ArgumentParser(description="OpenINTEL ccTLD weekly importer")
    parser.add_argument("--tlds", help="Comma-separated ccTLDs (overrides config/web)")
    parser.add_argument("--file", help="Process a local parquet file instead of downloading")
    parser.add_argument("--index", type=int, default=0,
                        help="0=latest weekly file, 1=previous, ... (useful for testing)")
    parser.add_argument("--dry-run", action="store_true", help="Read/diff without sending matches")
    parser.add_argument("--force", action="store_true", help="Re-download and re-process")
    parser.add_argument("--recheck", action="store_true",
                        help="Match already-cached ccTLD domains against the current keywords")
    parser.add_argument("--reset-tld", help="Delete the seen-set for a TLD first (testing)")
    parser.add_argument("--command-id", type=int, default=0,
                        help="Web command id to report progress/result to (internal)")
    args = parser.parse_args()

    cfg, settings = load_settings()

    if (not cfg.getboolean("openintel", "enabled", fallback=False)
            and not args.force and not args.file and not args.recheck):
        print("[-] OpenINTEL import disabled ([openintel] enabled = false).")
        return 0
    if not cfg.getboolean("openintel", "accept_terms", fallback=False):
        print("[-] You must accept the OpenINTEL terms ([openintel] accept_terms = true), "
              "CC BY-NC-SA 4.0, non-commercial.")
        return 1

    host_url = cfg.get("hosting", "url").rstrip("/")
    api_key = cfg.get("hosting", "api_key")

    log_dir = os.path.join(settings["data_dir"], "logs")
    logger.setup_logger(log_dir)
    log.info("OpenINTEL import starting. Attribution: %s", ATTRIBUTION)

    lock = acquire_lock(settings["data_dir"])
    if lock is None:
        log.warning("Another OpenINTEL import is already running. Exiting.")
        return 0

    def report(status: str, payload: dict) -> None:
        """Report progress/result back to the web command (if any)."""
        if not args.command_id:
            return
        try:
            sync_client.update_command_status(host_url, api_key, args.command_id,
                                              status, json.dumps(payload))
        except Exception as e:
            log.debug("Could not report command %s: %s", args.command_id, e)

    session = requests.Session()
    session.headers.update({"User-Agent": "ThreatIntelligence-TDL-OpenINTEL/1.0"})
    conn = init_db(settings["db_path"])
    reports = []
    kind = "recheck" if args.recheck else ("test" if args.file else "import")
    try:
        tlds = resolve_tlds(cfg, args, session, host_url, api_key)
        if not tlds:
            log.warning("No OpenINTEL TLDs configured (config [openintel] tlds or web panel).")
            report("completed", {"kind": kind, "tlds": [], "message": "No OpenINTEL TLDs configured."})
            return 0

        report("running", {"kind": kind, "tlds": tlds, "message": "Starting"})

        if args.reset_tld:
            conn.execute("DELETE FROM cctld_seen WHERE tld = ?", (args.reset_tld,))
            conn.execute("DELETE FROM cctld_runs WHERE tld = ?", (args.reset_tld,))
            conn.commit()

        if args.recheck:
            def progress(checked, total, matches):
                report("running", {"kind": "recheck", "tlds": tlds, "total_domains": total,
                                   "checked_domains": checked, "matches_found": matches})
            stats = recheck_cached(conn, tlds, host_url, api_key, settings, progress_cb=progress)
            log.info("OpenINTEL recheck done: checked=%d matches=%d",
                     stats["domains_checked"], stats["matches_found"])
            report("completed", {"kind": "recheck", "tlds": tlds,
                                 "total_domains": stats["total_domains"],
                                 "checked_domains": stats["domains_checked"],
                                 "matches_found": stats["matches_found"]})
            return 0

        for idx, tld in enumerate(tlds):
            if args.reset_tld and tld != args.reset_tld:
                continue
            report("running", {"kind": kind, "tlds": tlds, "current_tld": tld,
                               "done": idx, "total": len(tlds)})
            reports.append(run_tld(tld, session, conn, host_url, api_key, settings, args))

        if reports and not args.dry_run:
            sync_client.send_cctld_sync(host_url, api_key, reports)
        report("completed", {"kind": kind, "tlds": tlds,
                             "records_total": sum(int(r.get("records_total", 0)) for r in reports),
                             "records_new": sum(int(r.get("records_new", 0)) for r in reports),
                             "statuses": {r["tld"]: r["status"] for r in reports}})
        return 0
    except Exception as e:
        log.error("OpenINTEL run failed: %s", e)
        report("failed", {"kind": kind, "error": str(e)[:500]})
        return 1
    finally:
        release_lock(lock)
        conn.close()


if __name__ == "__main__":
    sys.exit(main())
