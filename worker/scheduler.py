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
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    log.info(f"Start: {datetime.now(timezone.utc).isoformat()}")

    # 1. Retry queued items first
    retry_sync_queue(db, host_url, api_key, max_retries)

    # 2. Get ICANN token
    token = downloader.get_token(icann_user, icann_pass)
    if not token:
        return stats

    # 3. Get approved TLDs
    tlds = downloader.get_approved_tlds(token)
    if not tlds:
        print("[-] No TLDs to process.")
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
                log.warning("No active TLDs selected in web panel and no whitelist configured. "
                            "Go to /admin/tlds.php and mark at least one TLD, or set a whitelist in config.ini. "
                            "Skipping worker cycle to avoid downloading all zones.")
                return stats
    except Exception as e:
        log.error(f"Failed to sync TLDs with hosting: {e}")
        # Fallback to config whitelist
        whitelist_raw = cfg.get("tlds", "whitelist", fallback="").strip()
        if whitelist_raw:
            whitelist = [t.strip().lower() for t in whitelist_raw.split(",") if t.strip()]
            tlds = [t for t in tlds if t in whitelist]

    if not tlds:
        log.warning("No TLDs to process.")
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
        log.error(f"Failed to fetch keywords: {e}")
        return stats

    if not keywords:
        print("[!] No active keywords on hosting. Nothing to match.")
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
                        max_domains: int = 0, source: str = "czds") -> dict:
    """Re-check cached CZDS domains against current keywords. Returns stats.

    `tlds` limits the scan to the given TLDs (None/empty = all) and
    `max_domains` caps the number of domains checked (0 = no cap).
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
    keyword_matcher = matcher.Matcher(keywords)

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
                  api_key: str, tlds: list | None = None, max_domains: int = 0) -> dict:
    """Recheck the OpenINTEL ccTLD cache (cctld_seen) against current keywords."""
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
                                     progress_cb=progress, max_domains=max_domains)
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


HASH_SEARCH_NOTE = ("Prefix/contains search only covers text-cached TLDs; huge TLDs "
                    "cached as hashes (e.g. .com) are excluded. Exact search covers both.")


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
                          openintel_db_path: str | None = None) -> dict:
    """Search the worker's caches and return a unified result list.

    Aggregates the CZDS gTLD cache (domains_cache + compact hash cache) and, when
    `openintel_db_path` is given, the OpenINTEL ccTLD cache (cctld_seen). Results
    carry a `source` of "zone" (CZDS) or "ct" (OpenINTEL). `contains` is bounded
    by a timeout per cache so a full scan can never hang the worker.
    """
    query = (query or "").strip().lower()
    limit = max(1, min(int(limit or 100), 200))
    note = HASH_SEARCH_NOTE

    if not query:
        return {"results": [], "partial": False, "note": "Empty query."}
    if mode not in ("exact", "prefix", "contains"):
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
                logs.append({"level": "info", "message": f"Worker cycle ({mode}) completed: {worker_stats['tlds_processed']} TLDs, {worker_stats['matches_found']} matches"})

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

                total = {"domains_checked": 0, "matches_found": 0, "sources": sources, "tlds": tlds}
                if "openintel" in sources:
                    s = recheck_cctld(db, cfg, host_url, api_key, tlds=tlds, max_domains=max_domains)
                    total["domains_checked"] += int(s.get("domains_checked", 0))
                    total["matches_found"] += int(s.get("matches_found", 0))
                if "czds" in sources:
                    if not tlds and not max_domains:
                        logs.append({"level": "warning", "message":
                                     "CZDS recheck skipped: select ICANN TLDs or set a max_domains cap "
                                     "to avoid scanning the whole cache."})
                    else:
                        s = recheck_all_domains(db, host_url, api_key, max_age,
                                                tlds=tlds, max_domains=max_domains, source="czds")
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
                if cfg.has_section("whois"):
                    timeout = cfg.getint("whois", "timeout", fallback=20)
                    rdap_only = cfg.getboolean("whois", "rdap_only", fallback=False)
                    whois_fallback = cfg.getboolean("whois", "whois_fallback", fallback=True)
                    rate_delay = cfg.getfloat("whois", "rate_delay", fallback=1.0)
                else:
                    timeout, rdap_only, whois_fallback, rate_delay = 20, False, True, 1.0
                entries = []
                for d in domains:
                    entries.append(whois.lookup_domain(d, data_dir, timeout=timeout,
                                                       rdap_only=rdap_only,
                                                       whois_fallback=whois_fallback))
                    if rate_delay > 0:
                        time.sleep(rate_delay)
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

            elif command == "search_domain":
                opts = {}
                if payload:
                    try:
                        opts = json.loads(payload) if isinstance(payload, str) else {}
                    except (ValueError, TypeError):
                        opts = {}
                q = str(opts.get("q", "")).strip().lower()
                mode = str(opts.get("mode", "exact"))
                try:
                    limit = int(opts.get("limit", 100) or 100)
                except (TypeError, ValueError):
                    limit = 100
                search_result = search_cached_domains(
                    db, q, mode=mode, limit=limit,
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
                            logs.append({"level": "info", "message":
                                         f"Scheduled daily cycle done: {worker_stats['tlds_processed']} TLDs, "
                                         f"{worker_stats['matches_found']} matches"})

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
            logs.append({"level": "info", "message": f"Worker cycle completed: {worker_stats['tlds_processed']} TLDs, {worker_stats['matches_found']} matches"})

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
