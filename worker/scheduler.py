#!/usr/bin/env python3
"""Main orchestrator: download zones, parse, deduplicate, match keywords, sync to hosting.
Supports daemon mode with command polling from the web panel."""

import argparse
import configparser
import json
import logging
import os
import sqlite3
import sys
import time
from datetime import datetime, timezone, timedelta

try:
    import fcntl
except ImportError:  # pragma: no cover - planned for Linux workers only
    fcntl = None

import downloader
import logger
import parser
import matcher
import sync_client

log = logging.getLogger("tdl_worker")


def init_local_db(db_path: str) -> sqlite3.Connection:
    """Create local worker SQLite database if not exists."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA temp_store=MEMORY")
    conn.execute("PRAGMA cache_size=-65536")
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
    """)
    conn.commit()
    return conn


def _stage_and_diff_batch(cursor: sqlite3.Cursor, tld: str, now: str, batch: list[str],
                          keyword_matcher, matches: list[dict]) -> int:
    """Stage a parsed batch, insert genuinely new domains and match them.

    Uses a TEMP table plus a SQL anti-join so the full known-domain set is never
    loaded into Python, keeping peak memory bounded on very large TLDs.
    Returns the number of new domains found.
    """
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
    if not new_domains:
        return 0
    cursor.executemany(
        "INSERT OR IGNORE INTO domains_cache (domain, tld, first_seen) VALUES (?, ?, ?)",
        ((domain, tld, now) for domain in new_domains)
    )
    if keyword_matcher is not None:
        matches.extend(keyword_matcher.match(new_domains))
    return len(new_domains)


def get_tld_meta(db: sqlite3.Connection, tld: str) -> dict:
    """Return the stored download/run metadata for a TLD."""
    cursor = db.cursor()
    cursor.execute(
        "SELECT etag, last_modified, last_run_date, last_run_status FROM tld_meta WHERE tld = ?",
        (tld,)
    )
    row = cursor.fetchone()
    if not row:
        return {"etag": None, "last_modified": None, "last_run_date": None, "last_run_status": None}
    return {"etag": row[0], "last_modified": row[1], "last_run_date": row[2], "last_run_status": row[3]}


def update_tld_meta(db: sqlite3.Connection, tld: str, etag: str | None,
                    last_modified: str | None, run_date: str | None, status: str) -> None:
    """Persist download validators and the last successful run date for a TLD."""
    cursor = db.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO tld_meta (tld, etag, last_modified, last_run_date, last_run_status) "
        "VALUES (?, ?, ?, ?, ?)",
        (tld, etag, last_modified, run_date, status)
    )
    db.commit()


def process_tld(tld: str, token: str, download_dir: str, db: sqlite3.Connection,
                keywords: list[dict], force: bool = False) -> list[dict]:
    """Download, parse, deduplicate and match a single TLD. Returns match dicts.

    To minimise load on the ICANN CZDS API this function:
      - skips a TLD already successfully processed today (unless force is set),
      - performs a conditional request (ETag / Last-Modified) so an unchanged
        zone is not transferred again,
      - keeps the last downloaded zone file on disk instead of deleting it.
    """
    today_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    now = datetime.now(timezone.utc).isoformat()
    meta = get_tld_meta(db, tld)

    # 1. Daily idempotency guard: never re-scan a TLD already done today.
    if not force and meta["last_run_date"] == today_date and meta["last_run_status"] == "ok":
        print(f"[=] .{tld} already processed today ({today_date}). Skipping to avoid re-scanning.")
        return []

    # 2. Conditional download (only transfers the zone if it changed).
    os.makedirs(download_dir, exist_ok=True)
    filepath = os.path.join(download_dir, f"{tld}.zone.gz")
    prev_etag = None if force else meta["etag"]
    prev_last_modified = None if force else meta["last_modified"]
    status, etag, last_modified = downloader.download_zone(
        tld, token, filepath, etag=prev_etag, last_modified=prev_last_modified
    )
    if status == "failed":
        return []
    if status == "not_modified":
        print(f"[=] .{tld} zone unchanged since last run. Skipping parse.")
        update_tld_meta(db, tld, meta["etag"], meta["last_modified"], today_date, "ok")
        return []

    # 3. Parse and find new domains. The comparison against the cache is done
    #    entirely in SQLite (batched + anti-join) so the full known-domain set
    #    is never loaded into Python: peak memory stays bounded on huge TLDs.
    print(f"[*] Parsing {tld}.zone ...")
    keyword_matcher = matcher.Matcher(keywords) if keywords else None
    total = 0
    new_count = 0
    matches: list[dict] = []
    cursor = db.cursor()
    batch = []
    batch_size = 50000

    try:
        cursor.execute("CREATE TEMP TABLE IF NOT EXISTS zone_batch (domain TEXT PRIMARY KEY)")
        for domain in parser.parse_zone_gz(filepath, tld):
            total += 1
            batch.append(domain)
            if len(batch) >= batch_size:
                new_count += _stage_and_diff_batch(cursor, tld, now, batch, keyword_matcher, matches)
                batch = []
        if batch:
            new_count += _stage_and_diff_batch(cursor, tld, now, batch, keyword_matcher, matches)
        # Single commit per TLD: with WAL + synchronous=NORMAL this is much
        # cheaper than committing every batch.
        db.commit()
        cursor.execute("DROP TABLE IF EXISTS zone_batch")
    except Exception:
        db.rollback()
        raise

    print(f"[+] {tld}: {total:,} total, {new_count:,} new.")

    cursor.execute(
        "INSERT INTO zone_runs (tld, run_date, records_total, records_new, status) VALUES (?, ?, ?, ?, ?)",
        (tld, now, total, new_count, "ok")
    )
    db.commit()

    # Zone parsed and cached successfully: persist validators + today's date so
    # subsequent runs can skip this TLD via a conditional request / daily guard.
    update_tld_meta(db, tld, etag, last_modified, today_date, "ok")

    if not matches:
        return []
    for m in matches:
        m["first_seen"] = now
    print(f"[+] {len(matches)} matches found for .{tld}.")
    return matches


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


def run_worker_cycle(db: sqlite3.Connection, cfg: configparser.ConfigParser, host_url: str, api_key: str, version: str, force: bool = False) -> dict:
    """Run one full worker cycle. Returns stats dict."""
    download_dir = cfg.get("worker", "download_dir", fallback="./zones")
    data_dir = cfg.get("worker", "data_dir", fallback="./data")
    max_retries = cfg.getint("worker", "max_retries", fallback=5)
    icann_user = cfg.get("icann", "username")
    icann_pass = cfg.get("icann", "password")

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
    })

    # 5. Process each TLD
    all_matches = []
    domains_processed = 0
    for tld in tlds:
        try:
            matches = process_tld(tld, token, download_dir, db, keywords, force=force)
            all_matches.extend(matches)
            stats["tlds_processed"] += 1
            # Count total domains seen this cycle from zone_runs
            cursor = db.cursor()
            cursor.execute(
                "SELECT records_total FROM zone_runs WHERE tld = ? AND run_date = (SELECT MAX(run_date) FROM zone_runs WHERE tld = ?)",
                (tld, tld)
            )
            row = cursor.fetchone()
            if row:
                domains_processed += row[0]
            # Send incremental heartbeat + log after each TLD
            sync_client.send_heartbeat(host_url, api_key, {
                "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                "is_running": 1,
                "version": version,
                "current_action": f"Processing .{tld}",
                "current_tld": tld,
                "total_tlds": total_tlds,
                "tlds_processed": stats["tlds_processed"],
                "domains_processed": domains_processed,
            })
            sync_client.send_logs(host_url, api_key, [{
                "level": "info",
                "message": f"TLD {stats['tlds_processed']}/{total_tlds}: .{tld} done ({row[0] if row else 0} domains)"
            }])
        except Exception as e:
            print(f"[-] Exception processing {tld}: {e}")
            # Roll back any partially inserted cache rows so the TLD is retried
            # cleanly on the next run instead of silently losing its matches.
            try:
                db.rollback()
            except Exception:
                pass
            sync_client.send_logs(host_url, api_key, [{
                "level": "error",
                "message": f"Exception processing .{tld}: {e}"
            }])

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
    })
    log.info(f"End: {datetime.now(timezone.utc).isoformat()}")
    return stats


def recheck_all_domains(db: sqlite3.Connection, host_url: str, api_key: str, max_age_days: int = 30) -> dict:
    """Re-check cached domains against current keywords. Returns stats."""
    stats = {
        "domains_checked": 0,
        "matches_found": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    log.info("Starting keyword recheck against cached domains...")

    try:
        keywords = sync_client.get_keywords(host_url, api_key)
        log.info(f"Keywords loaded: {len(keywords)}")
    except Exception as e:
        log.error(f"Failed to fetch keywords: {e}")
        return stats

    if not keywords:
        log.warning("No active keywords. Nothing to recheck.")
        return stats

    age_clause = ""
    age_param = ()
    if max_age_days > 0:
        age_clause = " WHERE first_seen >= datetime('now', '-' || ? || ' days')"
        age_param = (max_age_days,)

    total_domains = db.execute(f"SELECT COUNT(*) FROM domains_cache{age_clause}", age_param).fetchone()[0]
    log.info(f"Cached domains to check (max {max_age_days} days): {total_domains:,}")
    started_at = datetime.now(timezone.utc).isoformat()

    if total_domains == 0:
        log.warning("No cached domains found. Run the worker at least once to download zones before rechecking.")
        sync_client.send_recheck_status(host_url, api_key, {
            "is_running": 0,
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

    while True:
        cursor = db.cursor()
        if max_age_days > 0:
            # Keyset pagination: WHERE domain > last ORDER BY domain avoids the
            # O(n^2) cost of deep OFFSET scans on large caches.
            cursor.execute(
                "SELECT domain, tld, first_seen FROM domains_cache "
                "WHERE first_seen >= datetime('now', '-' || ? || ' days') AND domain > ? "
                "ORDER BY domain LIMIT ?",
                (max_age_days, last_domain, batch_size)
            )
        else:
            cursor.execute(
                "SELECT domain, tld, first_seen FROM domains_cache "
                "WHERE domain > ? ORDER BY domain LIMIT ?",
                (last_domain, batch_size)
            )
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
            all_matches.append(m)

        stats["domains_checked"] += len(domains)
        batches_since_stop_check += 1

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
        "total_domains": total_domains,
        "checked_domains": stats["domains_checked"],
        "matches_found": stats["matches_found"],
        "started_at": started_at,
        "completed_at": datetime.now(timezone.utc).isoformat(),
    })

    log.info(f"Recheck complete. Domains checked: {stats['domains_checked']:,}, Matches: {stats['matches_found']}")
    return stats


def handle_commands(db: sqlite3.Connection, cfg: configparser.ConfigParser, host_url: str, api_key: str, version: str, force: bool = False) -> tuple[list[dict], dict | None, bool]:
    """Poll and execute pending commands from the hosting. Returns (log entries, worker_stats, commands_processed)."""
    logs = []
    worker_stats = None
    commands_processed = False
    try:
        commands = sync_client.get_commands(host_url, api_key)
    except Exception as e:
        logs.append({"level": "error", "message": f"Failed to fetch commands: {e}"})
        return logs, worker_stats, commands_processed

    if not commands:
        return logs, worker_stats, commands_processed

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
            if command == "run_worker":
                sync_client.send_heartbeat(host_url, api_key, {
                    "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                    "is_running": 1,
                    "version": version,
                })
                worker_stats = run_worker_cycle(db, cfg, host_url, api_key, version, force=force)
                result = json.dumps(worker_stats)
                logs.append({"level": "info", "message": f"Worker cycle completed: {worker_stats['tlds_processed']} TLDs, {worker_stats['matches_found']} matches"})

            elif command == "recheck_keywords":
                sync_client.send_heartbeat(host_url, api_key, {
                    "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                    "is_running": 1,
                    "version": version,
                })
                max_age = cfg.getint("worker", "max_domain_age_days", fallback=30)
                stats = recheck_all_domains(db, host_url, api_key, max_age)
                result = json.dumps(stats)
                logs.append({"level": "info", "message": f"Recheck completed: {stats['domains_checked']:,} domains, {stats['matches_found']} matches"})

            elif command == "update_whitelist":
                if not cfg.has_section("tlds"):
                    cfg.add_section("tlds")
                cfg.set("tlds", "whitelist", payload)
                with open(config_path, "w") as f:
                    cfg.write(f)
                result = f"Whitelist updated to: {payload}"
                logs.append({"level": "info", "message": result})

            elif command == "update_worker":
                result = "Manual update not implemented. Use git pull."
                logs.append({"level": "warning", "message": result})
                status = "failed"

            elif command == "stop_recheck":
                result = "Stop recheck command acknowledged. If a recheck is running it will stop at the next batch boundary."
                logs.append({"level": "info", "message": result})

            else:
                result = f"Unknown command: {command}"
                logs.append({"level": "warning", "message": result})

            sync_client.mark_command_done(host_url, api_key, cmd_id, status, result)
            logs.append({"level": "info", "message": f"Command {cmd_id} marked as {status}"})

        except Exception as e:
            error_msg = str(e)
            logs.append({"level": "error", "message": f"Command {cmd_id} failed: {error_msg}"})
            sync_client.mark_command_done(host_url, api_key, cmd_id, "failed", error_msg)

    return logs, worker_stats, commands_processed


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


def main() -> int:
    parser_args = argparse.ArgumentParser(description="ThreatIntelligence-TDL Worker")
    parser_args.add_argument("--daemon", action="store_true", help="Run in daemon mode with command polling")
    parser_args.add_argument("--interval", type=int, default=60, help="Polling interval in seconds (daemon mode)")
    parser_args.add_argument("--once", action="store_true", help="Run one worker cycle and exit (legacy)")
    parser_args.add_argument("--status", action="store_true", help="Show last run status and exit")
    parser_args.add_argument("--force", action="store_true",
                             help="Ignore the daily guard and conditional cache, reprocessing all TLDs")
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
    version = get_version()

    # Setup logging with 90-day rotation
    log = logger.setup_logger(os.path.join(data_dir, "logs"))

    if api_key == "TU_API_KEY":
        log.error("Please edit config.ini with real credentials.")
        return 1

    db_path = os.path.join(data_dir, "worker.db")
    db = init_local_db(db_path)

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

    if args.daemon:
        log.info(f"Daemon mode started. Polling every {args.interval}s. Press Ctrl+C to stop.")
        try:
            while True:
                logs = []
                worker_stats = None
                try:
                    cmd_logs, worker_stats, _ = handle_commands(db, cfg, host_url, api_key, version)
                    logs.extend(cmd_logs)

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

                time.sleep(args.interval)
        except KeyboardInterrupt:
            log.info("Daemon mode stopped by user.")
    else:
        # One-shot mode: process commands first, then run worker cycle if nothing was processed
        logs, worker_stats, commands_processed = handle_commands(db, cfg, host_url, api_key, version, force=args.force)

        if not commands_processed and not worker_stats:
            # No commands pending → legacy cron behavior: run full cycle
            worker_stats = run_worker_cycle(db, cfg, host_url, api_key, version, force=args.force)
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

    release_worker_lock(lock_handle)
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
