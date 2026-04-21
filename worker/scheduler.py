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

import downloader
import logger
import parser
import matcher
import sync_client


def init_local_db(db_path: str) -> sqlite3.Connection:
    """Create local worker SQLite database if not exists."""
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode=WAL")
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
    """)
    conn.commit()
    return conn


def load_existing_domains(db: sqlite3.Connection, tld: str) -> set:
    """Load all known domains for a TLD into a set (RAM)."""
    cursor = db.cursor()
    cursor.execute("SELECT domain FROM domains_cache WHERE tld = ?", (tld,))
    return {row[0] for row in cursor}


def process_tld(tld: str, token: str, download_dir: str, db: sqlite3.Connection, keywords: list[dict]) -> list[dict]:
    """Download, parse, deduplicate and match a single TLD. Returns match dicts."""
    today = datetime.now(timezone.utc).strftime("%Y%m%d")
    filepath = os.path.join(download_dir, f"{tld}_{today}.txt.gz")
    os.makedirs(download_dir, exist_ok=True)

    # 1. Download
    if not downloader.download_zone(tld, token, filepath):
        return []

    # 2. Load existing domains for this TLD into memory
    print(f"[*] Loading known domains for .{tld} ...")
    existing = load_existing_domains(db, tld)
    print(f"[+] {len(existing)} domains already known for .{tld}.")

    # 3. Parse and find new domains
    print(f"[*] Parsing {tld}.zone ...")
    new_domains = []
    total = 0
    now = datetime.now(timezone.utc).isoformat()
    cursor = db.cursor()
    batch = []
    batch_size = 10000

    for domain in parser.parse_zone_gz(filepath, tld):
        total += 1
        if domain not in existing:
            new_domains.append(domain)
            existing.add(domain)
            batch.append((domain, tld, now))
            if len(batch) >= batch_size:
                cursor.executemany(
                    "INSERT INTO domains_cache (domain, tld, first_seen) VALUES (?, ?, ?)",
                    batch
                )
                db.commit()
                batch = []

    if batch:
        cursor.executemany(
            "INSERT INTO domains_cache (domain, tld, first_seen) VALUES (?, ?, ?)",
            batch
        )
        db.commit()

    # 4. Cleanup downloaded file
    os.remove(filepath)

    print(f"[+] {tld}: {total:,} total, {len(new_domains):,} new.")

    cursor.execute(
        "INSERT INTO zone_runs (tld, run_date, records_total, records_new, status) VALUES (?, ?, ?, ?, ?)",
        (tld, now, total, len(new_domains), "ok")
    )
    db.commit()

    if not new_domains or not keywords:
        return []

    # 5. Match against keywords
    print(f"[*] Matching {len(new_domains):,} new domains against {len(keywords)} keywords ...")
    matches = matcher.match_domains(new_domains, keywords)
    print(f"[+] {len(matches)} matches found for .{tld}.")
    return matches


def retry_sync_queue(db: sqlite3.Connection, host_url: str, api_key: str, max_retries: int) -> None:
    """Attempt to send any queued payloads."""
    cursor = db.cursor()
    now = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        "SELECT id, payload, retry_count FROM sync_queue WHERE next_retry <= ? AND retry_count < ?",
        (now, max_retries)
    )
    rows = cursor.fetchall()
    if not rows:
        return

    print(f"[*] Retrying {len(rows)} queued sync item(s) ...")
    for row_id, payload_json, retry_count in rows:
        payload = json.loads(payload_json)
        ok = sync_client.send_matches(host_url, api_key, payload)
        if ok:
            cursor.execute("DELETE FROM sync_queue WHERE id = ?", (row_id,))
            db.commit()
        else:
            next_retry = (datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()
            cursor.execute(
                "UPDATE sync_queue SET retry_count = ?, next_retry = ? WHERE id = ?",
                (retry_count + 1, next_retry, row_id)
            )
            db.commit()


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


def run_worker_cycle(db: sqlite3.Connection, cfg: configparser.ConfigParser, host_url: str, api_key: str) -> dict:
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

    log = logging.getLogger("tdl_worker")
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
            tlds = [t for t in tlds if t in active_tlds]
            print(f"[*] Active TLDs from hosting: {len(tlds)}")
        else:
            # Fallback to config whitelist if no active TLDs set in web
            whitelist_raw = cfg.get("tlds", "whitelist", fallback="").strip()
            if whitelist_raw:
                whitelist = [t.strip().lower() for t in whitelist_raw.split(",") if t.strip()]
                tlds = [t for t in tlds if t in whitelist]
                print(f"[*] Fallback whitelist applied: {len(tlds)} TLDs to process.")
    except Exception as e:
        print(f"[-] Failed to sync TLDs with hosting: {e}")
        # Fallback to config whitelist
        whitelist_raw = cfg.get("tlds", "whitelist", fallback="").strip()
        if whitelist_raw:
            whitelist = [t.strip().lower() for t in whitelist_raw.split(",") if t.strip()]
            tlds = [t for t in tlds if t in whitelist]

    if not tlds:
        print("[-] No TLDs to process.")
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

    # 5. Process each TLD
    all_matches = []
    domains_processed = 0
    for tld in tlds:
        try:
            matches = process_tld(tld, token, download_dir, db, keywords)
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
        except Exception as e:
            print(f"[-] Exception processing {tld}: {e}")

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
    log.info(f"End: {datetime.now(timezone.utc).isoformat()}")
    return stats


def recheck_all_domains(db: sqlite3.Connection, host_url: str, api_key: str) -> dict:
    """Re-check all cached domains against current keywords. Returns stats."""
    stats = {
        "domains_checked": 0,
        "matches_found": 0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    log.info("Starting keyword recheck against all cached domains...")

    try:
        keywords = sync_client.get_keywords(host_url, api_key)
        print(f"[+] Keywords loaded: {len(keywords)}")
    except Exception as e:
        print(f"[-] Failed to fetch keywords: {e}")
        return stats

    if not keywords:
        log.warning("No active keywords. Nothing to recheck.")
        return stats

    batch_size = 50000
    offset = 0
    all_matches = []

    while True:
        cursor = db.cursor()
        cursor.execute(
            "SELECT domain, tld FROM domains_cache ORDER BY domain LIMIT ? OFFSET ?",
            (batch_size, offset)
        )
        rows = cursor.fetchall()
        if not rows:
            break

        domains = []
        tld_map = {}
        for domain, tld in rows:
            domains.append(domain)
            tld_map[domain] = tld

        matches = matcher.match_domains(domains, keywords)
        for m in matches:
            m["tld"] = tld_map.get(m["domain"], m["tld"])
            all_matches.append(m)

        stats["domains_checked"] += len(domains)
        offset += batch_size
        log.info(f"Checked {stats['domains_checked']:,} domains so far...")

    if all_matches:
        log.info(f"Sending {len(all_matches)} recheck matches to hosting...")
        ok = sync_client.send_matches(host_url, api_key, all_matches)
        if not ok:
            queue_matches(db, all_matches)
        stats["matches_found"] = len(all_matches)
    else:
        log.info("No new matches found during recheck.")

    log.info(f"Recheck complete. Domains checked: {stats['domains_checked']:,}, Matches: {stats['matches_found']}")
    return stats


def handle_commands(db: sqlite3.Connection, cfg: configparser.ConfigParser, host_url: str, api_key: str) -> list[dict]:
    """Poll and execute pending commands from the hosting. Returns log entries."""
    logs = []
    try:
        commands = sync_client.get_commands(host_url, api_key)
    except Exception as e:
        logs.append({"level": "error", "message": f"Failed to fetch commands: {e}"})
        return logs

    if not commands:
        return logs

    config_path = os.path.join(os.path.dirname(__file__), "config.ini")

    for cmd in commands:
        cmd_id = cmd["id"]
        command = cmd["command"]
        payload = cmd.get("payload", "")
        logs.append({"level": "info", "message": f"Executing command {cmd_id}: {command}"})

        try:
            if command == "run_worker":
                stats = run_worker_cycle(db, cfg, host_url, api_key)
                result = json.dumps(stats)
                logs.append({"level": "info", "message": f"Worker cycle completed: {stats['tlds_processed']} TLDs, {stats['matches_found']} matches"})

            elif command == "recheck_keywords":
                stats = recheck_all_domains(db, host_url, api_key)
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

            else:
                result = f"Unknown command: {command}"
                logs.append({"level": "warning", "message": result})

            sync_client.mark_command_done(host_url, api_key, cmd_id, "completed", result)

        except Exception as e:
            error_msg = str(e)
            logs.append({"level": "error", "message": f"Command {cmd_id} failed: {error_msg}"})
            sync_client.mark_command_done(host_url, api_key, cmd_id, "failed", error_msg)

    return logs


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


def main() -> int:
    parser_args = argparse.ArgumentParser(description="ThreatIntelligence-TDL Worker")
    parser_args.add_argument("--daemon", action="store_true", help="Run in daemon mode with command polling")
    parser_args.add_argument("--interval", type=int, default=60, help="Polling interval in seconds (daemon mode)")
    parser_args.add_argument("--once", action="store_true", help="Run one worker cycle and exit (legacy)")
    parser_args.add_argument("--status", action="store_true", help="Show last run status and exit")
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

    if args.daemon:
        log.info(f"Daemon mode started. Polling every {args.interval}s. Press Ctrl+C to stop.")
        while True:
            logs = []
            try:
                # Poll commands
                cmd_logs = handle_commands(db, cfg, host_url, api_key)
                logs.extend(cmd_logs)

                # Send heartbeat
                sync_client.send_heartbeat(host_url, api_key, {
                    "last_heartbeat": datetime.now(timezone.utc).isoformat(),
                    "is_running": 1,
                    "version": version,
                })

                # Send logs
                if logs:
                    sync_client.send_logs(host_url, api_key, logs)

            except Exception as e:
                log.error(f"Daemon loop error: {e}")

            time.sleep(args.interval)
    else:
        # One-shot mode: process commands first, then run worker cycle
        logs = handle_commands(db, cfg, host_url, api_key)
        if not any(cmd.get("command") == "run_worker" for cmd in sync_client.get_commands(host_url, api_key)):
            # No explicit run_worker command, execute cycle directly
            stats = run_worker_cycle(db, cfg, host_url, api_key)
            logs.append({"level": "info", "message": f"Worker cycle completed: {stats['tlds_processed']} TLDs, {stats['matches_found']} matches"})

        sync_client.send_heartbeat(host_url, api_key, {
            "last_run": datetime.now(timezone.utc).isoformat(),
            "is_running": 0,
            "version": version,
        })
        if logs:
            sync_client.send_logs(host_url, api_key, logs)

    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
