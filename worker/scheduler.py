#!/usr/bin/env python3
"""Main orchestrator: download zones, parse, deduplicate, match keywords, sync to hosting."""

import configparser
import json
import os
import sqlite3
import sys
from datetime import datetime, timezone, timedelta

import downloader
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


def main() -> int:
    config_path = os.path.join(os.path.dirname(__file__), "config.ini")
    if not os.path.exists(config_path):
        print(f"[-] Config file not found: {config_path}")
        print("    Copy config.ini.example to config.ini and fill in your credentials.")
        return 1

    cfg = configparser.ConfigParser()
    cfg.read(config_path)

    icann_user = cfg.get("icann", "username")
    icann_pass = cfg.get("icann", "password")
    host_url = cfg.get("hosting", "url").rstrip("/")
    api_key = cfg.get("hosting", "api_key")
    download_dir = cfg.get("worker", "download_dir", fallback="./zones")
    data_dir = cfg.get("worker", "data_dir", fallback="./data")
    max_retries = cfg.getint("worker", "max_retries", fallback=5)

    if icann_user == "TU_USUARIO_ICANN" or api_key == "TU_API_KEY":
        print("[-] Please edit config.ini with real credentials.")
        return 1

    db_path = os.path.join(data_dir, "worker.db")
    db = init_local_db(db_path)

    print(f"[*] Start: {datetime.now(timezone.utc).isoformat()}")

    # 1. Retry queued items first
    retry_sync_queue(db, host_url, api_key, max_retries)

    # 2. Get ICANN token
    token = downloader.get_token(icann_user, icann_pass)
    if not token:
        return 1

    # 3. Get approved TLDs
    tlds = downloader.get_approved_tlds(token)
    if not tlds:
        print("[-] No TLDs to process.")
        return 1

    # 4. Get keywords from hosting
    print("[*] Fetching keywords from hosting ...")
    try:
        keywords = sync_client.get_keywords(host_url, api_key)
        print(f"[+] Keywords loaded: {len(keywords)}")
    except Exception as e:
        print(f"[-] Failed to fetch keywords: {e}")
        return 1

    if not keywords:
        print("[!] No active keywords on hosting. Nothing to match.")
        return 0

    # 5. Process each TLD
    all_matches = []
    for tld in tlds:
        try:
            matches = process_tld(tld, token, download_dir, db, keywords)
            all_matches.extend(matches)
        except Exception as e:
            print(f"[-] Exception processing {tld}: {e}")

    # 6. Send all matches to hosting
    if all_matches:
        print(f"[*] Sending total of {len(all_matches)} matches to hosting ...")
        ok = sync_client.send_matches(host_url, api_key, all_matches)
        if not ok:
            queue_matches(db, all_matches)
    else:
        print("[*] No new matches to send.")

    # 7. Send heartbeat
    stats = {
        "tlds_processed": len(tlds),
        "matches_found": len(all_matches),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        sync_client.send_heartbeat(host_url, api_key, stats)
    except Exception:
        pass

    print(f"[*] End: {datetime.now(timezone.utc).isoformat()}")
    db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
