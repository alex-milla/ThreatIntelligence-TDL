# ThreatIntelligence-TDL

Monitor new domain registrations across ICANN CZDS zone files. Users define keywords (brands, company names, etc.) and receive notifications when matching domains are registered.

## Architecture

This project uses a hybrid architecture:

- **Worker (Python 3)** runs on your LXC/VPS. It downloads zone files from ICANN CZDS, parses them, detects new domains, matches them against user keywords, and sends results to the web UI.
- **Web UI (PHP 8+)** runs on shared hosting. It manages users, keywords, displays matches, and exposes a secure API for the worker.

```
LXC/VPS (Python Worker)        HTTPS API        Shared Hosting (PHP + SQLite)
- Download zones                ───────►        - Users & Keywords
- Parse & detect new domains    ◄───────        - Matches & Notifications
- Match against keywords                        - Admin Dashboard
```

## Requirements

### Worker (LXC/VPS)
- Python 3.8+
- `requests` library
- Internet access to ICANN CZDS API and your shared hosting
- Enough disk space to keep the latest downloaded zone file per active TLD (up to ~200 MB per TLD compressed)
- Modest RAM: the known-domain cache is **not** loaded into memory (deduplication runs inside SQLite with a per-batch staging table), so memory no longer grows with the accumulated cache. Processing is batched; the main remaining cost is the parser holding the current zone's unique domains (~1 GB for very large TLDs like `.xyz`).

### Web UI (Shared Hosting)
- PHP 8.0+
- SQLite 3 extension enabled
- Write permissions in `data/` directory

## Quick Start

### 1. Web UI (Shared Hosting)

Upload all files and folders (except `worker/`) to your hosting root.

```bash
# The hosting must allow writing to data/
chmod 755 data
```

Visit `https://yourdomain.com/install.php` and create the admin account. **Save the generated API key** — you will need it for the worker.

### 2. Worker (LXC/VPS)

```bash
git clone https://github.com/alex-milla/ThreatIntelligence-TDL.git
cd ThreatIntelligence-TDL/worker
bash install.sh
```

Edit `config.ini`:

```ini
[icann]
username = YOUR_ICANN_USERNAME
password = YOUR_ICANN_PASSWORD

[hosting]
url = https://yourdomain.com
api_key = THE_API_KEY_FROM_INSTALL

[worker]
download_dir = ./zones
data_dir = ./data
batch_size = 10000
max_retries = 5
```

Run manually first:

```bash
python3 scheduler.py
```

Then schedule it via cron (daily at 06:00 UTC):

```bash
0 6 * * * cd /path/to/ThreatIntelligence-TDL/worker && /usr/bin/python3 scheduler.py >> /var/log/tdl_worker.log 2>&1
```

### Updating the worker

> **The web updater (`/admin/update.php`) and the worker are separate.** Updating the web app does **not** update the worker running on its own host (LXC/VPS). The Admin panel and the TLDs page show a warning when the worker reports a version different from the app.

From the panel: **Admin → Update Worker** queues an `update_worker` command. The worker does `git fetch` + `git reset --hard origin/main` (untracked `config.ini`, `data/`, `zones/` are never touched) and exits so systemd (`Restart=always`) relaunches it with the new code. This requires a git checkout and the `tdl-worker` service.

From the shell:

```bash
cd /path/to/ThreatIntelligence-TDL/worker
bash update.sh            # git pull --ff-only + pip install -r requirements.txt
bash update.sh --restart  # also restart the tdl-worker systemd service (daemon mode)
```

In cron mode the next run picks up the new code automatically; in daemon mode use `--restart`.

## How It Works

1. The worker authenticates with ICANN CZDS and downloads your approved TLD zone files automatically.
2. It maintains a local cache (`domains_cache`) of all domains it has ever seen.
3. During each run, it detects which domains are **new** since the last run.
4. It fetches active keywords from the web UI via API.
5. New domains are matched against keywords (case-insensitive substring).
6. Matches are sent to the web UI, which creates notifications for each affected user.

> **Zone file format:** CZDS zone files use lowercase rrtypes (`example.com. 3600 in ns ns1.example.net.`). The parser is case-insensitive for the record type, and a non-trivial zone that yields zero domains is flagged as `parse_error` (not marked as processed) so parser regressions are visible.

## Minimizing load on the ICANN CZDS API

The worker is designed to query CZDS as little as possible:

- **Conditional requests**: per-TLD `ETag` / `Last-Modified` values are stored and sent back via `If-None-Match` / `If-Modified-Since`. If the zone has not changed, ICANN replies `304 Not Modified` and nothing is transferred or parsed.
- **Daily guard**: a TLD successfully processed today is skipped for the rest of the day. Running cron several times a day does **not** re-download or re-scan zones already done.
- **Single instance lock**: `data/worker.lock` (via `flock`) prevents overlapping cron/systemd runs from duplicating downloads.
- **Retained zone files**: the latest `.zone.gz` per active TLD is kept on disk (overwritten on the next change) instead of being deleted.

### Download visibility and manual refresh

The worker reports the result of every TLD back to the web UI (`api/v1/tld_sync.php`). The **TLDs** admin page (`/admin/tlds.php`) shows, per TLD: last sync time, a status badge (`Downloaded`, `Unchanged`, `Skipped today`, `Failed`), number of domains, new domains, zone file size and the last error. The table refreshes automatically while the worker is running.

From that page you can also trigger a run without leaving the browser:

- **Refresh Selected** — skips the daily guard but keeps the `ETag`/`Last-Modified` validators, so the zone is downloaded only if it changed on ICANN's side.
- **Force Re-download** — ignores the daily guard *and* the cache, re-downloading the full zone files for the selected TLDs.

Both operate on the **currently active (checked)** TLDs only, never on all approved TLDs.

Equivalent CLI flags:

```bash
python3 scheduler.py --once --force     # full reprocess (ignore guard + cache)
python3 scheduler.py --once --refresh   # bypass guard, keep conditional download
```

## Very large zone files (e.g. `.com`)

Some zones are multi-gigabyte (`.com` is ~4.6 GB compressed). The worker handles them specially:

- **Resumable downloads**: a partial `.zone.gz.part` is kept and resumed with `Range`/`If-Range` (ICANN CZDS supports `206 Partial Content`), so a dropped connection does not restart the transfer.
- **Completeness check**: the remote size is read first and the final file size must match `Content-Length`; otherwise the TLD is marked `incomplete` and retried.
- **Compact hash cache**: zones larger than `hash_cache_min_mb` (default 512 MB) are cached as 64-bit hashes instead of domain text. `.com` (~160 M domains) then costs ~5 GB instead of ~17 GB. `recheck_keywords` excludes hash-cached TLDs (there is no text to match offline).
- **Guards**: `max_zone_size_gb` refuses zones above a hard limit (`skipped_large`), and `min_free_disk_gb` refuses to start if free disk would drop too low (`no_space`).
- **Per-TLD retries**: failed/incomplete TLDs are retried immediately (up to `max_download_retries`) and then queued for the next cycle with backoff (`tld_retry_queue`).

Relevant `config.ini` keys:

```ini
[worker]
max_zone_size_gb = 0        ; 0 = no hard limit
min_free_disk_gb = 5
hash_cache_min_mb = 512
retain_zone_hash_tlds = false   ; delete the multi-GB zone after parsing
max_download_retries = 3
retry_delay_seconds = 300
```

> On Debian/Ubuntu with PEP 668, `pip install` may be blocked. The optional `pyahocorasick` accelerator can be installed with `apt install python3-ahocorasick`; the worker runs fine without it (substring fallback).

## User Features

- **Keywords**: Each user can define keywords to monitor (e.g., `santander`, `nasa`).
- **Notifications**: In-app notifications when a new domain matches any of your keywords.
- **Dashboard**: View recent matches and statistics.
- **Admin Panel**: Manage users, keyword limits, API keys, sync logs, and system updates.

## Updates

The admin panel includes a **System Update** page (`/admin/update.php`) that checks GitHub releases and updates the **web application** files automatically. Your SQLite database is never overwritten during updates.

The **worker** is updated separately: use **Admin → Update Worker** (queues the `update_worker` command, requires a git checkout + the `tdl-worker` systemd service) or run `worker/update.sh --restart` on the worker host. The panel shows a warning if the worker version does not match the app version.

For private repositories, set a GitHub personal access token in `admin/update.php` or via the `GITHUB_TOKEN` environment variable.

## Security Notes

- The worker API is protected by a single API key (generated during install).
- Keep `data/` outside the web root if your hosting allows it; otherwise `data/.htaccess` blocks direct access.
- Use HTTPS between the worker and the hosting.
- The worker never stores user data or keywords locally (only a domain cache for deduplication).

## License

MIT
