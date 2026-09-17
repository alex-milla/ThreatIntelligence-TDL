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

```bash
cd /path/to/ThreatIntelligence-TDL/worker
bash update.sh            # git pull --ff-only + pip install -r requirements.txt
bash update.sh --restart  # also restart the tdl-worker systemd service (daemon mode)
```

Untracked files (`config.ini`, `data/`, `zones/`) are never touched. In cron mode the next run picks up the new code automatically; in daemon mode use `--restart`.

## How It Works

1. The worker authenticates with ICANN CZDS and downloads your approved TLD zone files automatically.
2. It maintains a local cache (`domains_cache`) of all domains it has ever seen.
3. During each run, it detects which domains are **new** since the last run.
4. It fetches active keywords from the web UI via API.
5. New domains are matched against keywords (case-insensitive substring).
6. Matches are sent to the web UI, which creates notifications for each affected user.

## Minimizing load on the ICANN CZDS API

The worker is designed to query CZDS as little as possible:

- **Conditional requests**: per-TLD `ETag` / `Last-Modified` values are stored and sent back via `If-None-Match` / `If-Modified-Since`. If the zone has not changed, ICANN replies `304 Not Modified` and nothing is transferred or parsed.
- **Daily guard**: a TLD successfully processed today is skipped for the rest of the day. Running cron several times a day does **not** re-download or re-scan zones already done.
- **Single instance lock**: `data/worker.lock` (via `flock`) prevents overlapping cron/systemd runs from duplicating downloads.
- **Retained zone files**: the latest `.zone.gz` per active TLD is kept on disk (overwritten on the next change) instead of being deleted.

To force a full reprocess (ignoring the daily guard and conditional cache):

```bash
python3 scheduler.py --once --force
```

## User Features

- **Keywords**: Each user can define keywords to monitor (e.g., `santander`, `nasa`).
- **Notifications**: In-app notifications when a new domain matches any of your keywords.
- **Dashboard**: View recent matches and statistics.
- **Admin Panel**: Manage users, keyword limits, API keys, sync logs, and system updates.

## Updates

The admin panel includes a **System Update** page that checks GitHub releases and updates application files automatically. Your SQLite database is never overwritten during updates.

For private repositories, set a GitHub personal access token in `admin/update.php` or via the `GITHUB_TOKEN` environment variable.

## Security Notes

- The worker API is protected by a single API key (generated during install).
- Keep `data/` outside the web root if your hosting allows it; otherwise `data/.htaccess` blocks direct access.
- Use HTTPS between the worker and the hosting.
- The worker never stores user data or keywords locally (only a domain cache for deduplication).

## License

MIT
