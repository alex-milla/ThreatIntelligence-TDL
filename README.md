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
- Enough disk space for temporary zone file downloads (up to ~200 MB per TLD compressed)
- Enough RAM to hold existing domains for a TLD in memory (~1 GB recommended for large TLDs like `.xyz`)

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

## How It Works

1. The worker authenticates with ICANN CZDS and downloads your approved TLD zone files automatically.
2. It maintains a local cache (`domains_cache`) of all domains it has ever seen.
3. During each run, it detects which domains are **new** since the last run.
4. It fetches active keywords from the web UI via API.
5. New domains are matched against keywords (case-insensitive substring).
6. Matches are sent to the web UI, which creates notifications for each affected user.

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
