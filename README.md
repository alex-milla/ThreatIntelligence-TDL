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

> **Debian/Ubuntu (PEP 668):** system-wide `pip install` is blocked. Create a
> virtualenv and re-run the installer so the systemd units use it:
> ```bash
> sudo apt install python3-venv python3-full
> bash setup_venv.sh
> bash install.sh
> ```

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

Then schedule it.

### Scheduling the daily ICANN (CZDS) cycle

**Recommended — daemon mode with the automatic daily run.** `install.sh` sets up
the `tdl-worker` systemd service; once it is running the worker triggers one full
cycle per local day after the configured time, so **no cron is needed**:

```ini
[worker]
auto_daily = true
daily_run_time = 04:00
daily_run_timezone = Europe/Madrid
```

The daemon holds `data/worker.lock`, so a `--once` cron job would be skipped
while it runs. The daily guard still avoids re-scanning TLDs already processed
today, and if the host was off at the scheduled time the cycle runs on the next
poll after it starts.

**Alternative — cron / one-shot mode** (if you do not run the daemon):

```bash
0 6 * * * cd /path/to/ThreatIntelligence-TDL/worker && /usr/bin/python3 scheduler.py --once >> /var/log/tdl_worker.log 2>&1
```

Cron mode and the daemon are mutually exclusive (single-instance lock): use
`--once` only when the `tdl-worker` service is stopped.

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

### New-domain baseline (no historical floods)

The first successful scan of a TLD is a **baseline**: the worker caches every domain but does not notify. From the next changed zone onwards it reports only delegations added since the previous successful scan of that TLD. This avoids flooding users with the whole zone on a fresh install, when a new TLD is activated, after clearing `worker.db`, or when a TLD changes between the text cache and the compact hash cache. The TLD is shown as **Baselined** on the TLDs page.

Matches produced by the manual **Recheck** are stored with `is_historical=1`; the web UI hides them (and any domain already tagged good/bad) from the default "new" listings. Use the **Include tagged / historical** toggle on the Notifications page to review them, or **Admin → System → New-domain listing** to archive/restore the existing matches in bulk (reversible).

## Minimizing load on the ICANN CZDS API

The worker is designed to query CZDS as little as possible:

- **Conditional requests**: per-TLD `ETag` / `Last-Modified` values are stored and sent back via `If-None-Match` / `If-Modified-Since`. If the zone has not changed, ICANN replies `304 Not Modified` and nothing is transferred or parsed.
- **Daily guard**: a TLD successfully processed today is skipped for the rest of the day. Running cron several times a day does **not** re-download or re-scan zones already done.
- **Single instance lock**: `data/worker.lock` (via `flock`) prevents overlapping cron/systemd runs from duplicating downloads.
- **Retained zone files**: the latest `.zone.gz` per active TLD is kept on disk (overwritten on the next change) instead of being deleted.

### Download visibility and manual refresh

The worker reports the result of every TLD back to the web UI (`api/v1/tld_sync.php`). The **TLDs** admin page (`/admin/tlds.php`) shows, per TLD: last sync time, a status badge (`Downloaded`, `Unchanged`, `Skipped today`, `Failed`), number of domains, new domains, zone file size and the last error. The table refreshes automatically while the worker is running.

If the ICANN cycle cannot start at all — bad CZDS credentials, no approved TLDs, no active selection or no active keywords — the failure is reported instead of silently finishing with 0 TLDs: the active CZDS TLDs are marked **Failed** with the reason, a worker-log entry is stored, and `/admin/` (**Overview → Sync health**) shows the last `run_worker` cycle with its status, stage and error. The **Admin → Sync** tab records one row per sync source (`czds-sync`, `openintel-sync`) with the records received/inserted and any error, alongside the match ingests (`czds`, `ct`).

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
- **Guards**: `max_zone_size_gb` refuses zones above a hard limit (`skipped_large`), and `min_free_disk_gb` refuses to start if free disk would drop too low. The same limit is checked **during** parsing: if it is reached, the worker stops with `no_space` and frees the zone file.
- **Bounded WAL**: huge zones are committed and WAL-checkpointed every `commit_every_batches` batches (default 10 → 500k domains) instead of one giant transaction, so the WAL does not balloon while parsing `.com`.
- **Per-TLD retries**: failed/incomplete TLDs are retried immediately (up to `max_download_retries`) and then queued for the next cycle with backoff (`tld_retry_queue`).
- **Phase timing**: each parsed TLD logs a `[timing]` line with the wall time spent in `parse` (gzip+scan), `stage` (dedupe/anti-join), `insert`, `match`, `commit` and `download`, to identify whether parsing is CPU- or I/O-bound (`journalctl -u tdl-worker | grep timing`).

Relevant `config.ini` keys:

```ini
[worker]
max_zone_size_gb = 0        ; 0 = no hard limit
min_free_disk_gb = 5
hash_cache_min_mb = 512
retain_zone_hash_tlds = false   ; delete the multi-GB zone after parsing
max_download_retries = 3
retry_delay_seconds = 300
commit_every_batches = 10   ; commit + WAL checkpoint every 500k domains
sqlite_cache_mb = 2048      ; SQLite page cache (MB); lower on hosts with little RAM
sqlite_synchronous_parse = OFF  ; skip fsync during parse (NORMAL to revert)
```

> `sqlite_synchronous_parse = OFF` only applies while a zone is being parsed and is restored to `NORMAL` afterwards. It speeds up the write path but reduces durability; `worker.db` is a rebuildable cache (if corrupted, stop the worker, delete `worker.db*` and re-parse).

> On Debian/Ubuntu with PEP 668, `pip install` may be blocked. The optional `pyahocorasick` accelerator can be installed with `apt install python3-ahocorasick`; the worker runs fine without it (substring fallback).

## User Features

- **Keywords**: Each user can define keywords to monitor (e.g., `santander`, `nasa`). Keywords are matched case-insensitively as **substrings** of the domain name (the TLD is ignored) and, when they contain wildcards, **also as glob patterns** — `*` (any sequence), `?` (one char), `[abc]`/`[0-9]` classes (`[!...]` negation) and `{n,m}` repetition. No type has to be chosen: `microsoft` matches as a substring and `micro*soft` matches `micro-soft` / `microxsoft`. Glob patterns are pre-filtered by their longest literal anchor so the full-cache recheck stays fast; patterns without a literal anchor (e.g. `[0-9]{3}`) are skipped by the recheck but still applied to the new domains of each scan. An existing keyword's text can be edited from the keywords list.
- **Notifications**: In-app notifications when a new domain matches any of your keywords.
- **Dashboard**: Statistics and a **domain lookup** that searches the worker's cached domains (exact match covers every cached domain, including huge hash-cached TLDs like `.com`; prefix/contains cover text-cached TLDs only). A second **glob search** box accepts keyword-style patterns (`*`, `?`, `[abc]`/`[a-z]`, `[!...]`, `{n,m}`), requires at least 3 literal characters, searches text-cached TLDs only and can be limited to a **discovery-date window** (From/To + 7/30/90-day presets; last 7 days by default, maximum 90 days). Both are served by the worker through the command queue, so they need the worker in **daemon mode** and wait for the current run to finish.
- **Admin Panel**: Manage users, keyword limits, API keys, sync logs, and system updates.

## WHOIS / RDAP enrichment (on demand + automatic)

From any domain modal you can click **Fetch WHOIS (worker)**. The web queues a `whois_lookup` command; the **worker** performs the RDAP query (with a WHOIS port 43 fallback) and posts the result back. The modal shows registrar, creation/expiration dates and nameservers. The Notifications page also has a batch **Fetch WHOIS (worker)** button for the selected/visible domains.

Additionally, after each download the worker automatically caches the WHOIS/RDAP data of the **newly matched** domains (`[worker] auto_whois = true`, capped by `auto_whois_max`), so the panel, the per-keyword match list and the reports already show creation dates without any manual step. Rechecks never trigger it, and it uses the `[whois]` settings (rate limit, restricted TLDs, overrides). The OpenINTEL import also caches the data it already collects during confirmation.

- Registration data is cached in `domain_whois`, so repeat views are instant.
- RDAP/WHOIS is **not DNS**: nameservers come from the registration response, not a resolver. No local DNS server is involved.
- Lookups are spaced by `[whois] rate_delay` (config) to be gentle with registries.
- Command latency depends on `[worker] poll_interval` (default 20 s).

## Reputation lookups (VirusTotal + abuse.ch)

The domain detail (Watchlist, Notifications, Dashboard lookup and the reports) shows two reputation sources, both cached and refreshed **on demand** through the worker command queue:

- **VirusTotal** (`vt_lookup`): per-domain verdict from the VirusTotal API v3 (`[virustotal] api_key`, `rate_delay_seconds`, `daily_limit`, `cache_days`). Buttons: **Check VirusTotal (worker)** / **Open in VirusTotal**.
- **abuse.ch** (`abusech_lookup`): validates the matched domain against two free abuse.ch services with a single Auth-Key (`[abusech] auth_key`):
  - **URLhaus** host lookup — malware distribution sites; the Spamhaus DBL result (`phishing_domain`, `botnet_cc_domain`, `abused_legit_*`) and currently-serving payloads drive the verdict.
  - **ThreatFox** IOC search — confirmed IOCs (botnet C2, payload delivery, cc-skimming) with the malware family and confidence level.

  Buttons: **Check Abuse.ch** (per-domain and batch) / **Open in URLhaus**. Each domain takes up to two requests, spaced by `rate_delay_seconds` and capped by `daily_limit`.
  - Verdict: `malicious` (URLhaus online/DBL phishing-botnet, or a ThreatFox IOC), `suspicious` (URLhaus listed but offline/not listed, or a spammer/redirector DBL entry), or `clean` (not found). `urlhaus_enabled` / `threatfox_enabled` toggle each source.

Results are cached in `domain_vt` and `domain_abusech`, so repeat views are instant. A missing API key makes the command fail with a clear message (the rest of the worker is unaffected).

### abuse.ch bulk feed (local blacklist)

Besides the on-demand lookup, the worker keeps a **local copy of the full URLhaus and ThreatFox datasets** so freshly detected domains can be validated without spending API quota:

- **When**: after the daily TLD sync (the same hook as auto-WHOIS), the worker refreshes the dump when it is older than `feed_sync_hours` (default 24) and then cross-checks the new (non-historical) matches, capped by `auto_abusech_max` (default 200). Disable it with `feed_enabled = false`.
- **What it stores**: `abusech_feed` (worker DB) holds one row per domain per source — URLhaus host aggregates (URL count / online count / tags) and ThreatFox domain IOCs (threat type, malware family, confidence, tags). The URLhaus CSV dump has no Spamhaus DBL status, so phishing/botnet DBL classifications come only from the on-demand lookup.
- **What it sends**: only `malicious`/`suspicious` hits, so a feed "not found" never overwrites a richer on-demand result.
- **Config**: `feed_enabled`, `feed_sync_hours`, `auto_abusech_max`, `feed_timeout`, `feed_urlhaus_dump` (default `recent.csv`).

## Intelligence: dormant-domain tracking

Attackers often register a domain and leave it dormant until it ages past reputation blocks (many defenses block domains younger than ~30 days) and then activate it to impersonate a legitimate site. **Intelligence** follows those domains instead of discarding them when they are still clean.

- **Enrollment (per keyword)**: each keyword has a tracking config (enable, window `tracking_days`, and `tracking_enroll_max_age_days`). After a cycle the worker proposes the new matches; the web enrolls those whose WHOIS creation date is recent enough, are not flagged by abuse.ch and are not tagged `bad`. Configure it in **Keywords → Tracking**.
- **Excluded domains are still tracked**: a match you mark as `excluded` (benign, kept out of reports) keeps being monitored for the keyword's window. A per-cycle sweep enrolls already-excluded recent domains, so it does not depend on the domain being a "new" match.
- **Weekly pass (Sunday night)**: the worker runs one validation pass per week on the configured day/time (`[tracking] weekly_day`/`weekly_run_time`/`weekly_run_timezone`, default Sunday 03:00 Europe/Madrid); if the host was off then, it runs on the next poll. It processes every due domain in batches (`batch_max`, safety cap `weekly_batch_max`); the per-keyword interval is 168 h so all are due once a week. **Check now** forces a pass on demand.
- **Checks**: the weekly pass reports signals: **reputation** (abuse.ch + VirusTotal), **WHOIS/NS changes**, **DNS resolution** (Google DoH), **TLS certificate issuance** (crt.sh, key-less) and **HTTP content** (the matched keyword/brand in the title/body, a login form, a plain 200 and a content hash for change detection).
- **Activation**: reputation `malicious`/`suspicious`, a domain that starts resolving after not resolving at enrollment, a certificate issued after enrollment, or HTTP content containing the brand or a login form. WHOIS/NS changes, a plain HTTP 200 and content-hash changes are informational (set `http_activate_any_200 = true` to also activate on a plain 200). Each signal has its own toggle (`reputation_enabled`, `whois_enabled`, `dns_enabled`, `cert_enabled`, `http_enabled`).
- **Reactivation**: when a tracked domain activates, an excluded one is switched back to `observing` with a note (so it is visible again and returns to the reports for review) and an **INTELLIGENCE** notification is raised.
- **Baseline**: the first check records the DNS status and the content hash so "starts resolving" and "content changed" are real changes; WHOIS/NS and reputation come from enrollment.
- **Lifecycle**: a domain that activates gets an **INTELLIGENCE** notification (and email if enabled); one that reaches the end of its window without a signal is archived as **dormant**. Nothing is discarded.
- **UI**: the **Intelligence** page lists tracked domains with status, age, days left, checks and signals, with **Check now** / **Extend** / **Mark dormant** / **Delete** actions.

## IOCs (indicator export)

The **IOCs** page (sidebar, under Intelligence) lists the **malicious/suspicious domains per keyword** and exports them as indicators:

- **Source**: **Live** (current state: analyst tag `bad`, VirusTotal or abuse.ch `malicious`/`suspicious`) or **Generated reports** (the domains that were reported as malicious/suspicious in saved report snapshots).
- **Filters**: keyword (or all) and severity (`Malicious`, or `Malicious + Suspicious`).
- **Export**: **plain text** (one domain per line — EDL, or MISP *freetext* import) and **MISP event JSON** (domain attributes with `to_ids`). Both are authenticated downloads; a copy-to-clipboard of the TXT is included.
- A domain that matches several keywords appears in each keyword's list; the "all keywords" view deduplicates.

> A hosted **feed URL (EDL)** with a read-only token, for automatic consumption by a firewall, is noted as a future enhancement (see the project checkpoint).

## OpenINTEL ccTLD import (optional, weekly)

CZDS only covers gTLDs. For **country-code TLDs** (`.io`, `.es`, `.fr`, ...) the worker can additionally import the **weekly apex-domain lists** published by [OpenINTEL](https://www.openintel.nl/data/domain-lists/cctld-names/), extracted from Certificate Transparency logs.

- **Separate process/database**: `worker/openintel.py` uses its own SQLite (`data/openintel.db`) and is launched by `tdl-openintel.timer` (Sundays, 17:00 Europe/Madrid) or on demand from **Admin → TLDs → ccTLD (OpenINTEL)** (`run_openintel`). It never touches the CZDS pipeline.
- The **first run baselines** a ccTLD (caches everything, reports nothing). Later runs report only domains seen for the first time, matched against keywords; candidates are optionally confirmed with RDAP/WHOIS so old domains are filtered out.
- The weekly files are **`.csv.gz`** and are read without extra dependencies; `pyarrow` is only needed if a dataset is ever served as parquet. Enable the import in `config.ini`:
  ```ini
  [openintel]
  enabled = true
  accept_terms = true     # you must accept the OpenINTEL terms
  tlds =                  # fallback only; ccTLDs activated in the web panel (TLDs → ccTLD) are the source of truth
  ```
- **ccTLDs are managed in the web panel**: any ccTLD you add/activate under **Admin → TLDs → ccTLD (OpenINTEL)** is picked up automatically by the weekly run; adding one also queues an import to baseline it (the first run caches everything and reports nothing). `[openintel] tlds` is only a fallback used if the panel is unreachable or has no active ccTLD.
- **License:** the OpenINTEL data is **CC BY-NC-SA 4.0** (non-commercial, attribution required). Commercial use requires a license from OpenINTEL. Attribution:
  > The research leading to these results was made possible by OpenINTEL (https://www.openintel.nl/), a joint project of the University of Twente, SIDN, NLnet Labs and SURF.
- The lists are "domains seen in a valid certificate", not a registry's registration date; the WHOIS confirmation (or the web "old validated domain" filter) is what decides whether a domain is genuinely new.

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
