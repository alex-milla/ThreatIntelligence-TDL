# Changelog

All notable changes to this project will be documented in this file.

## [v1.3.45] - 2026-09-18

### Safe parsing of huge zones (WAL / disk)
- **Batched commits**: TLDs are no longer committed once at the end. Every `commit_every_batches` batches (default 10 → 500k domains) the worker commits and runs `PRAGMA wal_checkpoint(PASSIVE)`, so the SQLite WAL does not grow to several GB while parsing a zone like `.com` (~160M rows).
- **Mid-parse disk guard**: if free disk drops below `min_free_disk_gb` during parsing, the worker stops cleanly with status `no_space`, removes the multi-GB zone file and queues the TLD for retry (instead of filling the disk).
- **Dropped `idx_cache_hash_tld`**: the hash cache is never queried by TLD (`recheck` excludes hash-cached TLDs), so the index only cost time and disk on 100M+ row tables. Removed on new databases and dropped by migration on existing ones.

## [v1.3.44] - 2026-09-18

### Critical parser fix: lowercase rrtypes
- CZDS zone files commonly use **lowercase rrtypes** (`in ns`). The byte pre-filter added in v1.3.39 (`b" NS"` / `b"\tNS"`) was case-sensitive and silently dropped almost every NS line, so **no domains were parsed since v1.3.39**.
- `parser.py` now accepts `NS`/`ns`/mixed case in the pre-filter. Added regression tests with lowercase and mixed-case rrtypes.
- **`parse_error` safety net**: if a non-trivial zone (> 1 MB) yields 0 domains, the TLD is **not** marked as processed, the zone is kept and a retry is queued, and the UI shows `Parse error` instead of a false `Downloaded`.

### Actions after upgrading
- Run **Force Re-download** (or `--force`) for the affected TLDs: the daily guard already marked them as done for today. `com` (~160 M domains) will use the compact hash cache; `sbs`/`online` use the text cache.

## [v1.3.43] - 2026-09-18

### Robust handling of very large zone files
- **Resumable downloads**: `downloader.py` resumes an interrupted transfer with `Range` + `If-Range` (ICANN CZDS supports `206 Partial Content`) and retries transient failures (`IncompleteRead`, connection drops) with backoff.
- **Size validation**: the remote size is read first (HEAD) and the final file size must match `Content-Length`; otherwise the download is marked `incomplete` and the partial is kept for the next attempt.
- **Compact hash cache**: zones above `hash_cache_min_mb` (default 512 MB, e.g. `.com` ≈ 4.6 GB) store a 64-bit hash per domain instead of the domain text, keeping the local DB small. Matching still uses the real domain text. Huge TLD zones are removed after parsing (`retain_zone_hash_tlds=false`).
- **Bounded parser memory**: `parser.py` no longer keeps every domain of a zone in a Python `set` (the cause of the 1.9 GB peak); it deduplicates consecutive owners and lets SQL remove the rest.
- **Safety guards**: `max_zone_size_gb` (skip with `skipped_large`), `min_free_disk_gb` (skip with `no_space`) and a disk-space check before downloading.
- **Per-TLD retry queue**: failed/incomplete TLDs are retried immediately (up to `max_download_retries`) and, if still failing, queued for the next cycle with exponential backoff (`tld_retry_queue`).

### Visibility and robustness
- **Live progress during a single TLD**: heartbeats every ~10 s show `Downloading .com 1.2/4.6 GB` and `Parsing .com (12M domains)`.
- **Line-buffered stdout** so per-TLD `print()` output appears immediately in the journal.
- **Orphaned commands recovered**: on startup the worker closes commands left in `running` by a crash/restart; a failed status update no longer aborts the daemon loop. Admin can also cancel `running` commands.
- **New TLD statuses** shown with badges: `incomplete`, `skipped_large`, `no_space`, `retrying`, plus retry attempt/time.
- **Large-selection warning** in `admin/tlds.php` before Force/Refresh.
- **PEP 668**: `install.sh`/`update.sh` detect an externally-managed environment and print `apt install python3-ahocorasick` / venv guidance instead of a raw pip error.

## [v1.3.42] - 2026-09-18

### Worker visibility and lifecycle
- **Version mismatch banner**: the Admin panel and TLDs page now warn when `worker_status.version` differs from the app `VERSION`, with a one-click **Update Worker** action. This prevents the "I updated but nothing happens" case where only the web app was updated.
- **`update_worker` implemented**: the worker pulls `origin/main` (`git fetch` + `git reset --hard`, never touching `config.ini`, `data/`, `zones/`) and exits so systemd (`Restart=always`) relaunches it with the new code. Fails gracefully on non-git checkouts.
- **Command lifecycle**: commands are marked `running` when execution starts and `completed`/`failed`/`cancelled` when it ends, with a new `finished_at` timestamp. Admin shows a **Recent Commands** table with status, start/finish and duration.
- **Current command in `worker_status`**: `current_command` / `current_command_id` are reported and shown in the Live Worker card.
- **Live per-TLD reporting**: on small selections (≤50 TLDs, e.g. a force/refresh of a few TLDs) the worker reports after every TLD, so the TLD table updates during the run instead of only at the end.
- **Anti-duplicate queuing**: `run_worker`, `recheck_keywords` and `update_worker` are not queued again while an equivalent command is pending or running.

### Install
- **`worker/install.sh`**: installs and enables the `tdl-worker` systemd service (paths generated from the checkout location); `tdl-worker.service` sets `PYTHONUNBUFFERED=1` for live logs.

## [v1.3.41] - 2026-09-18

### Per-TLD download visibility (worker -> web)
- **New API endpoint `api/v1/tld_sync.php`**: the worker reports the outcome of every processed TLD (`downloaded`, `not_modified`, `skipped_today`, `failed`) together with record counts, zone file size/mtime and the last error.
- **`tlds` table**: safe migrations add `records_total`, `records_new`, `zone_size`, `zone_file_mtime` and `last_error`.
- **`worker/sync_client.py`**: new `report_tld_sync()`; reports are flushed in batches of 25 to avoid one HTTP call per TLD.
- **`worker/scheduler.py`**: `process_tld()` now returns `(matches, info)`; the heartbeat `domains_processed` is taken from the real run result instead of a stale `zone_runs` lookup.

### Visual validation (`admin/tlds.php`)
- TLD table now shows **Last Sync**, a colour-coded **Status** badge, **Domains**, **New**, **Size** and **Error** per TLD, plus a summary of the last cycle.
- New session-authenticated `ajax_tld_status.php`; the table auto-refreshes every 5 s while the worker is running.

### Manual refresh from the UI
- **Refresh Selected**: bypasses the daily guard but keeps the conditional `ETag`/`Last-Modified` validators, so a TLD is only transferred again if it actually changed.
- **Force Re-download**: ignores both the daily guard and the cache (full re-download of the selected TLDs).
- Both queue a `run_worker` command with a JSON payload; `handle_commands` parses `force`/`refresh`. New CLI flag `--refresh`.
- Fixed: daemon mode now passes `--force`/`--refresh` to command handling (previously the flag was ignored in daemon mode).

## [v1.3.40] - 2026-09-17

### Worker maintenance
- **`worker/update.sh`**: helper script to update the worker in one command (`git pull --ff-only` + `pip install -r requirements.txt`). `--restart` also restarts the `tdl-worker` systemd service for daemon mode. Untracked `config.ini`, `data/` and `zones/` are never touched. Cron mode picks up the new code on its next run without restarting.

## [v1.3.39] - 2026-09-17

### Worker performance / ICANN CZDS load reduction
- **Conditional downloads**: `downloader.download_zone` now sends `If-None-Match` / `If-Modified-Since` when a previous `ETag` / `Last-Modified` is known. A `304 Not Modified` response skips both download and parse, so unchanged zones are not transferred again.
- **Daily idempotency guard**: each TLD tracks its last successful run date (`tld_meta` table). A TLD already processed today is skipped, preventing the cron from re-scanning everything on repeated same-day runs.
- **Zone file retention**: the last downloaded `.zone.gz` is kept on disk instead of being deleted, and writes are atomic (`.part` + rename) so an interrupted download never replaces a good copy.
- **Anti-overlap lock**: the worker acquires an exclusive `flock` (`data/worker.lock`). A second cron/systemd instance exits immediately instead of duplicating downloads against ICANN.
- **`--force` flag**: bypasses the daily guard and conditional cache for manual full reprocessing (`python3 scheduler.py --once --force`).

### Worker processing speed (local CPU, no extra ICANN load)
- **Parser byte pre-filter**: `parser.py` reads the zone as bytes and skips lines that cannot contain an NS record before decoding/tokenising them, greatly reducing per-line work on large zones.
- **Aho-Corasick matcher**: `matcher.py` uses `pyahocorasick` when installed to find all keywords in a single pass (with a substring fallback if the optional dependency is missing). Preserves one match per (domain, keyword).
- **SQLite tuning**: `synchronous=NORMAL`, `temp_store=MEMORY`, larger page cache/mmap, one commit per TLD and 50k insert batches.
- **Bounded memory on huge TLDs**: `domains_cache` is no longer loaded into a Python `set`. New domains are detected in SQLite with a per-batch TEMP staging table and a `LEFT JOIN ... IS NULL` anti-join (using the primary-key indexes), so peak RAM stays bounded regardless of TLD size. The matcher automaton is also built once per run (`matcher.Matcher`) instead of per batch.
- **Recheck keyset pagination**: `recheck_all_domains` pages with `WHERE domain > last ORDER BY domain LIMIT n` instead of `LIMIT/OFFSET`, removing the quadratic cost of deep offsets.

## [v1.3.9] - 2026-04-21

### New features
- **Stop Recheck**: Admin can now queue a `stop_recheck` command from the dashboard. The worker checks for pending stop commands every 3 batches (~150k domains) and gracefully exits the recheck loop, sending partial results.
- **Clickable match counts**: In `keywords.php`, the match count for each keyword is now a link that filters notifications by that keyword.
- **Domain tags (Good/Bad)**: New `domain_tags` table allows marking domains as good or bad. Tags are shown as colored badges in Recent Matches and Notifications. The domain detail modal includes buttons to mark, change, or remove a tag. Previously classified domains are instantly identified when they reappear.

## [v1.3.8] - 2026-04-21

### Parser fix: extract only real SLD registrations
- `parser.py` now yields **only** second-level domains (SLDs) directly under the TLD.
- **Before**: the parser extracted every NS record in the zone file, including the TLD apex (`digital.`), infrastructure subdomains (`nic.digital.`, `whois.digital.`, `ns1.nic.digital.`), and wildcard records (`*.digital.`).
- **After**: only owners with exactly `N+1` labels are kept (where `N` = labels of the TLD). For `.digital` only `example.digital` passes; `digital`, `nic.digital`, and `ns1.nic.digital` are discarded.
- Wildcard records (`*`) are also explicitly skipped.

## [v1.3.7] - 2026-04-21

### RDAP Whois fix
- `ajax_whois.php` now uses the **IANA RDAP Bootstrap** (`data.iana.org/rdap/dns.json`) to query the correct TLD-specific RDAP server instead of relying solely on `rdap.org`, which returns 404 for many new gTLDs (e.g., `.digital`, `.tech`). Bootstrap JSON is cached locally for 7 days.
- Domain validation in whois endpoint now accepts Unicode/IDN characters (aligned with `matches.php`).
- Removed redundant `session_start()` in `ajax_whois.php`.

## [v1.3.6] - 2026-04-21

### Fase 4 – Robustez final del diagnóstico
- **B-06** Worker daemon mode now sends `tlds_processed`, `domains_processed`, and `matches_found` in the heartbeat payload after each cycle.
- **B-08** `matches.php` domain validation now accepts Unicode/IDN domains (`\p{L}`). Skipped invalid domains are counted and logged in `sync_logs.error`.
- **B-11** Worker logs the difference between TLDs discovered and TLDs returned as active by the hosting.
- **B-12** `downloader.py` uses `urllib.parse.urlparse` + `os.path.basename` for robust TLD extraction from CZDS URLs.
- **B-13** `parser.py` now correctly identifies NS records by skipping owner, TTL, and class tokens, preventing false positives from RRSIG lines containing "NS".
- **B-16** `update_worker` command now marks as `failed` instead of `completed` since manual update is not implemented.
- **B-18** `install.php` hard gate: redirects to home if any admin user already exists in the database, even if the lock file is missing.
- **B-19** Removed duplicate `session_start()` in `ajax_recheck_status.php`.
- **B-20** `mail.php` sanitizes `HTTP_HOST` to prevent header injection in notification emails.

## [v1.3.5] - 2026-04-21

### Fase 3 – Higiene / Cleanup
- **B-05** Removed orphaned `api/v1/heartbeat.php` endpoint.
- **B-17** Added dead-letter queue (`sync_dead_letter`) for `sync_queue` items that exhaust `max_retries`. Failed payloads are preserved with `error_reason`, `retry_count`, and `failed_at`. Errors are logged to the hosting API.

## [v1.3.4] - 2026-04-21

### Fase 2 – Robustez
- **B-04** `tlds.is_active` now defaults to `0`. Worker warns and exits if no TLDs are active and no whitelist is configured.
- **B-07** Match emails are now sent asynchronously after the JSON response is flushed (`fastcgi_finish_request`).
- **B-09** Admin API keys rate limit raised to 600 req/min; deterministic cleanup of `api_requests` on every call.
- **B-15** Admin self-disable protection: an admin cannot remove their own admin flag or delete their own account.

## [v1.3.3] - 2026-04-21

### Domain Analysis Modal
- Added on-demand RDAP whois lookup (`ajax_whois.php` via cURL) inside the domain modal.

## [v1.3.0] - 2026-04-21

### Domain Analysis Modal
- Click any matched domain to open a modal with VirusTotal link and RDAP whois button.

## [v1.2.9] - 2026-04-21

### first_seen Synchronization
- Worker sends `first_seen` timestamp to hosting. Displayed in dashboard and notifications.

## [v1.2.8] - 2026-04-21

### Domain Age Filter
- Added `max_domain_age_days` to worker config (default 30). Dashboard shows period selector (24h/7d/30d/all).

## [v1.2.7] - 2026-04-21

### Notifications – Bulk Delete All Matching
- Added "Delete All Matching Results (N)" button for mass deletion across all pages.

## [v1.2.4] - 2026-04-21

### Notifications – Search & Filters
- Search by domain, TLD, or keyword.
- Date filters (24h / 7d / 30d / all) and unread-only checkbox.
- Pagination (50 per page) with numbered links.
- Bulk checkbox selection + "Delete Selected".

## [v1.2.3] - 2026-04-21

### Admin Cleanup Tool
- `admin/cleanup.php` detects and deletes false-positive matches caused by the TLD-matching bug.

## [v1.2.2] - 2026-04-21

### Matcher Fix
- Keywords no longer match the TLD portion (e.g., `life` won't match `abc.life`).

## [v1.2.1] - 2026-04-21

### Fase 1 – Críticos
- **B-01** `worker_status.php` uses partial `UPDATE` instead of `INSERT OR REPLACE` to avoid overwriting admin fields.
- **B-02** One-shot mode uses `commands_processed` flag to prevent double execution cycle.
- **B-03** Fixed module-level logger `NameError` in worker (`log = logging.getLogger("tdl_worker")`).
