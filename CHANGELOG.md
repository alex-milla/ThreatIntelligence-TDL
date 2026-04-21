# Changelog

All notable changes to this project will be documented in this file.

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
