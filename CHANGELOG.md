# Changelog

All notable changes to this project will be documented in this file.

## [v1.8.0] - 2026-09-22

### Added - Threat-intelligence report layout (Phase A)

- **Executive Summary** at the top: domains detected / require review / confirmed malicious, plus derived notes (keyword matches, recently registered, missing reputation). It never turns "no verdict" into "safe".
- **Reframed, mutually-exclusive KPI cards** by assessment: Domains · Review required · Confirmed malicious · Suspicious · Confirmed benign · Unknown / not checked.
- **Assessment status per domain** (`malicious / suspicious / benign / review_required / unknown`) derived from the stored data, with documented rules: `bad` or VirusTotal `malicious` → malicious; VirusTotal `suspicious`/`dga` → suspicious; tag `good` → benign; a new domain or a keyword match → review required (configurable via `report_review_on_new` / `report_review_on_keyword`).
- **Triage table** (Assessment, Domain, First seen, Age, Why flagged, Reputation, Source) and a **collapsible detail panel** per domain (Timing, Registration, Reputation, Detection, raw data).
- **Reputation semantics** that keep `Not checked` ≠ `No detections` ≠ tag `good`, and show engine counts (`X of N engines`).
- **Domain age** (today / N days) and clearer dates.
- **Consistent color semantics** (red malicious, amber suspicious/review, green benign, grey unknown/not checked).
- **Print**: the Executive Summary comes first and **every domain detail is expanded** on print/PDF (plus a `beforeprint` handler), with repeated table headers.
- The derived fields are computed by the new `includes/report_present.php` transformation layer from the saved snapshot, so **existing saved reports render with the new layout** without any schema change or migration.

### Verification
- Real render of a snapshot with a new keyword-matched domain (no VT), a VirusTotal-malicious domain and a tag-`good` domain: Executive Summary, status pills (review/malicious/benign), "Not checked" reputation, the triage table, the collapsible detail rows and the raw-data block are all present, with no PHP errors.
- `php -l` on all `public_html` files: 0 errors; `node --check assets/bulk.js`: OK; `worker/tests.py`: PASS.

## [v1.7.0] - 2026-09-22

### Added - Saved report history (immutable snapshots)

- **Generating a report now saves it.** The **Generate Report** button stores an immutable snapshot in the new `report_history` table (gzip-compressed) and opens it at `report_view.php?id=...`. The snapshot keeps the WHOIS/VirusTotal data collected at generation time, so an old report never changes even if matches are updated later.
- **History tab** inside Reports (`?tab=history`): lists the saved reports (date, title, group, keywords, domains) with **Open** and **Delete** actions, and can be **filtered by keyword group** with the same group tabs as the builder. Each user only sees their own reports.
- **Cleanup**: delete one report, delete the selected ones, or **delete all shown** (respects the active group filter), each with a confirmation.
- **Shared builder** (`includes/report_builder.php`): the report data collection was extracted so generating and rendering use the same logic.

### Changed
- `report_view.php` now loads a saved snapshot by `id` (a foreign/unknown id returns 404). Direct links without an `id` redirect to the Reports page.
- Reports still include every domain discovered in the selected period (hiding only explicitly excluded domains; historical unless requested), and the professional layout/KPIs/VT detail is unchanged.

## [v1.6.16] - 2026-09-22

### Fixed - A keyword with today's matches no longer disappears from the report

- **Report builder (`reports.php`)**: "last sync" is now decided by **discovery date only** — a keyword is listed when it has matches discovered in the last 24h, excluding only explicitly **excluded** domains. Classification (good/bad/observing/watchlist) and the WHOIS "registered before the last scan" heuristic no longer remove a keyword. This fixes the case where a keyword with domains found today was hidden just because their WHOIS registration date was old (auto-WHOIS populated it since v1.6.13). The **Matches** column now shows the last-sync count.
- **Groups never come out empty**: if a group has no last-sync keywords, opening it now shows **all** its keywords (with a notice) so a report can still be generated. Every group tab is always rendered.
- **Report output (`report_view.php`)**: a report now includes **every domain discovered in the period**, hiding only explicitly excluded domains; historical (recheck) matches stay hidden unless requested. `good/bad`, watchlist and old registrations are shown with their WHOIS/VirusTotal data. The Notifications/Dashboard/Keywords visibility rules are unchanged.

## [v1.6.15] - 2026-09-22

### Changed - Reports show only the last sync, with a professional layout

- **Report builder (`reports.php`)**: by default it now lists only the keywords that had matches in the **last sync (last 24h)**. A new **"Show all keywords"** checkbox lifts that restriction. Group tab counts follow the same scope.
- **Report output (`report_view.php`)**: keywords with no matching domains are **omitted** (no more empty sections), so a report contains only the keywords from the last sync. The selected group name is shown in the header.
- **Professional format**: new cover header (brand, title, group/period/generated/user), a **KPI strip** (Domains, New, Malicious, Suspicious, Good, Bad), a restyled per-keyword **Summary** table (now including Watchlist) and cleaner per-keyword detail sections with stat pills.
- **All WHOIS/VirusTotal data**: the detail table now shows WHOIS status and the full cached VirusTotal data (verdict plus malicious/suspicious/harmless/undetected counts, reputation and last analysis date).
- **Print**: A4 **landscape** with wider margins, per-keyword page breaks and repeated table headers.

## [v1.6.14] - 2026-09-22

### Changed - Per-keyword match list hides excluded domains and sorts by Created

- **`keyword_matches.php`**: the **All states** view now hides **excluded** domains, so after **Exclude selected** they disappear from the main list (consistent with the Keywords counter, Notifications and the Reports). A new **Include excluded** checkbox (and the existing **Excluded** state filter) brings them back.
- **Created** is now a sortable column (by WHOIS creation date). Domains without a creation date (`NULL`) always sort **last**, in both ascending and descending order.

## [v1.6.13] - 2026-09-22

### Added - Automatic WHOIS after each download

- **Worker**: after a download cycle the worker now caches the WHOIS/RDAP registration data of the **newly matched** domains, so the panel, the per-keyword match list and the reports already show creation dates without a manual `Fetch WHOIS`. It is on by default (`[worker] auto_whois = true`) and capped by `auto_whois_max` (default 200); it reuses the `[whois]` settings (`rate_delay`, `disabled_tlds`, overrides) and is best-effort (a registry failure never aborts the cycle). **Rechecks never trigger it.**
- The OpenINTEL importer now caches the WHOIS data it already collects during candidate confirmation (`whois_confirm`), which was previously used only to filter.
- Shared `scheduler.whois_lookup_entries()` helper (also used by the on-demand `whois_lookup` command).

### Added - Exclude domains from the report (per-keyword match list)

- New **Excluded** classification (`domain_tags.tag = 'excluded'`). Excluded domains are hidden from Notifications, the Dashboard and the Reports by default, and are skipped by the bulk WHOIS/VirusTotal actions (client- and server-side).
- `keyword_matches.php`: new **Exclude / Unexclude** button per row and bulk **Exclude selected / Unexclude selected** actions, plus an **Excluded** state filter and a visible badge. Excluded rows are still listed so they can be restored.

### Changed - Same-tab navigation and report default period

- The **Matches** count on Keywords/Reports now opens the per-keyword list in the **same tab** (was `target="_blank"`). External links (VirusTotal, OpenINTEL) keep the new tab.
- The report **Period** now defaults to **Last 24h**, so a report reflects the latest (nightly) sync by default.

## [v1.6.12] - 2026-09-20

### Fixed - ccTLD counts blanked on "unchanged" runs

- On weeks when the OpenINTEL weekly file is the same as the last processed one, `run_tld` returned early with `records_total = 0`, and `cctld_sync.php` overwrote the stored total with 0, so the **ccTLD (OpenINTEL)** table showed `—` for **Domains** on every `Unchanged` TLD (only freshly `Baselined`/`Updated` ones kept their count).
- The unchanged branch now reports the last known total from `cctld_runs`, so **Domains** stays populated while **New** correctly shows `—` (nothing new that run). No web-side change was needed.

## [v1.6.11] - 2026-09-20

### Fixed - Keyword recheck now covers the ICANN cache too

- The Keywords page **Recheck** button only scanned the ccTLD (OpenINTEL) cache, because it sent no `sources` and the worker defaults to `["openintel"]`. It now rechecks **both caches** (ccTLD + ICANN/CZDS) for the selected keywords (or all keywords when none is selected). The source list is decided server-side; the button label and a confirmation warn that the ICANN scan can take a while.
- **Worker**: the CZDS recheck guard no longer requires selected TLDs or a max-domains cap when a **max age** bounds the scan (`[worker] max_domain_age_days`, default 30). A recheck with no TLDs, no cap and no age limit is still skipped.
- **Admin → Recheck**: the advanced form now has a **keywords** multi-select (active keywords, with their user); leaving it empty rechecks all keywords. Selected ids are sent as `keyword_ids` in the command payload.
- Note: hash-cached huge TLDs (e.g. `.com`) remain excluded from rechecks (no domain text to match).

## [v1.6.10] - 2026-09-20

### Added - Recheck selected keywords (Keyword page)

- The admin **Recheck** on the Keywords page now has a checkbox per keyword and a **select all** header, so you can recheck **all** cached domains (when nothing is selected, as before) or only a **chosen subset** of keywords.
- The selected keyword ids travel in the command payload (validated server-side: only the admin's own keywords are accepted). The button label shows how many keywords are selected.
- Worker: `recheck_keywords` accepts a `keyword_ids` list. `recheck_all_domains` (CZDS) and `openintel.recheck_cached` (ccTLD) filter the keyword set with the new shared `matcher.filter_keywords()` before matching. Empty/absent = all keywords (unchanged behavior).
- The quick Keywords button still targets the fast ccTLD/OpenINTEL cache; when CZDS is included (Admin → Recheck) the same subset filter applies.
- Test: `test_filter_keywords`.

## [v1.6.9] - 2026-09-20

### Changed - ccTLD (OpenINTEL) TLDs are managed from the web panel

- **The web panel is now the source of truth** for which ccTLDs are imported. `resolve_tlds()` fetches the active OpenINTEL ccTLDs from the panel first; `[openintel] tlds` in `config.ini` is kept only as a **fallback** (used when the panel is unreachable or has no active ccTLD). Activating a ccTLD under **Admin → TLDs → ccTLD (OpenINTEL)** is enough — no config edit needed to have it picked up by the weekly timer.
- **Auto-baseline on add**: adding a ccTLD now queues a `run_openintel` for the active ccTLDs, so the new TLD is baselined immediately instead of waiting for the next Sunday (the first run caches everything and reports nothing; use **Recheck** for immediate matches on already-seen domains).
- Docs: `README.md`, `md/CONFIGURACION-worker.md` and `worker/config.ini.example` clarify that `tlds` is a fallback; fixed the OpenINTEL timer day in the install message and the docs (Sundays 17:00 Europe/Madrid).
- Test: `test_openintel_resolve_tlds_precedence` covers panel > config > `--tlds` precedence.

## [v1.6.8] - 2026-09-20

### Added - Printable reports by keyword (and keyword groups)

- **New "Informes" tab**: a report builder (`reports.php`) where you select one or more keywords (or a whole group) and generate a report with **all the data** collected for each matched domain.
- **Keyword groups**: keywords can be organised into named groups (a keyword belongs to **at most one** group). Group CRUD from the Reports page; deleting a group ungroups its keywords. New `keyword_groups` table + `keywords.group_id` migration.
- **Printable report** (`report_view.php`): header (generated at, user, keywords, filters), a **Summary** table (domains, new, good/bad/observing/untagged, malicious/suspicious) and a **per-keyword section** listing Domain, TLD, First Seen, Created (+NEW), Expiration, Registrar, Name Servers, Tag, VT, Watchlist, Source and Historical. Sections break per keyword when printing and interactive controls are hidden by the print stylesheet. Use the browser's **Print / Save as PDF**.
- **Filters**: period (all / 24h / 7d / 30d), state (all / good / bad / observing / untagged / watchlist / historical), source (CZDS / OpenINTEL) and an "include tagged / historical / old" toggle. Default view follows the same visibility rules as Notifications.
- The default visibility rules were extracted to `includes/report.php` (`matchVisibilityClauses()`) and are now shared by `notifications.php` and the reports, so both stay in sync.

## [v1.6.7] - 2026-09-20

### Fixed - WHOIS for restricted ccTLDs (.es and similar)

- **Fail fast**: new `[whois] connect_timeout` (default 6s) so registries that refuse/block port 43 no longer stall ~20s per domain.
- **Statuses**: lookups now return `ok` / `unsupported` / `error`; the domain panel explains the reason ("This registry does not publish WHOIS/RDAP data (e.g. .es)") instead of a silent `N/A`.
- **Retry failed lookups**: `ajax_whois_request.php` only treats `status='ok'` rows as cached, so `error`/`unsupported` domains can be retried with the bulk button.
- **First seen fallback**: the panel now shows **First Seen (zone)** (`MIN(matches.first_seen)`, from CZDS/OpenINTEL) as a registration-date proxy when the registry publishes no creation date. The per-keyword match page already exposes this as its First Seen column.
- **Per-TLD overrides**: `[whois] rdap_overrides` (e.g. `de=https://rdap.denic.de/`), `whois_overrides` and `disabled_tlds` (default `es`), so restricted registries return `unsupported` without any network call.
- **Correct booleans**: `whois_confirm` (OpenINTEL) now parses `rdap_only`/`whois_fallback` properly (before, any non-empty string — including `"false"` — was truthy).

## [v1.6.6] - 2026-09-20

### Added - Bulk WHOIS and VirusTotal on the per-keyword match list

- **`keyword_matches.php`**: per-row checkboxes + "Select all visible", and bulk buttons **Fetch WHOIS (worker)** and **Check VirusTotal (worker)** for the selected domains (all visible rows on the page when nothing is selected). A new **VT** column shows the cached verdict badge, and a **Refresh** button reloads to pick up worker results.
- The two bulk actions (`fetchVisibleWhois` / `fetchVisibleVt`) were moved to a shared **`assets/bulk.js`** loaded from `templates/footer.php`, and the duplicate inline copies were removed from `notifications.php` (same behaviour; exports to workers respect the existing caps: WHOIS 200, VT 25 per request, cached domains skipped).

## [v1.6.5] - 2026-09-20

### Added - Per-keyword match review page

- **New `keyword_matches.php`**: from the Matches cell of a keyword you can now open (new tab) a read-only page listing **every domain ever matched** by that keyword, including those already discarded/validated (tagged good/bad), in the watchlist, or from a historical recheck — the ones with a visible count of 0.
- **Search and filters**: free-text search (domain/TLD), state filter (All / Good / Bad / Observing / In watchlist / Historical / Untagged) and source filter (CZDS / OpenINTEL), plus sortable columns (Domain, TLD, First Seen, Discovered) and pagination (100/page).
- **Access control**: reachable only from a keyword you own; `id` + `user_id` are enforced and a foreign/unknown id returns 404. Not linked from the navigation.
- The keyword **Matches** cell now links the visible count and the `(N total)` figure to the new page, and keeps a small icon to the Notifications view filtered by keyword.

## [v1.6.4] - 2026-09-20

### Added - Live keyword-recheck status and a manual Refresh button

- **Keywords page auto-refresh**: the admin recheck controls are now a live section with an `#activity-watcher`, so after queuing "Recheck All Cached Domains" the status (Running with a progress bar, Queued, Completed or Idle) and the Stop button update on their own, and refresh once when the worker finishes. The keyword table is a live section too, so its *Matches* counts catch up automatically.
- **Manual Refresh button**: a new `[data-refresh-live]` button refreshes those sections **in place** (AJAX GET, no page reload, no lost scroll) via the exposed `App.refreshLiveSections()`; it falls back to a GET navigation.
- **PRG on recheck**: queuing a recheck now stores a flash message and redirects to `/keywords.php` (like Stop Recheck), so refreshing never resubmits the form.

## [v1.6.3] - 2026-09-20

### Fixed - Admin hit the keyword limit and was told to contact themselves

- **Admins are now unlimited**: `getMaxKeywords()` returns `0` (unlimited) when the user `is_admin = 1`, so an administrator can no longer be blocked by the stored `users.max_keywords`. The value keeps governing regular users, which the admin sets per user in **Admin → Users**.
- **New default raised to 20** for regular users (was 10): `register.php` now sets it explicitly, the schema migration uses `DEFAULT 20`, and a guarded one-time migration raises existing regular users still on the old default of 10. It records `settings.max_keywords_default_20`, so a later manual value is respected, and admins are left untouched.
- **Message**: "Contact the administrator" is only shown to regular users; an admin sees "Increase it in Admin → Users".
- **Admin → Users**: admin rows now display *Unlimited* instead of the numeric limit.

## [v1.6.2] - 2026-09-20

### Fixed - Login fields still looked misaligned

- **Offset focus ring**: the global `input:focus-visible` rule draws a 2px outline 2px *outside* the box, so the autofocused username looked bigger and shifted next to the password. Auth fields now keep the focus indication on the field itself (no offset outline).
- **Uniform fields**: auth inputs now share the same surface background, and Chrome's autofill background/text colours are neutralised so the prefilled username matches the password field.

## [v1.6.1] - 2026-09-20

### Fixed - Misaligned login fields and top navigation

- **Full-width text fields**: Materialize v2 dropped the v1 `width: 100%` on `.input-field` inputs and textareas, so they collapsed to the browser default size and no longer lined up with the submit button (visible on Login/Register). Restored the full-width rule.
- **Navbar baseline**: the dropdown triggers (Admin, account) and the theme toggle sat off the text baseline because Materialize v2 renders nav links as blocks and the caret icon floats. Nav links are now flex rows with the caret inline and vertically centred.

## [v1.6.0] - 2026-09-20

### Added - Automatic daily ICANN run + weekly OpenINTEL schedule

- **Daemon auto-daily (CZDS)**: in daemon mode the worker now runs one full cycle per local day after a configurable time, so **no cron is needed** (a `--once` cron job would be silently skipped while the daemon holds `worker.lock`). New `[worker]` settings: `auto_daily = true`, `daily_run_time = 04:00`, `daily_run_timezone = Europe/Madrid`.
- **No retry loops**: the local `last_daily_attempt` marker records the attempt even when the run fails (e.g. an invalid ICANN token), so the daemon does not hammer the API every poll. The daily guard still skips TLDs already processed today, and a host that was off at the scheduled time catches up on the next poll.
- **OpenINTEL weekly timer** moved to **Sundays 17:00 Europe/Madrid** (`tdl-openintel.timer`, `Persistent=true`).
- Tests: `resolve_daily_schedule` / `daily_cycle_due` coverage in `worker/tests.py`.

## [v1.5.0] - 2026-09-19

### Added - VirusTotal domain reputation (batch + cache)

- **Worker**: new `worker/virustotal.py` (API v3) and a `vt_lookup` command. Classifies each domain as `malicious` (malicious>0) > `dga` (VT `dga` tag) > `suspicious` (suspicious>0) > `clean`, and respects the free plan limits: `[virustotal] rate_delay_seconds = 16` (4/min) and `daily_limit = 500` (counter `vt_usage` in `worker.db`, reset per UTC day). On HTTP 429/403 it stops the batch. Results are posted to the web (`api/v1/vt_results.php`) and cached in `domain_vt`.
- **Notifications**: new **VT column** next to the domain with a badge (`MALICIOUS`/`DGA`/`SUSPICIOUS`/`CLEAN`/`—`) and a **Check VirusTotal (worker)** batch button for the selected/visible domains (capped at 25 per request, skips cached unless forced).
- **Domain panel** (Notifications, Dashboard and Watchlist): a **VirusTotal** section showing the verdict, malicious/suspicious counts and tags, plus a per-domain **Check VirusTotal** button (`assets/vt.js`).
- New endpoints `ajax_vt_request.php`, `ajax_vt_cache.php`, `api/v1/vt_results.php`; new `domain_vt` table and `.vt-badge` styles. `[virustotal] api_key` in `config.ini`.
- Note: the free API does not return an explicit DGA verdict; DGA is only flagged when VT tags the domain, otherwise it is treated as clean.

### Fixed - TLD tabs did not refresh after forcing a task

- The TLD table row poll now starts **always** (not only when a task was active at load) and refreshes when the activity watcher fires `tdl:refreshed` (emitted by `js/app.js` after a section refresh), so a forced run updates without F5.
- Added a **Refresh** button on each TLD tab (ICANN/ccTLD) that reloads the current tab.

## [v1.4.7] - 2026-09-19

### Fixed - Keywords page slow to load

- **Missing index on `notifications(match_id)`**: the Keywords page computes each keyword's visible match count, which looked up notifications by `match_id` with no index, forcing a scan of `notifications` per match (`~matches × notifications`). Added a composite index `notifications(match_id, user_id)` (used as a covering index).
- **Rewrote the Keywords query** from a correlated subquery per keyword to a **single-pass `LEFT JOIN` + `GROUP BY`**, so the whole list is one query. Semantics are identical (verified old vs new count for visible/hidden/watchlist/tagged/observing/old cases).
- Added `matches(keyword_id, is_historical)` (skip historical matches quickly) and `matches(discovered_at)` (dashboard/notifications ordering) indexes.
- `EXPLAIN QUERY PLAN` now shows `SEARCH n USING COVERING INDEX idx_notif_match_user (match_id=? AND user_id=?)`.

## [v1.4.6] - 2026-09-19

### Added / Changed - unified data across sources, scoped recheck

- **Unified domain lookup**: the dashboard "Domain lookup" now searches **both** caches and shows them in one list: CZDS gTLDs (`domains_cache` + compact hash cache) **and** OpenINTEL ccTLDs (`cctld_seen`). Each result is tagged `(gTLD)` or `(ccTLD/CT)`. So a `.io` domain is found in the same place as a gTLD.
- **One Recheck with selectable scope** (no more split tools):
  - Command `recheck_keywords` accepts `{sources:[openintel|czds], tlds:[...], max_age_days, max_domains}`.
  - **Default (quick) = ccTLD only**, so it never scans the whole ICANN/CZDS cache.
  - The **ICANN part is skipped** unless you select its TLDs or set a `max_domains` cap, and can be limited by TLD and age.
  - Runs in the daemon for a single unified progress; `recheck_status` now stores/display the `source`.
- **Admin → Recheck tab**: origin checkboxes (ccTLD / ICANN), a TLD multi-select (grouped by source, with cached counts), `max_age_days`, `max_domains`, a live **estimated domain count**, and Stop. The status block (not the form) is the live-refreshed section, so selections are preserved.
- New `[worker] recheck_max_domains` config (0 = no cap).

## [v1.4.5] - 2026-09-19

### Fixed

- **OpenINTEL commands stuck in `running`**: `worker/openintel.py` used `json.dumps()` in its status reporting but never imported `json`, so every report raised `NameError`, was swallowed, and the command never left `running` even though the job had finished. Added the missing import and made reporting failures **warn** (they are no longer silent).
- The importer also reports `failed` if it cannot acquire the OpenINTEL lock (another run in progress) instead of exiting silently.
- **Zombie processes**: the daemon now reaps finished detached children (`reap_children()`), so the OpenINTEL child no longer lingers as `<defunct>`.
- Log line now says `import`/`recheck`/`test` instead of always "import".

## [v1.4.4] - 2026-09-19

### Fixed

- **OpenINTEL run visibility**: the `run_openintel` command was marked `completed` immediately with `{"started": true}`, so the UI could not tell whether the import/recheck had finished or what it found.
  - The daemon now keeps the command **`running`** and passes `--command-id` to the detached `openintel.py`, which reports **progress** (checked/total/matches) and the **final summary** (or error) back through the command.
  - The OpenINTEL tab's run status is now a live section, so it refreshes automatically while running and shows the final result (e.g. `checked X / Y domains · N match(es)` for a recheck).

## [v1.4.3] - 2026-09-19

### Added

- **OpenINTEL recheck**: match the already-cached ccTLD domains against the current keywords. Because the first run is a baseline that caches without notifying, this lets you mine the cached domains.
  - CLI: `openintel.py --recheck [--tlds io,es,...]`.
  - Admin → TLDs → ccTLD (OpenINTEL) → **Match cached** (queues `run_openintel` with `{"recheck": true}`).
  - Matches are flagged **historical** (`is_historical=1`, `source='ct'`), so they are hidden from the default "new" listings and visible via the **Include tagged / historical** toggle, mirroring the CZDS recheck.

## [v1.4.2] - 2026-09-19

### Fix

- **OpenINTEL directory depth**: the ccTLD lists have an extra **`day=NN`** level (`tld=io/year=2026/month=09/day=14/...`). The parser now descends `day=` directories (falling back to files directly under the month) and picks the latest day.
- **File format**: the lists are **`.csv.gz`** (one apex domain per line, no header), not parquet. `read_domains()` now dispatches by extension and reads CSV gzip natively.

### Changed

- **`pyarrow` is optional** (only needed if a dataset is served as parquet). It was removed from the required dependencies; `install.sh`/`update.sh` no longer force-install it. The PEP 668 virtualenv support remains available via `setup_venv.sh`.

## [v1.4.1] - 2026-09-19

### Fix

- **OpenINTEL index parser**: the download index uses **unencoded** `=` links (`tld=io`, `year=2026`, `month=09`) and a `301` from `tld=io` to `tld%3Dio/`. The parser now navigates the **real hrefs** with `urljoin` + `unquote` and follows redirects, accepting `=` and `%3D` alike, instead of building `tld%3D…/year%3D…` URLs. This is why `.io` stayed at `No data`.
- **OpenINTEL agreement cookie** is now sent on the index and file requests, and the `no_data` case is logged instead of failing silently.

### Web UI

- **Add ccTLD** form on the OpenINTEL tab, visible even when the list is empty (breaks the chicken-and-egg: you could not add the first ccTLD).
- The last `run_openintel` command status/result is shown on the tab, with a pointer to the worker log.

### Install / update

- New `worker/setup_venv.sh` and virtualenv-aware `install.sh`/`update.sh` (Debian/Ubuntu block system-wide `pip` via PEP 668). `pyarrow` is installed explicitly; the systemd units use `worker/.venv/bin/python` when present. `.gitignore` now ignores `.venv/`.

## [v1.4.0] - 2026-09-19

### New data source: OpenINTEL ccTLD import (optional, weekly)

- **ccTLD coverage**: CZDS only covers gTLDs, so the worker can now import the weekly **apex-domain lists** published by [OpenINTEL](https://www.openintel.nl/data/domain-lists/cctld-names/) (from CT logs) for country-code TLDs like `.io`, `.es`, `.fr`.
- **Separate worker module** `worker/openintel.py` with its **own SQLite** (`data/openintel.db`): it never touches the CZDS pipeline. It is launched by `tdl-openintel.timer` (Mondays) or on demand from the admin (`run_openintel` command, run detached) and uses `pyarrow` to read the `.parquet.gz` files.
- **Baseline + diff**: the first run of a ccTLD caches everything without reporting; later runs report only domains seen for the first time, matched against keywords. Candidates are optionally confirmed with RDAP/WHOIS (`whois_confirm`) so old domains are filtered out.
- **Web separation of sources**: new `tlds.source` (`czds`/`openintel`) and `matches.source` (`czds`/`ct`). The TLDs admin page has tabs **ICANN (CZDS)** / **ccTLD (OpenINTEL)** with their own statuses and a **Run OpenINTEL** button; selection is scoped per source. New `api/v1/cctld_sync.php`.
- **Attribution**: OpenINTEL data is **CC BY-NC-SA 4.0** (non-commercial); the footer and README show the required attribution. Enable it in `config.ini` (`[openintel] enabled = true`, `accept_terms = true`).

### Fix

- **`last_ok_sync` was never set**: `tld_sync.php` compared `? = 1` with a parameter that PDO binds as text (`'1' = 1` is false in SQLite), so the "old validated domain" filter introduced in v1.3.65 never had a reference. Both `tld_sync.php` and `cctld_sync.php` now use `last_ok_sync = COALESCE(?, last_ok_sync)`.

## [v1.3.67] - 2026-09-19

### Dashboard - domain lookup against the worker cache

- **Removed the "Recent Matches" table** (and its period filter; the Matches KPI is now all-time). The full lists live on the Notifications page.
- **New "Domain lookup" card** below the detection graph: type a domain or part of it and search the **worker's local cache** (queued as a `search_domain` command; the worker answers on its next poll).
  - `exact` matches both the text cache and the compact hash cache (so it also works for huge TLDs like `.com`).
  - `prefix`/`contains` cover text-cached TLDs only; `contains` requires >= 4 characters, is capped at 100 rows and aborts after 5 s (partial results) so a full scan cannot hang the worker.
  - Partial input shows a result list; a single exact match opens the domain panel directly (WHOIS, classification, watchlist, VirusTotal) in a standalone container.
- New `ajax_domain_search.php` (queue + poll) available to any logged-in user, with a per-session rate limit and identical-pending-search reuse.
- Worker: new `search_cached_domains()` helper and `search_domain` command (`worker/scheduler.py`), plus a unit test.

## [v1.3.66] - 2026-09-19

### Web UI - sortable table columns (Keywords and Notifications)

- **Keywords page**: the `Keyword`, `Matches` and `Added` headers are now clickable. Clicking toggles asc/desc and shows ▲/▼ with `aria-sort`.
- **Notifications page** (including the list you get when opening a keyword's matches): sortable `Status`, `Domain`, `TLD`, `Keyword`, `First Seen`, `Created` and `Discovered` columns. Sorting is preserved across pagination and combined with the existing filters (`q`, `date`, `unread_only`, `new_days`, `archived`, `observing`).
- Sorting `Created` adds a `LEFT JOIN domain_whois` so it is done server-side, coherent with the WHOIS data.
- Whitelisted columns only (the `sort`/`dir` parameters are never interpolated into SQL).

## [v1.3.65] - 2026-09-19

### New classification state: "Insufficient info" (under observation)
- **New third tag `observing`** alongside good/bad. The domain panels (Dashboard, Notifications and Watchlist) now show an **Insufficient info** button and the row action menu in Notifications has the equivalent entry. Domains under observation remain visible (they are not hidden).
- `domain_tags.tag` no longer has a `CHECK` constraint (safe table rebuild preserving rows), so further states can be added later; values are validated in PHP (`ajax_tag_domain.php`, `api/v1/domain_tags.php`).
- Chips/badges support the third state (`.tag-chip.observing`, warning tone) on all three pages.

### Hide validated domains registered before the last successful scan
- New **`tlds.last_ok_sync`**, advanced only by a real successful scan (`downloaded`, `not_modified`, `baselined`).
- New **`domain_whois.creation_ts`** (UTC, normalized with `strtotime()`) so SQLite can compare raw WHOIS dates; `COALESCE(creation_ts, datetime(creation_date))` is used in queries.
- The default "new" views (Notifications list + bulk delete + hidden counter, Dashboard KPIs/sparkline/recent matches and the Keywords match counter) now hide a domain whose WHOIS creation date is **older than `last_ok_sync - new_domain_days`**. Domains under observation are exempt (they stay in the list).
- Notifications adds an **Only observing** filter and the existing toggle is renamed **Include tagged / historical / old**.

## [v1.3.64] - 2026-09-19

### Web UI - partial auto-refresh when a process finishes

- **New activity probe** `ajax_worker_activity.php` (`getWorkerActivity()` in `includes/auth.php`): reports whether the worker, a recheck or a queued command is active, plus the worker version. Available to any logged-in user.
- **Partial refresh, no full reload**: pages mark the parts that change with `data-live-section` (plus an `#activity-watcher` with the initial state). While work is active those sections are re-fetched every few seconds and refreshed a final time when it finishes. Forms, scroll position and open menus are preserved.
- **Admin panel**: Worker Status, Live Worker Progress, Recheck, Recent/Pending Commands and Worker/Sync Logs now update themselves. The broken bespoke polls (the browser poll of `/api/v1/worker_status.php` lacked the API key, and the recheck poll only started if it was already running) were removed in favour of the shared mechanism.
- **TLDs page**: the table poll now starts when a run is merely **queued** (previously it only started if the worker was already running, so a queued Refresh/Force never updated), and the status summary refreshes itself.
- **Dashboard**: stats, sparkline, recent matches and the admin worker-health card refresh while a run is in progress and once it ends, so new matches appear without F5.
- **System Update**: after a successful self-update the page now redirects (PRG) so the freshly installed files and version are loaded; the success message is kept via a flash.

## [v1.3.63] - 2026-09-19

### Worker - TLD baseline (only new delegations since the last validation)
- **First scan of a TLD is a baseline**: the worker populates `domains_cache` but does **not** emit matches, so a fresh install, a new TLD, a cleared `worker.db` or a force re-download no longer floods old domains as "new".
- **Cache-mode guard**: if a TLD switches between the text cache and the compact hash cache, that run only repopulates the cache and does not emit matches (the anti-join would otherwise run against an empty table).
- New `tld_meta.baselined` / `tld_meta.cache_mode` columns (additive, safe migration). The TLDs page/admin panel shows a `Baselined` status.
- **Recheck matches are flagged `is_historical=1`** so they no longer appear as new domains.

### Web - hide tagged and historical domains from the "new" listings
- New `matches.is_historical` column (additive, safe migration); `api/v1/matches.php` stores the worker flag.
- **Notifications**: by default hides historical matches and domains already tagged good/bad. New **Include tagged / historical** toggle, hidden-count notice, and filter-aware bulk delete.
- **Dashboard**: recent matches, KPIs and the 30-day sparkline exclude tagged/historical matches so they agree with the Notifications page.
- **Admin → System → New-domain listing**: one-off, reversible **Archive all current matches** / **Restore archived** action to clean the listing of matches that predate the baseline rule.

## [v1.3.62] - 2026-09-19

### Fix
- **Navbar icons**: the top menu icons used `class="material-icons left"`, and Materialize v2 styles `i.left` as `float:left; margin-left:-8px`, which pushed them out of the flow and mixed them with the previous item's text. Removed the icons from the top nav links (Dashboard, Keywords, Notifications, Watchlist, TLDs, Admin, account, Login/Register), leaving clean text. The dropdown caret (`arrow_drop_down`) and the theme toggle icon are kept. Icons in the dropdowns and the mobile sidenav are unchanged.

## [v1.3.61] - 2026-09-19

### Web UI — warm "brown pastel" theme, icon spacing and sticky footer
- **Light theme re-palette to warm brown pastels** (was too blue): background `#faf6f1`, primary brown `#7a5c51`, warm surfaces/borders, brown links and navbar. **Danger stays red**; success/warning keep muted green/ochre; `info` moved from blue to warm taupe.
- **Dark theme warmed to match**: coffee-brown surfaces (`#241f1c`/`#2e2825`) with a tan accent (`#c9a48f`); danger stays red.
- **Icon spacing** in menus increased: navbar links 10px, dropdowns 12px, row action menus 10px, sidenav 14px, and buttons now have 8px around their icons.
- **Sticky footer**: the version bar stays at the bottom of the viewport when the content is short and moves down with longer content (body flex column + `main { flex: 1 0 auto }`).

## [v1.3.60] - 2026-09-19

### Fix
- **Navbar layout with Materialize v2.3.3**: the header used the v1 markup (`<nav>` + `.nav-wrapper` + `.sidenav-trigger`), but v2 activates the component with the **`.navbar`** class. Without it the menu rendered as a vertical bulleted list and the mobile trigger showed on desktop. Added `navbar` to the `<nav>`, right-aligned the flex menu, made `.nav-wrapper` transparent so the brand background shows, and show the sidenav trigger only below 993 px.

## [v1.3.59] - 2026-09-19

### Web UI — soft buttons + no forced dark mode
- **Buttons are pastel/tinted, no solid fills**: primary is a soft blue tint with blue text and danger a soft red tint with red text, so no more loud solid red/blue buttons.
- **Pagination, group chips and NEW badges** use the same soft tones.
- **`color-scheme: light` declared** so browsers with "auto dark mode" (Chrome/Edge) no longer forcibly darken the light theme. Dark mode remains available through the toggle.

## [v1.3.58] - 2026-09-19

### Web UI — "Soft Corporate" theme + light/dark mode
- **New pastel corporate palette** (dusty blue `#5e81ac` + muted greys) replacing the high-saturation purple/rainbow scheme ("no more eye-bleeding colours").
- **Light/dark mode with a toggle** in the navbar and the mobile sidenav; the choice is stored in `localStorage` and applied before paint (no flash of the wrong theme). Default is light.
- **Removed the rainbow buttons**: *Mark Good/Bad*, VirusTotal and similar are now soft/outline buttons with coloured icons; only **primary** and **danger** remain solid.
- **Stat cards, status badges, tag chips, alerts and notices** use soft semantic tones that adapt to the active theme.
- **Cache-busting**: CSS/JS are requested with `?v=<VERSION>` so a new release is picked up without a hard refresh.
- Materialize MD3 design tokens are mapped to the palette for **both** themes (inputs, checkboxes, switches, progress, pagination, links).

## [v1.3.57] - 2026-09-19

### Web UI — Materialize CSS integration
- **Full UI migration to Materialize CSS v2.3.3** (already bundled in `public_html/css`). `main.css` replaced by `css/app.css`; new `js/app.js` initialises components.
- **100% self-hosted, shared-hosting friendly**: Roboto + Material Icons are served locally from `public_html/fonts/` via `css/fonts.css` (no Google Fonts/CDN dependency). `.htaccess` declares the `.woff2` MIME type.
- **Layout**: Materialize navbar (`deep-purple`) with mobile sidenav, native dropdowns for Admin/Account, active-page highlighting and a footer showing the version.
- **Dashboard**: KPI stat-cards with icons, worker-health banner, 30-day sparkline, striped/hover tables and the inline domain-detail panel restyled.
- **Keywords / Notifications / Watchlist / Account / Login / Register**: `input-field` with floating labels and icons, Materialize switches, status badges, tag chips, action menus with Material icons, Materialize pagination and group chips.
- **Admin**: tabbed panel, Materialize progress bars for live worker/recheck, `status-*` badges, restyled users/commands/sync/tables, update and cleanup pages, and the standalone installer.
- **Fase 7 polish**: active nav state + `aria-current`, `aria-label` on icon-only controls, keyboard focus outline, fixed-position row action menus (no clipping on small screens) and mobile responsive tweaks.
- **Fixed**: created `public_html/VERSION` (was only at repo root) so `auth.php`/`update.php`/footer report the version correctly and worker version-mismatch detection works.
- **CI**: GitHub Actions workflow (`.github/workflows/ci.yml`) runs `php -l` over all PHP files and the Python worker unit tests on every push/PR to `main`.

## [v1.3.55] - 2026-09-19

### Layout
- **Web files migrated to `public_html/`**: all PHP, assets, `admin/`, `api/`, `templates/` moved under `public_html/` so the web DocumentRoot excludes `data/`, `worker/` and `env/`. PHP includes keep using `__DIR__`; absolute web paths are unchanged. `.htaccess` hardened.

## [v1.3.54] - 2026-09-19

### Web UI
- **Domain detail as an expandable table row** (`toggleDomainDetail`): replaces the overlay modal with a `<tr class="dpanel-row">` inserted below the clicked row, one panel open at a time. New `.dpanel-*` styles; the old overlay modal was removed.

## [v1.3.53] - 2026-09-19

### Web UI
- **Domain detail modal redesign** (index/notifications): structured header, labelled WHOIS grid, classification/watchlist sections and footer; CSS moved to the stylesheet; `style.display` toggling replaced by class toggle.

## [v1.3.52] - 2026-09-19

### Fix
- **Timezone**: all DB timestamps are UTC; added `fmt_date()` (UTC → Europe/Madrid) and applied it to every date displayed in the dashboard, notifications, watchlist, keywords, admin (worker/commands/logs/sync/recheck/TLDs) and the AJAX status endpoints.

## [v1.3.51] - 2026-09-19

### Web UI
- CSS extracted from `header.php` into an external stylesheet; navbar dropdowns switched from hover to click (no layout shift on load); **TLDs** promoted to a top-level navbar link; sticky navbar; **Email preferences** moved to `account.php`; responsive media queries for mobile.

## [v1.3.50] - 2026-09-19

### Fix
- **Live Worker Progress card always visible**: the TLD download/parse progress bar was hidden inside the Worker tab pane (introduced in v1.3.49), so it only appeared when that tab was active. Moved out of the tab system — now shows whenever the worker is running, matching the original behaviour.

## [v1.3.49] - 2026-09-19

### Worker
- **`sqlite_cache_mb` default raised to 2048 MB** (was 512). With the recommended 8 GB LXC, this avoids editing `config.ini` by hand on fresh deploys. On hosts with less RAM, lower it (e.g. 512). An explicit value in `config.ini` always wins, so existing installs are unaffected.

### Web UI reorganisation (no routes or endpoints changed)
- **Navbar**: split into two zones — App (Dashboard / Keywords / Notifications / Watchlist) and dropdowns for Account (email notifications, API key, logout) and Admin (Overview / Worker / Commands / Recheck / TLDs / Users / Sync / System). `TLDs` moved into the Admin dropdown. Refined dropdown styling reusing the existing `.action-menu-dropdown`.
- **Dashboard**: redesigned as an operational at-a-glance view — KPIs (keywords, matches in period, unread, last-24h new), a pure CSS/SVG "matches per day" sparkline, and the existing recent-matches table with its period filter. Removed the admin-only Keyword Recheck and Last Sync cards (they live in the Admin panel). A compact worker-health indicator is shown to admins and links to Admin Overview.
- **Admin panel** (`/admin/`): the monolithic page now exposes an in-place tabbed sub-navigation (Overview / Worker / Commands / Recheck / TLDs / Users / Sync / System), anchorable as `/admin/#worker`. The orphaned Cleanup and Update buttons left inside "Worker Status" now live under the System tab. `admin/tlds.php`, `admin/update.php` and `admin/cleanup.php` are unchanged; only their entry points moved.
- No API, AJAX, `.htaccess`, form `action=` or route changes. All existing bookmarks keep working.

## [v1.3.48] - 2026-09-18

### SQLite tuning for the parse (configurable)
- **Configurable page cache**: `[worker] sqlite_cache_mb` (default now **512 MB**, was a fixed 64 MB). With enough RAM this reduces page re-reads during the anti-join (`stage`) and inserts.
- **`synchronous=OFF` during the bulk parse only**: new `[worker] sqlite_synchronous_parse` (default `OFF`). It skips `fsync` on commits/checkpoints while a zone is parsed, then restores `NORMAL`. `worker.db` is a rebuildable cache, so the durability trade-off is bounded; set it to `NORMAL` to revert.
- No behaviour change to matching or reporting; both settings are read from `config.ini`.

## [v1.3.47] - 2026-09-18

### Parse phase timing (measurement only, no behaviour change)
- The worker now logs a per-TLD breakdown of where time goes:
  `[timing] .sbs parse=18.3s stage=15.2s insert=6.8s match=1.8s commit=0.4s download=2.1s total=42.1s`
  where `parse` is gzip + line scanning, `stage` is dedupe/temp-insert/anti-join,
  `insert` is writing new domains, `match` is keyword matching, `commit` is
  commit + WAL checkpoint and `download` is the transfer.
- Purely additive logging to decide, with data, the next optimisation step
  (SQLite cache/synchronous vs CPU). No configuration or durability changes.

## [v1.3.46] - 2026-09-18

### On-demand WHOIS/RDAP lookups executed by the worker
- **Worker-side lookup** (`worker/whois.py`): RDAP via the IANA bootstrap (cached 7 days) with a **WHOIS port 43 fallback** for TLDs without RDAP. Extracts registrar, creation/expiration dates and nameservers.
- **New command `whois_lookup`**: the web queues it (single domain or a batch) and the worker performs the lookup and posts results.
- **`api/v1/whois_results.php`**: upserts `domain_whois` (extended with `name_servers`, `source`, `status`, `updated_at`).
- **Web UI**: domain modal now shows cached data instantly and a **Fetch WHOIS (worker)** button that queues the lookup and polls for the result. New endpoints `ajax_whois_cache.php`, `ajax_whois_request.php`, `ajax_whois_result.php`; CSRF via `X-CSRF-Token` (meta tag added to the layout). Shared modal logic in `assets/whois.js`.
- **Batch lookups**: Notifications page has a **Fetch WHOIS (worker)** button for the selected (or all visible) domains.
- **Removed the blocking synchronous prefetch** in `notifications.php` (it queried RDAP one-by-one with a 3 s timeout on every page load). The list now renders immediately and is enriched on demand.
- **Faster command latency**: daemon poll interval is configurable (`[worker] poll_interval`, default 20 s); `tdl-worker.service`/`install.sh` no longer force 60 s.

### Notes
- WHOIS/RDAP is not DNS; no local resolver is involved. Nameservers come from the registration data.
- Registry rate limits: lookups are spaced by `[whois] rate_delay` and capped per request.

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
