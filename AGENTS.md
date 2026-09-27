# AGENTS.md — ThreatIntelligence-TDL

Guidance for AI agents and contributors working in this repository.

## What this is

Monitors new domain registrations across ICANN CZDS zone files (and optional
OpenINTEL ccTLD lists). Users define keywords; the worker detects new domains,
matches them and notifies the web UI.

Hybrid architecture:

- **`worker/`** — Python 3 daemon/CLI on an LXC/VPS. Downloads zones, parses,
  dedups in SQLite, matches keywords, pushes results to the web API.
- **`public_html/`** — PHP 8 + SQLite app on shared hosting. Users, keywords,
  notifications, reports, admin panel, and the worker API.

```
worker/ ──HTTPS X-API-Key──► public_html/api/v1/*.php ──► SQLite (data/app.db)
```

## Layout

| Path | Purpose |
|------|---------|
| `worker/scheduler.py` | Orchestrator: cycle, daemon, command dispatcher, updater |
| `worker/sync_client.py` | HTTP client for `api/v1` (the worker↔web contract) |
| `worker/parser.py`, `matcher.py`, `downloader.py` | Zone parsing/matching/downloads |
| `worker/{intel,openintel,whois,virustotal,abusech,cloudflare_radar}.py` | Enrichment |
| `worker/tests.py` | Worker unit tests (run via `pytest` or `python tests.py`) |
| `public_html/includes/auth.php` | Sessions, CSRF, rate limits, security headers |
| `public_html/includes/db.php` | SQLite schema + idempotent migrations |
| `public_html/includes/updater.php` | Self-update helpers (manifest, restore) |
| `public_html/includes/theme.php` | Light/dark theme resolution |
| `public_html/api/v1/` | Worker API (admin API key required) |
| `public_html/ajax_*.php` | Same-origin AJAX (session + CSRF) |
| `public_html/admin/` | Admin panel (users, TLDs, sync, system update) |
| `tests/` | PHP unit runner + Playwright E2E/accessibility |
| `docs/openapi.yaml` | Worker API contract |

## Commands

```bash
# PHP unit tests (dependency-free; no Composer)
php tests/run.php

# Lint every PHP file
find public_html -name '*.php' -print0 | xargs -0 -n1 php -l

# Worker tests with coverage (from worker/)
cd worker && pip install -r requirements.txt -r requirements-dev.txt && pytest

# E2E + accessibility (serves a throwaway seeded copy in .e2e/)
npm ci && npx playwright install chromium && npx playwright test
```

CI (`.github/workflows/ci.yml`) runs: php-lint, php-tests, worker pytest+coverage,
and the Playwright E2E/axe job.

## Conventions

- **Versions**: one release per change; bump **both** `VERSION` (worker) and
  `public_html/VERSION` (web) and add a `CHANGELOG.md` entry. Commit messages
  follow `vX.Y.Z: <summary>`.
- **No comments** unless they explain *why* (this repo is deliberate about it).
- PHP: prepared statements only; escape output with `htmlspecialchars`; CSRF via
  `validateCsrf()` on every state-changing POST; `requireAuth()`/`requireAdmin()`.
- Python: type hints, `configparser` for config, no user data stored server-side.
- **Backward compatibility matters**: the worker may run an older version than
  the web app. Do not remove or rename API response fields; add new ones.
- **UI layout v2**: the `ui_layout` setting (`classic` | `v2`) switches the
  analyst screens. v2 reuses the server-rendered markup and reinterprets it via
  `css/ui.css` + `assets/ui.js` (loaded only under `body.ui-v2`); it must not
  change form `name`/`action` values or the inline domain detail used by
  reports/print. Admins preview with `?ui=v2` / `?ui=classic`.

## Security invariants

- `getClientIp()` trusts proxy headers **only** behind a Cloudflare peer or with
  `TDL_TRUST_PROXY=1`.
- Session cookies are `HttpOnly` + `SameSite=Lax` (+ `Secure` on HTTPS).
- The worker API requires an **admin** API key and is rate-limited
  (`X-RateLimit-*` headers).
- The self-updater never touches `data/`, `config.ini` or operator-added files;
  it verifies ZIP entries against path traversal and keeps SHA-256 manifests.
- Secrets live in `worker/config.ini`, `env/`, `data/` — all gitignored.
- Deployment knobs (opt-in, no default change): `TDL_DATA_DIR` moves `app.db`
  outside the web root; `TDL_MAIL_FROM_DOMAIN` pins the notification From domain.

## Do not

- Commit `worker/config.ini`, `env/`, `data/`, `md/` or `skills/` (gitignored).
- Change the `api/v1` contract incompatibly (see `docs/openapi.yaml`).
- Edit `data/app.db` directly; use the schema migrations in `includes/db.php`.
