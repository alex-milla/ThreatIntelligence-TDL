<?php
/**
 * ThreatIntelligence-TDL Database Layer
 * SQLite wrapper with automatic table creation
 */

class Database {
    private static ?PDO $instance = null;
    
    public static function get(): PDO {
        if (self::$instance === null) {
            $dbDir = __DIR__ . '/../data';
            if (!is_dir($dbDir)) {
                mkdir($dbDir, 0755, true);
            }
            $dbPath = $dbDir . '/app.db';
            self::$instance = new PDO('sqlite:' . $dbPath);
            self::$instance->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            self::$instance->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            self::createTables();
        }
        return self::$instance;
    }
    
    private static function createTables(): void {
        $db = self::$instance;
        
        $db->exec("CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_key TEXT UNIQUE,
            is_active INTEGER DEFAULT 1,
            is_admin INTEGER DEFAULT 0,
            email_notifications INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");
        
        $db->exec("CREATE TABLE IF NOT EXISTS tlds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            is_active INTEGER DEFAULT 0,
            last_sync TEXT,
            status TEXT
        )");
        
        $db->exec("CREATE TABLE IF NOT EXISTS keywords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            keyword TEXT NOT NULL,
            is_active INTEGER DEFAULT 1,
            match_count INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )");
        
        $db->exec("CREATE INDEX IF NOT EXISTS idx_keywords_user ON keywords(user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_keywords_active ON keywords(is_active)");
        
        $db->exec("CREATE TABLE IF NOT EXISTS matches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            keyword_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            tld TEXT NOT NULL,
            discovered_at TEXT NOT NULL,
            synced_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (keyword_id) REFERENCES keywords(id),
            UNIQUE(keyword_id, domain)
        )");
        
        $db->exec("CREATE INDEX IF NOT EXISTS idx_matches_keyword ON matches(keyword_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_matches_domain ON matches(domain)");
        
        $db->exec("CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            match_id INTEGER NOT NULL,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (match_id) REFERENCES matches(id)
        )");
        
        $db->exec("CREATE INDEX IF NOT EXISTS idx_notif_user ON notifications(user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_notif_read ON notifications(is_read)");
        
        $db->exec("CREATE TABLE IF NOT EXISTS sync_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            source TEXT,
            records_received INTEGER DEFAULT 0,
            records_inserted INTEGER DEFAULT 0,
            error TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS commands (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            command TEXT NOT NULL,
            payload TEXT,
            status TEXT DEFAULT 'pending',
            result TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            executed_at TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS worker_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            level TEXT,
            message TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS worker_status (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            last_heartbeat TEXT,
            last_run TEXT,
            tlds_processed INTEGER DEFAULT 0,
            domains_processed INTEGER DEFAULT 0,
            matches_found INTEGER DEFAULT 0,
            is_running INTEGER DEFAULT 0,
            version TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            username TEXT,
            attempted_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_login_ip ON login_attempts(ip_address, attempted_at)");
        
        $db->exec("CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )");

        // Per-user dismissible reminders (e.g. the monthly excluded-domain review).
        $db->exec("CREATE TABLE IF NOT EXISTS user_reminders (
            user_id INTEGER NOT NULL,
            key TEXT NOT NULL,
            dismissed_at TEXT DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (user_id, key)
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS api_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip_address TEXT NOT NULL,
            api_key TEXT,
            endpoint TEXT,
            requested_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_api_ip ON api_requests(ip_address, requested_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_api_key ON api_requests(api_key, requested_at)");

        $db->exec("CREATE TABLE IF NOT EXISTS recheck_status (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            is_running INTEGER DEFAULT 0,
            total_domains INTEGER DEFAULT 0,
            checked_domains INTEGER DEFAULT 0,
            matches_found INTEGER DEFAULT 0,
            started_at TEXT,
            completed_at TEXT
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS domain_whois (
            domain TEXT PRIMARY KEY,
            creation_date TEXT,
            expiration_date TEXT,
            registrar TEXT,
            cached_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        $db->exec("CREATE TABLE IF NOT EXISTS domain_vt (
            domain TEXT PRIMARY KEY,
            verdict TEXT,
            malicious INTEGER DEFAULT 0,
            suspicious INTEGER DEFAULT 0,
            harmless INTEGER DEFAULT 0,
            undetected INTEGER DEFAULT 0,
            reputation INTEGER DEFAULT 0,
            tags TEXT,
            last_analysis_date TEXT,
            checked_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // abuse.ch domain validation (URLhaus malware hosts + ThreatFox IOCs).
        $db->exec("CREATE TABLE IF NOT EXISTS domain_abusech (
            domain TEXT PRIMARY KEY,
            verdict TEXT,
            urlhaus_verdict TEXT,
            urlhaus_url_count INTEGER DEFAULT 0,
            urlhaus_online INTEGER DEFAULT 0,
            urlhaus_dbl TEXT,
            threatfox_verdict TEXT,
            threatfox_matches INTEGER DEFAULT 0,
            threat_type TEXT,
            malware_family TEXT,
            confidence INTEGER DEFAULT 0,
            tags TEXT,
            last_analysis_date TEXT,
            checked_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Dormant-domain intelligence tracking. Each (domain, keyword) pair is
        // followed for the keyword's tracking window; the worker re-validates it
        // periodically and reports activation signals.
        $db->exec("CREATE TABLE IF NOT EXISTS domain_tracking (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            keyword_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            first_seen TEXT,
            enrolled_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT,
            status TEXT DEFAULT 'tracking',
            baseline TEXT,
            check_count INTEGER DEFAULT 0,
            last_checked_at TEXT,
            next_check_at TEXT,
            activated_at TEXT,
            activated_reason TEXT,
            UNIQUE(domain, keyword_id)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_tracking_due ON domain_tracking(status, next_check_at)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_tracking_user ON domain_tracking(user_id)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_tracking_domain ON domain_tracking(domain)");

        $db->exec("CREATE TABLE IF NOT EXISTS domain_tracking_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tracking_id INTEGER NOT NULL,
            at TEXT DEFAULT CURRENT_TIMESTAMP,
            type TEXT,
            detail TEXT
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_tracking_events ON domain_tracking_events(tracking_id)");

        // Per-keyword tracking configuration (window + cadence). New keywords
        // default to tracking disabled.
        foreach ([
            "ALTER TABLE keywords ADD COLUMN tracking_enabled INTEGER DEFAULT 0",
            "ALTER TABLE keywords ADD COLUMN tracking_days INTEGER DEFAULT 90",
            "ALTER TABLE keywords ADD COLUMN tracking_interval_hours INTEGER DEFAULT 168",
            "ALTER TABLE keywords ADD COLUMN tracking_enroll_max_age_days INTEGER DEFAULT 30",
            "ALTER TABLE notifications ADD COLUMN kind TEXT DEFAULT 'match'",
        ] as $alter) {
            try {
                $db->exec($alter);
            } catch (PDOException $e) {
                // Column already exists.
            }
        }

        // One-time: the tracking cadence is now weekly (168 h) and no longer
        // exposed in the UI. Raise keywords still on the old 24 h default.
        $tiMigrated = $db->query("SELECT value FROM settings WHERE key = 'tracking_interval_default_168' LIMIT 1")->fetchColumn();
        if ($tiMigrated === false) {
            $db->exec("UPDATE keywords SET tracking_interval_hours = 168 WHERE tracking_interval_hours IS NULL OR tracking_interval_hours = 24");
            $db->exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('tracking_interval_default_168', '1')");
        }

        $db->exec("CREATE TABLE IF NOT EXISTS watchlist (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id),
            UNIQUE(user_id, domain)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_watchlist_user ON watchlist(user_id)");

        $db->exec("CREATE TABLE IF NOT EXISTS watchlist_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_watchlist_groups_user ON watchlist_groups(user_id)");

        // Keyword groups for reports. A keyword belongs to at most one group
        // (keywords.group_id), so deleting a group only ungroups its keywords.
        $db->exec("CREATE TABLE IF NOT EXISTS keyword_groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_keyword_groups_user ON keyword_groups(user_id)");

        // Immutable snapshots of generated reports (history). The full report
        // data is stored gzip-compressed so an old report never changes even if
        // the underlying matches/WHOIS/VT data does.
        $db->exec("CREATE TABLE IF NOT EXISTS report_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT,
            group_id INTEGER,
            group_name TEXT,
            filters TEXT,
            keywords TEXT,
            data BLOB,
            domains INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_report_history_user ON report_history(user_id, created_at DESC)");

        // tag has no CHECK so new classification states (e.g. observing) can be
        // added without migrating; values are validated in PHP.
        $db->exec("CREATE TABLE IF NOT EXISTS domain_tags (
            domain TEXT PRIMARY KEY,
            tag TEXT,
            note TEXT,
            created_by INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Manual report queue: per-user domains the analyst has validated and
        // wants in the next report. Keyed per (domain, group_key) so a domain
        // that matches keywords in several groups can be reported in each
        // group's report. `reported_at`/`report_id` are stamped when a report is
        // generated, so pending items accumulate across days and a later report
        // picks up everything since the last generation. `group_key` is the
        // keyword group id as text, or '' for ungrouped keywords.
        $db->exec("CREATE TABLE IF NOT EXISTS report_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            group_key TEXT NOT NULL DEFAULT '',
            added_at TEXT DEFAULT CURRENT_TIMESTAMP,
            reported_at TEXT,
            report_id INTEGER,
            UNIQUE(user_id, domain, group_key)
        )");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_report_queue_user ON report_queue(user_id, reported_at)");

        // Safe migration: add max_keywords if it doesn't exist yet
        try {
            $db->exec("ALTER TABLE users ADD COLUMN max_keywords INTEGER DEFAULT 20");
        } catch (PDOException $e) {
            // Column already exists
        }

        // One-time: raise regular users still on the old default (10) to 20.
        // Guarded by a settings marker so an admin can later set a user back to 10.
        $mkMigrated = $db->query("SELECT value FROM settings WHERE key = 'max_keywords_default_20' LIMIT 1")->fetchColumn();
        if ($mkMigrated === false) {
            $db->exec("UPDATE users SET max_keywords = 20 WHERE is_admin = 0 AND max_keywords = 10");
            $db->exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('max_keywords_default_20', '1')");
        }

        // Safe migration: add first_seen to matches
        try {
            $db->exec("ALTER TABLE matches ADD COLUMN first_seen TEXT");
        } catch (PDOException $e) {
            // Column already exists
        }

        // Safe migration: flag recheck/archived matches. They are hidden from
        // the "new" listings by default (see notifications.php / index.php).
        try {
            $db->exec("ALTER TABLE matches ADD COLUMN is_historical INTEGER DEFAULT 0");
        } catch (PDOException $e) {
            // Column already exists
        }

        // Safe migration: match origin ('czds' zone files or 'ct' OpenINTEL).
        try {
            $db->exec("ALTER TABLE matches ADD COLUMN source TEXT DEFAULT 'czds'");
        } catch (PDOException $e) {
            // Column already exists
        }

        // Safe migration: add group_id to watchlist
        try {
            $db->exec("ALTER TABLE watchlist ADD COLUMN group_id INTEGER DEFAULT NULL");
        } catch (PDOException $e) {
            // Column already exists
        }

        // Safe migration: a keyword belongs to at most one report group.
        try {
            $db->exec("ALTER TABLE keywords ADD COLUMN group_id INTEGER DEFAULT NULL");
        } catch (PDOException $e) {
            // Column already exists
        }
        try {
            $db->exec("CREATE INDEX IF NOT EXISTS idx_keywords_group ON keywords(group_id)");
        } catch (PDOException $e) { }

        // Safe migration: add live progress columns to worker_status
        try {
            $db->exec("ALTER TABLE worker_status ADD COLUMN current_tld TEXT");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE worker_status ADD COLUMN total_tlds INTEGER DEFAULT 0");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE worker_status ADD COLUMN current_action TEXT");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE worker_status ADD COLUMN current_command TEXT");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE worker_status ADD COLUMN current_command_id INTEGER");
        } catch (PDOException $e) { }

        // Safe migration: command lifecycle finished_at timestamp
        try {
            $db->exec("ALTER TABLE commands ADD COLUMN finished_at TEXT");
        } catch (PDOException $e) { }

        // Safe migration: per-TLD download report columns (worker -> web)
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN records_total INTEGER DEFAULT 0");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN records_new INTEGER DEFAULT 0");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN zone_size INTEGER DEFAULT 0");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN zone_file_mtime TEXT");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN last_error TEXT");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN retry_attempts INTEGER DEFAULT 0");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN next_retry TEXT");
        } catch (PDOException $e) { }
        // TLD origin: 'czds' (ICANN gTLDs) or 'openintel' (ccTLDs).
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN source TEXT DEFAULT 'czds'");
        } catch (PDOException $e) { }

        // Safe migration: extend domain_whois with nameservers + lookup metadata
        try {
            $db->exec("ALTER TABLE domain_whois ADD COLUMN name_servers TEXT");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE domain_whois ADD COLUMN source TEXT");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE domain_whois ADD COLUMN status TEXT");
        } catch (PDOException $e) { }
        try {
            $db->exec("ALTER TABLE domain_whois ADD COLUMN updated_at TEXT");
        } catch (PDOException $e) { }

        // Safe migration: normalized UTC creation timestamp for SQL date filters
        // (raw WHOIS dates can be non-ISO, which SQLite's datetime() cannot parse).
        try {
            $db->exec("ALTER TABLE domain_whois ADD COLUMN creation_ts TEXT");
        } catch (PDOException $e) { }

        // Safe migration: last *successful* sync per TLD, used to hide validated
        // domains registered before the previous scan.
        try {
            $db->exec("ALTER TABLE tlds ADD COLUMN last_ok_sync TEXT");
        } catch (PDOException $e) { }

        // Safe migration: which cache the recheck is scanning (czds/openintel).
        try {
            $db->exec("ALTER TABLE recheck_status ADD COLUMN source TEXT");
        } catch (PDOException $e) { }

        // Safe migration: allow additional classification states (e.g. observing)
        // by dropping the old CHECK(tag IN ('good','bad')) constraint. SQLite
        // cannot alter a CHECK, so the table is rebuilt preserving its rows.
        try {
            $dtSql = $db->query("SELECT sql FROM sqlite_master WHERE type='table' AND name='domain_tags'")->fetchColumn();
            if (is_string($dtSql) && stripos($dtSql, 'CHECK(tag') !== false) {
                $db->exec("ALTER TABLE domain_tags RENAME TO domain_tags_old");
                $db->exec("CREATE TABLE domain_tags (
                    domain TEXT PRIMARY KEY,
                    tag TEXT,
                    note TEXT,
                    created_by INTEGER NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )");
                $db->exec("INSERT INTO domain_tags (domain, tag, note, created_by, created_at)
                           SELECT domain, tag, note, created_by, created_at FROM domain_tags_old");
                $db->exec("DROP TABLE domain_tags_old");
            }
        } catch (PDOException $e) {
            // Leave the table as-is; callers still validate tag values in PHP.
        }

        // Safe migration (v1.13.2): the report queue moved from one entry per
        // (user, domain) to one per (user, domain, group). SQLite cannot alter a
        // UNIQUE constraint, so the table is rebuilt and each existing pending
        // domain is expanded to one row per group of its matched keywords.
        try {
            $rqCols = $db->query("PRAGMA table_info(report_queue)")->fetchAll(PDO::FETCH_COLUMN, 1);
            if (is_array($rqCols) && !in_array('group_key', $rqCols, true)) {
                $db->exec("ALTER TABLE report_queue RENAME TO report_queue_old");
                $db->exec("CREATE TABLE report_queue (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    domain TEXT NOT NULL,
                    group_key TEXT NOT NULL DEFAULT '',
                    added_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    reported_at TEXT,
                    report_id INTEGER,
                    UNIQUE(user_id, domain, group_key)
                )");
                $oldRows = $db->query("SELECT user_id, domain, added_at, reported_at, report_id FROM report_queue_old")->fetchAll();
                $insRow = $db->prepare("INSERT OR IGNORE INTO report_queue
                    (user_id, domain, group_key, added_at, reported_at, report_id)
                    VALUES (?, ?, ?, ?, ?, ?)");
                $grpStmt = $db->prepare("SELECT DISTINCT COALESCE(CAST(k.group_id AS TEXT), '') AS gk
                    FROM matches m JOIN keywords k ON k.id = m.keyword_id
                    WHERE k.user_id = ? AND m.domain = ?");
                foreach ($oldRows as $r) {
                    $grpStmt->execute([$r['user_id'], $r['domain']]);
                    $keys = $grpStmt->fetchAll(PDO::FETCH_COLUMN);
                    if (empty($keys)) {
                        $keys = [''];
                    }
                    foreach (array_unique($keys) as $gk) {
                        $insRow->execute([
                            $r['user_id'], $r['domain'], (string)$gk,
                            $r['added_at'], $r['reported_at'], $r['report_id'],
                        ]);
                    }
                }
                $db->exec("DROP TABLE report_queue_old");
                $db->exec("CREATE INDEX IF NOT EXISTS idx_report_queue_user ON report_queue(user_id, reported_at)");
            }
        } catch (PDOException $e) {
            // Leave the table as-is; callers still resolve groups from keywords.
        }

        // Indexes that keep the keyword/dashboard queries fast on large data
        // (they are created after the column migrations so the columns exist).
        try {
            // notifications are looked up by (match_id, user_id) when counting a
            // keyword's visible matches (keywords.php). Composite so it can be a
            // covering index; also serves match_id-only lookups.
            $db->exec("CREATE INDEX IF NOT EXISTS idx_notif_match_user ON notifications(match_id, user_id)");
        } catch (PDOException $e) { }
        try {
            // Skip historical matches quickly when counting a keyword's matches.
            $db->exec("CREATE INDEX IF NOT EXISTS idx_matches_kw_hist ON matches(keyword_id, is_historical)");
        } catch (PDOException $e) { }
        try {
            // Dashboard/notifications order by discovery date.
            $db->exec("CREATE INDEX IF NOT EXISTS idx_matches_discovered ON matches(discovered_at)");
        } catch (PDOException $e) { }
    }
}
