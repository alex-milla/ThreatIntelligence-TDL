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

        $db->exec("CREATE TABLE IF NOT EXISTS domain_tags (
            domain TEXT PRIMARY KEY,
            tag TEXT CHECK(tag IN ('good','bad')),
            note TEXT,
            created_by INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");

        // Safe migration: add max_keywords if it doesn't exist yet
        try {
            $db->exec("ALTER TABLE users ADD COLUMN max_keywords INTEGER DEFAULT 10");
        } catch (PDOException $e) {
            // Column already exists
        }

        // Safe migration: add first_seen to matches
        try {
            $db->exec("ALTER TABLE matches ADD COLUMN first_seen TEXT");
        } catch (PDOException $e) {
            // Column already exists
        }

        // Safe migration: add group_id to watchlist
        try {
            $db->exec("ALTER TABLE watchlist ADD COLUMN group_id INTEGER DEFAULT NULL");
        } catch (PDOException $e) {
            // Column already exists
        }
    }
}
