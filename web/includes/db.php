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
            max_keywords INTEGER DEFAULT 10,
            email_notifications INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )");
        
        $db->exec("CREATE TABLE IF NOT EXISTS tlds (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            is_active INTEGER DEFAULT 1,
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
    }
}
