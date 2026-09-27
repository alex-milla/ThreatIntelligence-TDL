<?php
/**
 * Seed a throwaway E2E database. Usage: php seed.php <docroot>
 *
 * Creates one admin, closes registration and inserts a keyword + match +
 * notification so the UI has something to render. Idempotent.
 */
declare(strict_types=1);

$docroot = $argv[1] ?? '';
if ($docroot === '' || !is_file($docroot . '/includes/db.php')) {
    fwrite(STDERR, "usage: php seed.php <docroot>\n");
    exit(1);
}

require_once $docroot . '/includes/db.php';

$db = Database::get();

$username = 'e2e_admin';
$email    = 'e2e@example.test';
$password = 'e2e_password_123';
$hash     = password_hash($password, PASSWORD_DEFAULT);

$db->prepare(
    "INSERT OR REPLACE INTO users
        (id, username, email, password_hash, api_key, is_active, is_admin, email_notifications, max_keywords)
     VALUES (1, ?, ?, ?, ?, 1, 1, 0, 0)"
)->execute([$username, $email, $hash, 'e2e_api_key']);

$db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('registration_open', '0')")->execute();
$db->prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('new_domain_days', '1')")->execute();

$db->prepare("INSERT OR REPLACE INTO keywords (id, user_id, keyword, is_active, match_count) VALUES (1, 1, 'acme', 1, 2)")->execute();
$db->prepare("INSERT OR REPLACE INTO keywords (id, user_id, keyword, is_active, match_count, tracking_enabled) VALUES (2, 1, 'beta', 1, 0, 1)")->execute();
$db->prepare("INSERT OR REPLACE INTO keywords (id, user_id, keyword, is_active, match_count, tracking_enabled) VALUES (3, 1, 'gamma', 1, 5, 0)")->execute();

$db->prepare(
    "INSERT OR REPLACE INTO matches
        (id, keyword_id, domain, tld, discovered_at, first_seen, is_historical, source)
     VALUES (1, 1, 'acme-phishing.test', 'test', datetime('now'), datetime('now'), 0, 'czds')"
)->execute();

$db->prepare(
    "INSERT OR REPLACE INTO matches
        (id, keyword_id, domain, tld, discovered_at, first_seen, is_historical, source)
     VALUES (2, 1, 'acme-login.test', 'test', datetime('now'), datetime('now'), 0, 'czds')"
)->execute();

$db->prepare("INSERT OR REPLACE INTO notifications (id, user_id, match_id, is_read, kind) VALUES (1, 1, 1, 0, 'match')")->execute();
$db->prepare("INSERT OR REPLACE INTO notifications (id, user_id, match_id, is_read, kind) VALUES (2, 1, 2, 0, 'match')")->execute();

// Worker status with storage metrics, so the admin Storage tab has data.
$db->exec(
    "INSERT OR REPLACE INTO worker_status
        (id, is_running, version, last_heartbeat, storage_updated_at,
         disk_total_bytes, disk_free_bytes, db_size_bytes, zones_size_bytes)
     VALUES (1, 0, 'e2e', datetime('now'), datetime('now'),
             100000000000, 40000000000, 524288000, 1073741824)"
);

echo "Seeded E2E database at {$docroot}/data/app.db\n";
