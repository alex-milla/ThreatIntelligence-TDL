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

$db->prepare("INSERT OR REPLACE INTO keywords (id, user_id, keyword, is_active, match_count) VALUES (1, 1, 'acme', 1, 1)")->execute();

$db->prepare(
    "INSERT OR REPLACE INTO matches
        (id, keyword_id, domain, tld, discovered_at, first_seen, is_historical, source)
     VALUES (1, 1, 'acme-phishing.test', 'test', datetime('now'), datetime('now'), 0, 'czds')"
)->execute();

$db->prepare("INSERT OR REPLACE INTO notifications (id, user_id, match_id, is_read, kind) VALUES (1, 1, 1, 0, 'match')")->execute();

echo "Seeded E2E database at {$docroot}/data/app.db\n";
