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

$db->prepare("INSERT OR REPLACE INTO domain_tracking (id, domain, keyword_id, user_id, first_seen, enrolled_at, expires_at, status, check_count) VALUES (1, 'track-demo.test', 1, 1, datetime('now'), datetime('now'), datetime('now','+30 days'), 'tracking', 2)")->execute();

// Twelve dummy backups so the Backups page's 10-item retention can be asserted.
$backupBase = $docroot . '/data/backups';
@mkdir($backupBase, 0777, true);
for ($i = 1; $i <= 12; $i++) {
    $d = $backupBase . '/backup_202601' . str_pad((string)$i, 2, '0', STR_PAD_LEFT) . '_000000';
    @mkdir($d . '/public_html', 0777, true);
    @file_put_contents($d . '/public_html/marker.txt', 'seed ' . $i);
}

$db->prepare("INSERT OR REPLACE INTO watchlist_groups (id, user_id, name) VALUES (1, 1, 'Clients')")->execute();
$db->prepare("INSERT OR REPLACE INTO watchlist (id, user_id, domain, note, group_id) VALUES (1, 1, 'watch-demo.test', 'Seeded watch', NULL)")->execute();
$db->prepare("INSERT OR REPLACE INTO watchlist (id, user_id, domain, note, group_id) VALUES (2, 1, 'watch-clients.test', NULL, 1)")->execute();

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

// One saved report snapshot so report_view.php has something to render.
$now = gmdate('Y-m-d H:i:s');
$snapshot = [
    'generated_at' => $now,
    'group_name' => '',
    'filter_summary' => 'Manual report queue',
    'keywords' => ['acme'],
    'truncated' => false,
    'report' => [[
        'keyword' => 'acme',
        'counts' => ['domains' => 1, 'new' => 0, 'malicious' => 1, 'suspicious' => 0,
                     'good' => 0, 'bad' => 0, 'observing' => 0, 'untagged' => 1],
        'rows' => [[
            'domain' => 'acme-phishing.test',
            'tld' => 'test',
            'source' => 'czds',
            'tag' => '',
            'discovered_at' => $now,
            'first_seen' => $now,
            'is_historical' => 0,
            'verdict' => 'malicious',
            'malicious' => 1,
            'suspicious' => 0,
            'harmless' => 0,
            'undetected' => 0,
            'creation_date' => null,
        ]],
    ]],
];
$db->prepare("INSERT OR REPLACE INTO report_history
        (id, user_id, title, group_id, group_name, filters, keywords, data, domains, created_at)
     VALUES (1, 1, 'E2E Report', NULL, '', ?, ?, ?, 1, datetime('now'))")
   ->execute([json_encode(['note' => 'e2e']), json_encode(['acme']), gzcompress(json_encode($snapshot, JSON_UNESCAPED_UNICODE))]);

// One pending queue entry so the Reports builder shows the "Generate report" button.
$db->prepare("INSERT OR REPLACE INTO report_queue (id, user_id, domain, group_key, added_at, reported_at) VALUES (1, 1, 'acme-phishing.test', '', datetime('now'), NULL)")->execute();

// Worker status with storage metrics, so the admin Storage tab has data.
$db->exec(
    "INSERT OR REPLACE INTO worker_status
        (id, is_running, version, last_heartbeat, storage_updated_at,
         disk_total_bytes, disk_free_bytes, db_size_bytes, zones_size_bytes)
     VALUES (1, 0, 'e2e', datetime('now'), datetime('now'),
             100000000000, 40000000000, 524288000, 1073741824)"
);

echo "Seeded E2E database at {$docroot}/data/app.db\n";
