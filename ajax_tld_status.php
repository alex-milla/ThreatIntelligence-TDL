<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
if (empty($_SESSION['user_id']) || empty($_SESSION['is_admin'])) {
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

$db = Database::get();
$rows = $db->query(
    "SELECT name, is_active, last_sync, status, records_total, records_new, zone_size, "
    . "last_error, retry_attempts, next_retry FROM tlds ORDER BY is_active DESC, name"
)->fetchAll();

$tlds = [];
foreach ($rows as $r) {
    $tlds[] = [
        'name'           => $r['name'],
        'is_active'      => (int)$r['is_active'],
        'last_sync'      => $r['last_sync'],
        'status'         => $r['status'],
        'records_total'  => (int)$r['records_total'],
        'records_new'    => (int)$r['records_new'],
        'zone_size'      => (int)$r['zone_size'],
        'last_error'     => $r['last_error'],
        'retry_attempts' => (int)($r['retry_attempts'] ?? 0),
        'next_retry'     => $r['next_retry'],
    ];
}

$worker = $db->query("SELECT is_running FROM worker_status WHERE id = 1")->fetch();
echo json_encode([
    'success' => true,
    'is_running' => !empty($worker['is_running']),
    'tlds' => $tlds,
]);
