<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');

session_start();
if (empty($_SESSION['user_id']) || empty($_SESSION['is_admin'])) {
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

$db = Database::get();
$stmt = $db->query("SELECT * FROM recheck_status WHERE id = 1");
$status = $stmt->fetch();

if (!$status) {
    echo json_encode(['success' => true, 'status' => null]);
    exit;
}

// Calculate percentage
$total = (int)($status['total_domains'] ?? 0);
$checked = (int)($status['checked_domains'] ?? 0);
$pct = $total > 0 ? round($checked / $total * 100, 1) : 0;

$status['progress_pct'] = $pct;

echo json_encode(['success' => true, 'status' => $status]);
