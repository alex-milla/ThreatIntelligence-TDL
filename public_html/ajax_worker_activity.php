<?php
/**
 * Lightweight activity probe used by the UI to auto-refresh when the worker,
 * a recheck or a queued command finishes. Available to any logged-in user.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');

if (empty($_SESSION['user_id'])) {
    http_response_code(401);
    echo json_encode(['success' => false, 'error' => 'Unauthorized']);
    exit;
}

$db = Database::get();
echo json_encode(array_merge(['success' => true], getWorkerActivity($db)));
