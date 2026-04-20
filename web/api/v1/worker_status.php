<?php
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['api_key'] ?? '';
if (!$apiKey) {
    jsonResponse(['success' => false, 'error' => 'Missing API key'], 401);
}

$db = Database::get();
$user = verifyApiKey($db, $apiKey);
if (!$user || empty($user['is_admin'])) {
    jsonResponse(['success' => false, 'error' => 'Invalid API key'], 401);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];

    $stmt = $db->prepare("INSERT OR REPLACE INTO worker_status 
        (id, last_heartbeat, last_run, tlds_processed, domains_processed, matches_found, is_running, version) 
        VALUES (1, ?, ?, ?, ?, ?, ?, ?)");
    $stmt->execute([
        date('c'),
        $input['last_run'] ?? null,
        (int)($input['tlds_processed'] ?? 0),
        (int)($input['domains_processed'] ?? 0),
        (int)($input['matches_found'] ?? 0),
        (int)($input['is_running'] ?? 0),
        $input['version'] ?? null
    ]);
    jsonResponse(['success' => true]);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $stmt = $db->query("SELECT * FROM worker_status WHERE id = 1");
    $status = $stmt->fetch();
    if (!$status) {
        jsonResponse(['success' => true, 'status' => null]);
    }
    jsonResponse(['success' => true, 'status' => $status]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
