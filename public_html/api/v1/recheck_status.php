<?php
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
if (!$apiKey) {
    jsonResponse(['success' => false, 'error' => 'Missing API key'], 401);
}

$db = Database::get();
if (checkApiRateLimit($db, getClientIp(), $apiKey, basename(__FILE__))) {
    jsonResponse(['success' => false, 'error' => 'Rate limit exceeded. Try again later.'], 429);
}
$user = verifyApiKey($db, $apiKey);
if (!$user || empty($user['is_admin'])) {
    jsonResponse(['success' => false, 'error' => 'Invalid API key'], 401);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];

    $stmt = $db->prepare("INSERT OR REPLACE INTO recheck_status 
        (id, is_running, total_domains, checked_domains, matches_found, started_at, completed_at) 
        VALUES (1, ?, ?, ?, ?, ?, ?)");
    $stmt->execute([
        (int)($input['is_running'] ?? 0),
        (int)($input['total_domains'] ?? 0),
        (int)($input['checked_domains'] ?? 0),
        (int)($input['matches_found'] ?? 0),
        $input['started_at'] ?? null,
        $input['completed_at'] ?? null,
    ]);
    jsonResponse(['success' => true]);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $stmt = $db->query("SELECT * FROM recheck_status WHERE id = 1");
    $status = $stmt->fetch();
    if (!$status) {
        jsonResponse(['success' => true, 'status' => null]);
    }
    jsonResponse(['success' => true, 'status' => $status]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
