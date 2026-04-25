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

    // Ensure row 1 exists
    $db->exec("INSERT OR IGNORE INTO worker_status (id) VALUES (1)");

    $fields = [];
    $params = [];
    foreach (['last_run','tlds_processed','domains_processed','matches_found','is_running','version','current_tld','total_tlds','current_action'] as $col) {
        if (array_key_exists($col, $input)) {
            $fields[] = "$col = ?";
            if (in_array($col, ['tlds_processed','domains_processed','matches_found','is_running','total_tlds'], true)) {
                $params[] = (int)$input[$col];
            } else {
                $params[] = $input[$col];
            }
        }
    }
    // Always update last_heartbeat in UTC for consistency
    $fields[] = "last_heartbeat = ?";
    $params[] = gmdate('c');
    $params[] = 1; // WHERE id = 1

    $sql = "UPDATE worker_status SET " . implode(', ', $fields) . " WHERE id = ?";
    $db->prepare($sql)->execute($params);
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
