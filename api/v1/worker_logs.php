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
    $logs = $input['logs'] ?? [];

    $validLevels = ['info', 'warning', 'error', 'debug'];
    $stmt = $db->prepare("INSERT INTO worker_logs (level, message) VALUES (?, ?)");
    foreach ($logs as $log) {
        $level = strtolower($log['level'] ?? 'info');
        if (!in_array($level, $validLevels, true)) {
            $level = 'info';
        }
        $stmt->execute([$level, $log['message'] ?? '']);
    }
    jsonResponse(['success' => true, 'received' => count($logs)]);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $limit = (int)($_GET['limit'] ?? 50);
    $stmt = $db->prepare("SELECT * FROM worker_logs ORDER BY created_at DESC LIMIT ?");
    $stmt->execute([$limit]);
    jsonResponse(['success' => true, 'logs' => $stmt->fetchAll()]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
