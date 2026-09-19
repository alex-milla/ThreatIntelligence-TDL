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
    $tlds = $input['tlds'] ?? [];

    $db->beginTransaction();
    $stmt = $db->prepare("INSERT OR IGNORE INTO tlds (name) VALUES (?)");
    foreach ($tlds as $tld) {
        $stmt->execute([$tld]);
    }
    $db->commit();
    jsonResponse(['success' => true, 'imported' => count($tlds)]);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $onlyActive = isset($_GET['active']) && $_GET['active'] == '1';
    if ($onlyActive) {
        $stmt = $db->query("SELECT name FROM tlds WHERE is_active = 1 ORDER BY name");
    } else {
        $stmt = $db->query("SELECT id, name, is_active, last_sync, status FROM tlds ORDER BY name");
    }
    jsonResponse(['success' => true, 'tlds' => $stmt->fetchAll()]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
