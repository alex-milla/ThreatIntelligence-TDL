<?php
require __DIR__ . '/../../includes/db.php';
require __DIR__ . '/../../includes/auth.php';

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? $_GET['api_key'] ?? '';
if (!$apiKey) {
    jsonResponse(['success' => false, 'error' => 'Missing API key'], 401);
}

$db = Database::get();
$user = verifyApiKey($db, $apiKey);
if (!$user || empty($user['is_admin'])) {
    jsonResponse(['success' => false, 'error' => 'Invalid API key'], 401);
}

$input = json_decode(file_get_contents('php://input'), true) ?: [];

// Optional: store heartbeat info in a table or just acknowledge
jsonResponse([
    'success' => true,
    'message' => 'Heartbeat received',
    'server_time' => date('c'),
]);
