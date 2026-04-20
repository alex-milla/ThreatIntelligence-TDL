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

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Return pending commands
    $stmt = $db->prepare("SELECT id, command, payload FROM commands WHERE status = 'pending' ORDER BY created_at ASC");
    $stmt->execute();
    $commands = $stmt->fetchAll();
    jsonResponse(['success' => true, 'commands' => $commands]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $commandId = (int)($input['command_id'] ?? 0);
    $status = $input['status'] ?? 'completed';
    $result = $input['result'] ?? '';

    if (!$commandId) {
        jsonResponse(['success' => false, 'error' => 'Missing command_id'], 400);
    }

    $stmt = $db->prepare("UPDATE commands SET status = ?, result = ?, executed_at = datetime('now') WHERE id = ?");
    $stmt->execute([$status, $result, $commandId]);
    jsonResponse(['success' => true]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
