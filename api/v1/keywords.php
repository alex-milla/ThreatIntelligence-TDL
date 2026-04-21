<?php
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
if (!$apiKey) {
    jsonResponse(['success' => false, 'error' => 'Missing API key'], 401);
}

$db = Database::get();
$user = verifyApiKey($db, $apiKey);
if (!$user) {
    jsonResponse(['success' => false, 'error' => 'Invalid API key'], 401);
}

// Only admin users can use the worker API
if (empty($user['is_admin'])) {
    jsonResponse(['success' => false, 'error' => 'Forbidden'], 403);
}

$stmt = $db->query("SELECT id, user_id, keyword FROM keywords WHERE is_active = 1");
$keywords = $stmt->fetchAll();

jsonResponse(['success' => true, 'keywords' => $keywords]);
