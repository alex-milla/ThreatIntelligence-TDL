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

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $domain = trim($_GET['domain'] ?? '');
    if ($domain) {
        $stmt = $db->prepare("SELECT domain, tag, note, created_at FROM domain_tags WHERE domain = ? LIMIT 1");
        $stmt->execute([$domain]);
        $tag = $stmt->fetch();
        jsonResponse(['success' => true, 'tag' => $tag ?: null]);
    }
    // Batch lookup
    $domains = $_GET['domains'] ?? [];
    if (is_string($domains)) {
        $domains = explode(',', $domains);
    }
    $domains = array_filter(array_map('trim', $domains));
    if (empty($domains)) {
        jsonResponse(['success' => false, 'error' => 'No domains provided'], 400);
    }
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $stmt = $db->prepare("SELECT domain, tag, note, created_at FROM domain_tags WHERE domain IN ($placeholders)");
    $stmt->execute($domains);
    jsonResponse(['success' => true, 'tags' => $stmt->fetchAll()]);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $domain = strtolower(trim($input['domain'] ?? ''));
    $tag = $input['tag'] ?? '';
    $note = trim($input['note'] ?? '');

    if (!$domain || !in_array($tag, ['good', 'bad'], true)) {
        jsonResponse(['success' => false, 'error' => 'Invalid domain or tag'], 400);
    }

    $stmt = $db->prepare("INSERT OR REPLACE INTO domain_tags (domain, tag, note, created_by) VALUES (?, ?, ?, ?)");
    $stmt->execute([$domain, $tag, $note, $user['id']]);
    jsonResponse(['success' => true]);
}

if ($_SERVER['REQUEST_METHOD'] === 'DELETE') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $domain = strtolower(trim($input['domain'] ?? ''));
    if (!$domain) {
        jsonResponse(['success' => false, 'error' => 'Invalid domain'], 400);
    }
    $db->prepare("DELETE FROM domain_tags WHERE domain = ?")->execute([$domain]);
    jsonResponse(['success' => true]);
}

jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
