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

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
}

$input = json_decode(file_get_contents('php://input'), true) ?: [];
$entries = $input['entries'] ?? [];
if (!is_array($entries)) {
    jsonResponse(['success' => false, 'error' => 'Invalid entries payload'], 400);
}

$allowedStatus = [
    'downloaded', 'not_modified', 'skipped_today', 'failed', 'pending',
    'incomplete', 'skipped_large', 'no_space', 'retrying', 'parse_error',
];
$now = gmdate('c');
$updated = 0;

$stmt = $db->prepare(
    "UPDATE tlds SET last_sync = ?, status = ?, records_total = ?, records_new = ?, "
    . "zone_size = ?, zone_file_mtime = ?, last_error = ?, retry_attempts = ?, next_retry = ? WHERE name = ?"
);

$db->beginTransaction();
try {
    foreach (array_slice($entries, 0, 5000) as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $tld = strtolower(trim((string)($entry['tld'] ?? '')));
        if ($tld === '') {
            continue;
        }
        $status = (string)($entry['status'] ?? '');
        if (!in_array($status, $allowedStatus, true)) {
            $status = 'pending';
        }
        $error = isset($entry['error']) && $entry['error'] !== '' ? substr((string)$entry['error'], 0, 500) : null;

        $nextRetry = isset($entry['next_retry']) && $entry['next_retry'] !== '' ? (string)$entry['next_retry'] : null;

        $stmt->execute([
            $now,
            $status,
            (int)($entry['records_total'] ?? 0),
            (int)($entry['records_new'] ?? 0),
            (int)($entry['zone_size'] ?? 0),
            $entry['zone_file_mtime'] ?? null,
            $error,
            (int)($entry['attempts'] ?? 0),
            $nextRetry,
            $tld,
        ]);
        $updated += $stmt->rowCount();
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to store TLD sync report'], 500);
}

jsonResponse(['success' => true, 'updated' => $updated]);
