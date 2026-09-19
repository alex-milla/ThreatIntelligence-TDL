<?php
/**
 * Per-ccTLD sync reports from the OpenINTEL importer.
 *
 * Creates missing ccTLD rows (source = 'openintel', inactive by default) and
 * updates their status/last_sync. last_ok_sync is advanced only on a real
 * successful run, so the "old validated domain" filter keeps working.
 */
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

$allowedStatus = ['baselined', 'updated', 'unchanged', 'failed', 'no_data', 'pending'];
$okStatuses = ['baselined', 'updated', 'unchanged'];
$now = gmdate('c');
$updated = 0;

$insert = $db->prepare("INSERT OR IGNORE INTO tlds (name, source, is_active) VALUES (?, 'openintel', 0)");
$stmt = $db->prepare(
    "UPDATE tlds SET last_sync = ?, "
    . "last_ok_sync = COALESCE(?, last_ok_sync), "
    . "status = ?, records_total = ?, records_new = ?, last_error = ? "
    . "WHERE name = ? AND source = 'openintel'"
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
        $isOk = in_array($status, $okStatuses, true);

        $insert->execute([$tld]);
        $stmt->execute([
            $now,
            $isOk ? $now : null,
            $status,
            (int)($entry['records_total'] ?? 0),
            (int)($entry['records_new'] ?? 0),
            $error,
            $tld,
        ]);
        $updated += $stmt->rowCount();
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to store ccTLD sync report'], 500);
}

jsonResponse(['success' => true, 'updated' => $updated]);
