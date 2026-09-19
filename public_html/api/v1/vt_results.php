<?php
/**
 * VirusTotal domain reputation results sent by the worker.
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

$allowedVerdicts = ['malicious', 'dga', 'suspicious', 'clean', ''];

$stmt = $db->prepare(
    "INSERT OR REPLACE INTO domain_vt "
    . "(domain, verdict, malicious, suspicious, harmless, undetected, reputation, tags, last_analysis_date, checked_at) "
    . "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))"
);

$stored = 0;
$db->beginTransaction();
try {
    foreach (array_slice($entries, 0, 1000) as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $domain = strtolower(trim((string)($entry['domain'] ?? '')));
        if ($domain === '' || strlen($domain) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $domain)) {
            continue;
        }
        $verdict = strtolower((string)($entry['verdict'] ?? ''));
        if (!in_array($verdict, $allowedVerdicts, true)) {
            $verdict = '';
        }
        $lastDate = isset($entry['last_analysis_date']) && $entry['last_analysis_date'] !== null
            ? substr((string)$entry['last_analysis_date'], 0, 40) : null;

        $stmt->execute([
            $domain,
            $verdict,
            (int)($entry['malicious'] ?? 0),
            (int)($entry['suspicious'] ?? 0),
            (int)($entry['harmless'] ?? 0),
            (int)($entry['undetected'] ?? 0),
            (int)($entry['reputation'] ?? 0),
            isset($entry['tags']) ? substr((string)$entry['tags'], 0, 255) : '',
            $lastDate,
        ]);
        $stored++;
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to store VirusTotal results'], 500);
}

jsonResponse(['success' => true, 'stored' => $stored]);
