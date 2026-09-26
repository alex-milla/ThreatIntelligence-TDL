<?php
/**
 * Provider API consumption reported by the worker (Cloudflare URL Scanner +
 * Radar, VirusTotal and abuse.ch). Shown in the Admin "API quotas" tab.
 *
 * Payload: {"usage":[{"provider","period","count","limit_value"}],
 *           "meta":[{"provider","key","value"}]}
 * period: scans:/calls:/lookups: + day:YYYY-MM-DD or month:YYYY-MM.
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
$usage = $input['usage'] ?? [];
$meta = $input['meta'] ?? [];
if (!is_array($usage) || !is_array($meta)) {
    jsonResponse(['success' => false, 'error' => 'Invalid payload'], 400);
}

$allowedProviders = ['cloudflare', 'virustotal', 'abusech'];

$usageStmt = $db->prepare(
    "INSERT OR REPLACE INTO api_usage (provider, period, count, limit_value, updated_at) "
    . "VALUES (?, ?, ?, ?, datetime('now'))"
);
$metaStmt = $db->prepare(
    "INSERT OR REPLACE INTO api_usage_meta (provider, key, value, updated_at) "
    . "VALUES (?, ?, ?, datetime('now'))"
);

$storedUsage = 0;
$storedMeta = 0;
$db->beginTransaction();
try {
    foreach (array_slice($usage, 0, 200) as $row) {
        if (!is_array($row)) {
            continue;
        }
        $provider = strtolower(trim((string)($row['provider'] ?? '')));
        $period   = trim((string)($row['period'] ?? ''));
        if (!in_array($provider, $allowedProviders, true)) {
            continue;
        }
        if (!preg_match('/^(scans|calls|lookups):(day:\d{4}-\d{2}-\d{2}|month:\d{4}-\d{2})$/', $period)) {
            continue;
        }
        $count = max(0, (int)($row['count'] ?? 0));
        $limit = max(0, (int)($row['limit_value'] ?? 0));
        $usageStmt->execute([$provider, $period, $count, $limit]);
        $storedUsage++;
    }
    foreach (array_slice($meta, 0, 200) as $row) {
        if (!is_array($row)) {
            continue;
        }
        $provider = strtolower(trim((string)($row['provider'] ?? '')));
        $key      = strtolower(trim((string)($row['key'] ?? '')));
        if (!in_array($provider, $allowedProviders, true)) {
            continue;
        }
        if (!preg_match('/^[a-z_]{1,40}$/', $key)) {
            continue;
        }
        $metaStmt->execute([$provider, $key, substr((string)($row['value'] ?? ''), 0, 255)]);
        $storedMeta++;
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to store API usage'], 500);
}

jsonResponse(['success' => true, 'usage' => $storedUsage, 'meta' => $storedMeta]);
