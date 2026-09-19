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

$allowedStatus = ['ok', 'error', 'unsupported'];
$now = gmdate('c');
$stored = 0;

$stmt = $db->prepare(
    "INSERT OR REPLACE INTO domain_whois "
    . "(domain, creation_date, creation_ts, expiration_date, registrar, name_servers, source, status, updated_at, cached_at) "
    . "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))"
);

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
        $status = (string)($entry['status'] ?? '');
        if (!in_array($status, $allowedStatus, true)) {
            $status = 'error';
        }
        $nameServers = $entry['name_servers'] ?? [];
        if (!is_array($nameServers)) {
            $nameServers = [];
        }
        $nameServers = array_slice(array_values(array_filter(array_map(function ($n) {
            return is_string($n) ? strtolower(rtrim(trim($n), '.')) : null;
        }, $nameServers))), 0, 20);

        // Normalize the creation date to UTC so SQLite can compare it directly
        // (raw WHOIS/registrar formats are often not ISO-8601).
        $creationDate = $entry['creation_date'] ?? null;
        $creationTs = null;
        if (is_string($creationDate) && trim($creationDate) !== '') {
            $ts = strtotime($creationDate);
            if ($ts !== false) {
                $creationTs = gmdate('Y-m-d H:i:s', $ts);
            }
        }

        $stmt->execute([
            $domain,
            $creationDate,
            $creationTs,
            $entry['expiration_date'] ?? null,
            isset($entry['registrar']) ? substr((string)$entry['registrar'], 0, 255) : null,
            json_encode($nameServers),
            isset($entry['source']) ? substr((string)$entry['source'], 0, 20) : null,
            $status,
            $now,
        ]);
        $stored++;
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to store whois results'], 500);
}

jsonResponse(['success' => true, 'stored' => $stored]);
