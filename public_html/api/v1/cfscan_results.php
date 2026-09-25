<?php
/**
 * Cloudflare Radar (URL Scanner + DNS top locations) results sent by the worker.
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

$allowedVerdicts = ['malicious', 'suspicious', 'clean', ''];

// Preserve a previously stored DNS distribution when a later scan does not
// include one (the DNS call is optional / may fail independently).
$existingDnsStmt = $db->prepare("SELECT dns_countries FROM domain_cfscan WHERE domain = ? LIMIT 1");

// DNS-only reports merge into the existing row without touching the scan verdict.
$dnsHasStmt = $db->prepare("SELECT COUNT(*) FROM domain_cfscan WHERE domain = ?");
$dnsUpdStmt = $db->prepare("UPDATE domain_cfscan SET dns_countries = ?, checked_at = datetime('now') WHERE domain = ?");
$dnsInsStmt = $db->prepare("INSERT INTO domain_cfscan (domain, dns_countries, checked_at) VALUES (?, ?, datetime('now'))");

$stmt = $db->prepare(
    "INSERT OR REPLACE INTO domain_cfscan "
    . "(domain, verdict, status, error, categories, phishing, radar_rank, technologies, asn, country, "
    . "cert_issuer, dom_struct_hash, favicon_hash, report_url, dns_countries, last_analysis_date, checked_at) "
    . "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))"
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
        if (!empty($entry['dns_only'])) {
            $loc = null;
            if (isset($entry['dns_countries']) && is_array($entry['dns_countries'])) {
                $loc = json_encode(array_slice($entry['dns_countries'], 0, 50), JSON_UNESCAPED_UNICODE);
            }
            $dnsHasStmt->execute([$domain]);
            if ((int)$dnsHasStmt->fetchColumn() > 0) {
                $dnsUpdStmt->execute([$loc, $domain]);
            } else {
                $dnsInsStmt->execute([$domain, $loc]);
            }
            $stored++;
            continue;
        }

        $status = strtolower((string)($entry['status'] ?? ''));
        if (!in_array($status, ['ok', 'error'], true)) {
            $status = '';
        }
        $verdict = strtolower((string)($entry['verdict'] ?? ''));
        if (!in_array($verdict, $allowedVerdicts, true)) {
            $verdict = '';
        }
        // A failed scan carries no verdict, so the UI shows the error instead.
        if ($status === 'error') {
            $verdict = '';
        }
        $dnsCountries = null;
        if (isset($entry['dns_countries']) && is_array($entry['dns_countries'])) {
            $dnsCountries = json_encode(array_slice($entry['dns_countries'], 0, 50), JSON_UNESCAPED_UNICODE);
        } else {
            $existingDnsStmt->execute([$domain]);
            $prev = $existingDnsStmt->fetchColumn();
            $dnsCountries = ($prev === false) ? null : $prev;
        }

        $stmt->execute([
            $domain,
            $verdict,
            $status,
            substr((string)($entry['error'] ?? ''), 0, 255),
            substr((string)($entry['categories'] ?? ''), 0, 500),
            substr((string)($entry['phishing'] ?? ''), 0, 500),
            substr((string)($entry['radar_rank'] ?? ''), 0, 40),
            substr((string)($entry['technologies'] ?? ''), 0, 1000),
            substr((string)($entry['asn'] ?? ''), 0, 40),
            substr((string)($entry['country'] ?? ''), 0, 80),
            substr((string)($entry['cert_issuer'] ?? ''), 0, 255),
            substr((string)($entry['dom_struct_hash'] ?? ''), 0, 80),
            substr((string)($entry['favicon_hash'] ?? ''), 0, 80),
            substr((string)($entry['report_url'] ?? ''), 0, 500),
            $dnsCountries,
            substr((string)($entry['last_analysis_date'] ?? ''), 0, 40),
        ]);
        $stored++;
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to store Cloudflare results'], 500);
}

jsonResponse(['success' => true, 'stored' => $stored]);
