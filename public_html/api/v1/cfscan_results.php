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

// Detect a stringified dict / bare "data" left by a bad parse, so new reports
// never overwrite good data with garbage.
$malformed = function ($value): bool {
    $v = trim((string)$value);
    if ($v === '') {
        return false;
    }
    if (strcasecmp($v, 'data') === 0) {
        return true;
    }
    return strpos($v, "{'") !== false || strpos($v, "[{'") !== false
        || strpos($v, '"data"') !== false || strpos($v, "'data'") !== false;
};

// Preserve previously stored fields the new report does not carry or that look
// malformed (the DNS call is optional / may fail independently).
$existingStmt = $db->prepare(
    "SELECT verdict, status, error, categories, phishing, radar_rank, technologies, asn, country, "
    . "cert_issuer, dom_struct_hash, favicon_hash, report_url, dns_countries, last_analysis_date "
    . "FROM domain_cfscan WHERE domain = ? LIMIT 1"
);

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
        $existingStmt->execute([$domain]);
        $prevRow = $existingStmt->fetch() ?: [];

        // A successful scan trusts its own fields (empty included); a malformed
        // value or a failed scan keeps the previously stored value instead of
        // wiping it with garbage.
        $isError = ($status === 'error');
        $pick = function (string $key, $incoming) use ($prevRow, $malformed, $isError): string {
            $incoming = (string)$incoming;
            if ($malformed($incoming) || $isError) {
                return (string)($prevRow[$key] ?? '');
            }
            return $incoming;
        };

        $dnsCountries = null;
        if (isset($entry['dns_countries']) && is_array($entry['dns_countries'])) {
            $dnsCountries = json_encode(array_slice($entry['dns_countries'], 0, 50), JSON_UNESCAPED_UNICODE);
        } else {
            $dnsCountries = $prevRow['dns_countries'] ?? null;
        }

        // Keep the scanner report link even when the scan failed: it is the
        // scan's own URL (not a data field), so the UI can open it to see why.
        $reportUrl = trim((string)($entry['report_url'] ?? ''));
        if ($reportUrl === '' || $malformed($reportUrl)) {
            $reportUrl = (string)($prevRow['report_url'] ?? '');
        }

        $stmt->execute([
            $domain,
            $verdict,
            $status,
            substr((string)($entry['error'] ?? ''), 0, 255),
            substr($pick('categories', $entry['categories'] ?? ''), 0, 500),
            substr($pick('phishing', $entry['phishing'] ?? ''), 0, 500),
            substr($pick('radar_rank', $entry['radar_rank'] ?? ''), 0, 40),
            substr($pick('technologies', $entry['technologies'] ?? ''), 0, 1000),
            substr($pick('asn', $entry['asn'] ?? ''), 0, 40),
            substr($pick('country', $entry['country'] ?? ''), 0, 80),
            substr($pick('cert_issuer', $entry['cert_issuer'] ?? ''), 0, 255),
            substr($pick('dom_struct_hash', $entry['dom_struct_hash'] ?? ''), 0, 80),
            substr($pick('favicon_hash', $entry['favicon_hash'] ?? ''), 0, 80),
            substr($reportUrl, 0, 500),
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
