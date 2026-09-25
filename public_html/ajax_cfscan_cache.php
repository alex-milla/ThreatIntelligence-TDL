<?php
/**
 * Return the cached Cloudflare Radar (URL Scanner + DNS locations) data for a domain.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
requireAuth();

$domain = strtolower(trim($_GET['domain'] ?? ''));
if (!$domain || strlen($domain) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $domain)) {
    echo json_encode(['success' => false, 'error' => 'Invalid domain']);
    exit;
}

$db = Database::get();
$stmt = $db->prepare(
    "SELECT domain, verdict, status, error, categories, phishing, radar_rank, technologies, asn, country, "
    . "cert_issuer, dom_struct_hash, favicon_hash, report_url, dns_countries, last_analysis_date, checked_at "
    . "FROM domain_cfscan WHERE domain = ? LIMIT 1"
);
$stmt->execute([$domain]);
$row = $stmt->fetch();

if (!$row) {
    echo json_encode(['success' => true, 'cfscan' => null]);
    exit;
}

echo json_encode([
    'success' => true,
    'cfscan' => [
        'domain' => $row['domain'],
        'verdict' => $row['verdict'],
        'status' => $row['status'],
        'error' => $row['error'],
        'categories' => $row['categories'],
        'phishing' => $row['phishing'],
        'radar_rank' => $row['radar_rank'],
        'technologies' => $row['technologies'],
        'asn' => $row['asn'],
        'country' => $row['country'],
        'cert_issuer' => $row['cert_issuer'],
        'dom_struct_hash' => $row['dom_struct_hash'],
        'favicon_hash' => $row['favicon_hash'],
        'report_url' => $row['report_url'],
        'dns_countries' => json_decode((string)($row['dns_countries'] ?? ''), true) ?: [],
        'last_analysis_date' => $row['last_analysis_date'],
        'checked_at' => $row['checked_at'],
    ],
]);
