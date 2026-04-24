<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/whois.php';

header('Content-Type: application/json');

requireAuth();

$domain = trim($_GET['domain'] ?? '');
if (!$domain || strlen($domain) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $domain)) {
    echo json_encode(['success' => false, 'error' => 'Invalid domain']);
    exit;
}

$whois = getDomainWhois($domain, 20);

if ($whois === null) {
    echo json_encode([
        'success' => false,
        'error' => 'RDAP query failed',
        'fallback_url' => 'https://who.is/whois/' . urlencode($domain),
    ]);
    exit;
}

echo json_encode([
    'success' => true,
    'domain' => strtolower($domain),
    'creationDate' => $whois['creation_date'],
    'expirationDate' => $whois['expiration_date'],
    'registrar' => $whois['registrar'],
]);
