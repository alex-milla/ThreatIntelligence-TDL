<?php
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
    "SELECT domain, creation_date, expiration_date, registrar, name_servers, source, status, updated_at, cached_at "
    . "FROM domain_whois WHERE domain = ? LIMIT 1"
);
$stmt->execute([$domain]);
$row = $stmt->fetch();

if (!$row) {
    echo json_encode(['success' => true, 'whois' => null]);
    exit;
}

echo json_encode([
    'success' => true,
    'whois' => [
        'domain' => $row['domain'],
        'creation_date' => $row['creation_date'],
        'expiration_date' => $row['expiration_date'],
        'registrar' => $row['registrar'],
        'name_servers' => json_decode($row['name_servers'] ?? '[]', true) ?: [],
        'source' => $row['source'],
        'status' => $row['status'],
        'updated_at' => $row['updated_at'],
        'cached_at' => $row['cached_at'],
    ],
]);
