<?php
/**
 * Return the cached VirusTotal reputation for a domain (if any).
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
    "SELECT domain, verdict, malicious, suspicious, harmless, undetected, reputation, tags, last_analysis_date, checked_at "
    . "FROM domain_vt WHERE domain = ? LIMIT 1"
);
$stmt->execute([$domain]);
$row = $stmt->fetch();

if (!$row) {
    echo json_encode(['success' => true, 'vt' => null]);
    exit;
}

echo json_encode([
    'success' => true,
    'vt' => [
        'domain' => $row['domain'],
        'verdict' => $row['verdict'],
        'malicious' => (int)$row['malicious'],
        'suspicious' => (int)$row['suspicious'],
        'harmless' => (int)$row['harmless'],
        'undetected' => (int)$row['undetected'],
        'reputation' => (int)$row['reputation'],
        'tags' => $row['tags'],
        'last_analysis_date' => $row['last_analysis_date'],
        'checked_at' => $row['checked_at'],
    ],
]);
