<?php
/**
 * Return the cached AlienVault OTX reputation for a domain (if any).
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
    "SELECT domain, verdict, pulse_count, references_count, whitelisted, adversary, malware_families, tags, last_analysis_date, checked_at "
    . "FROM domain_otx WHERE domain = ? LIMIT 1"
);
$stmt->execute([$domain]);
$row = $stmt->fetch();

if (!$row) {
    echo json_encode(['success' => true, 'otx' => null]);
    exit;
}

echo json_encode([
    'success' => true,
    'otx' => [
        'domain' => $row['domain'],
        'verdict' => $row['verdict'],
        'pulse_count' => (int)$row['pulse_count'],
        'references_count' => (int)$row['references_count'],
        'whitelisted' => (int)$row['whitelisted'],
        'adversary' => $row['adversary'],
        'malware_families' => $row['malware_families'],
        'tags' => $row['tags'],
        'last_analysis_date' => $row['last_analysis_date'],
        'checked_at' => $row['checked_at'],
    ],
]);
