<?php
/**
 * Return the cached abuse.ch (URLhaus + ThreatFox) validation for a domain.
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
    "SELECT domain, verdict, urlhaus_verdict, urlhaus_url_count, urlhaus_online, urlhaus_dbl, "
    . "threatfox_verdict, threatfox_matches, threat_type, malware_family, confidence, tags, "
    . "last_analysis_date, checked_at FROM domain_abusech WHERE domain = ? LIMIT 1"
);
$stmt->execute([$domain]);
$row = $stmt->fetch();

if (!$row) {
    echo json_encode(['success' => true, 'abusech' => null]);
    exit;
}

echo json_encode([
    'success' => true,
    'abusech' => [
        'domain' => $row['domain'],
        'verdict' => $row['verdict'],
        'urlhaus_verdict' => $row['urlhaus_verdict'],
        'urlhaus_url_count' => (int)$row['urlhaus_url_count'],
        'urlhaus_online' => (int)$row['urlhaus_online'],
        'urlhaus_dbl' => $row['urlhaus_dbl'],
        'threatfox_verdict' => $row['threatfox_verdict'],
        'threatfox_matches' => (int)$row['threatfox_matches'],
        'threat_type' => $row['threat_type'],
        'malware_family' => $row['malware_family'],
        'confidence' => (int)$row['confidence'],
        'tags' => $row['tags'],
        'last_analysis_date' => $row['last_analysis_date'],
        'checked_at' => $row['checked_at'],
    ],
]);
