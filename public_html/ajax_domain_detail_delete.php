<?php
/**
 * Delete the cached "ficha" (enrichment) of one or more domains.
 *
 * Admin only. Removes only the cached WHOIS / VirusTotal / abuse.ch / Cloudflare
 * rows so the checks can be run again. It never touches analyst data (tags),
 * the watchlist, the report queue, matches/notifications, saved reports,
 * Intelligence tracking, nor the worker's domain cache.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
requireAuth();

if (empty($_SESSION['is_admin'])) {
    echo json_encode(['success' => false, 'error' => 'Admin only']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

validateCsrf();

$input = json_decode(file_get_contents('php://input'), true) ?: [];
$domains = $input['domains'] ?? null;
if (!$domains && !empty($input['domain'])) {
    $domains = [$input['domain']];
}
if (!is_array($domains)) {
    echo json_encode(['success' => false, 'error' => 'No domains provided']);
    exit;
}

$clean = [];
foreach (array_slice($domains, 0, 500) as $d) {
    $d = strtolower(trim((string)$d));
    if ($d !== '' && strlen($d) <= 253 && preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $d)) {
        $clean[$d] = true;
    }
}
$clean = array_keys($clean);
if (empty($clean)) {
    echo json_encode(['success' => false, 'error' => 'No valid domains']);
    exit;
}

// Only the cached enrichment tables that make up the detail panel.
$tables = [
    'whois'   => 'domain_whois',
    'vt'      => 'domain_vt',
    'abusech' => 'domain_abusech',
    'cfscan'  => 'domain_cfscan',
];

$db = Database::get();
$placeholders = implode(',', array_fill(0, count($clean), '?'));
$deleted = [];
$db->beginTransaction();
try {
    foreach ($tables as $key => $table) {
        $stmt = $db->prepare("DELETE FROM $table WHERE domain IN ($placeholders)");
        $stmt->execute($clean);
        $deleted[$key] = $stmt->rowCount();
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    echo json_encode(['success' => false, 'error' => 'Delete failed']);
    exit;
}

echo json_encode(['success' => true, 'domains' => count($clean), 'deleted' => $deleted]);
