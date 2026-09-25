<?php
/**
 * Queue a Cloudflare Radar (URL Scanner + DNS locations) check on the worker.
 *
 * Scans are asynchronous, sequential and rate limited (Free plan: 1 per 10 s),
 * so the batch is small (CFSCAN_BATCH_MAX) and domains already cached are
 * skipped unless force=1.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
requireAuth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

validateCsrf();

define('CFSCAN_BATCH_MAX', 20);

$input = json_decode(file_get_contents('php://input'), true) ?: [];
$domains = $input['domains'] ?? null;
if (!$domains && !empty($input['domain'])) {
    $domains = [$input['domain']];
}
if (!is_array($domains)) {
    echo json_encode(['success' => false, 'error' => 'No domains provided']);
    exit;
}
$force = !empty($input['force']);

$clean = [];
foreach (array_slice($domains, 0, 200) as $d) {
    $d = strtolower(trim((string)$d));
    if ($d === '' || strlen($d) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $d)) {
        continue;
    }
    $clean[$d] = true;
}
$clean = array_keys($clean);
if (empty($clean)) {
    echo json_encode(['success' => false, 'error' => 'No valid domains']);
    exit;
}

$db = Database::get();

// Excluded domains are never looked up (mirrors the report filter).
$exclStmt = $db->prepare("SELECT domain FROM domain_tags WHERE tag = 'excluded' AND domain IN ("
    . implode(',', array_fill(0, count($clean), '?')) . ")");
$exclStmt->execute($clean);
$excluded = array_flip(array_map('strtolower', $exclStmt->fetchAll(PDO::FETCH_COLUMN)));
if ($excluded) {
    $clean = array_values(array_filter($clean, fn($d) => !isset($excluded[$d])));
    if (empty($clean)) {
        echo json_encode(['success' => true, 'queued' => 0, 'message' => 'Excluded domains are skipped.']);
        exit;
    }
}

// Domains already queued in a pending/running cf_scan_lookup command.
$pendingCommandId = null;
$pendingDomains = [];
foreach ($db->query("SELECT id, payload FROM commands WHERE command = 'cf_scan_lookup' AND status IN ('pending','running') ORDER BY id ASC")->fetchAll() as $c) {
    $payload = json_decode($c['payload'] ?? '{}', true) ?: [];
    foreach (($payload['domains'] ?? []) as $pd) {
        $pendingDomains[strtolower((string)$pd)] = true;
    }
    if ($pendingCommandId === null) {
        $pendingCommandId = (int)$c['id'];
    }
}

// Skip domains already cached unless a refresh was requested.
$cached = [];
if (!$force) {
    $placeholders = implode(',', array_fill(0, count($clean), '?'));
    $stmt = $db->prepare("SELECT domain FROM domain_cfscan WHERE domain IN ($placeholders)");
    $stmt->execute($clean);
    foreach ($stmt->fetchAll() as $r) {
        $cached[strtolower($r['domain'])] = true;
    }
}

$toFetch = [];
foreach ($clean as $d) {
    if (isset($pendingDomains[$d])) {
        continue;
    }
    if (!$force && isset($cached[$d])) {
        continue;
    }
    $toFetch[] = $d;
    if (count($toFetch) >= CFSCAN_BATCH_MAX) {
        break;
    }
}

if (empty($toFetch)) {
    echo json_encode([
        'success' => true,
        'command_id' => $pendingCommandId,
        'queued' => 0,
        'message' => $pendingCommandId
            ? 'Already queued; waiting for the worker.'
            : 'All requested domains are already cached (use "force" to refresh).',
    ]);
    exit;
}

$db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)")
   ->execute(['cf_scan_lookup', json_encode(['domains' => $toFetch])]);
$commandId = (int)$db->lastInsertId();

echo json_encode([
    'success' => true,
    'command_id' => $commandId,
    'queued' => count($toFetch),
    'message' => 'Queued for the worker.',
]);
