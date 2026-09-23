<?php
/**
 * Report queue endpoint.
 *
 * GET  ?domain=<d>                      -> { success, queued: bool, added_at }
 * POST { domains: [...], queued: bool }  -> { success, queued, count, status: {domain: bool} }
 * POST { domain: "<d>",  queued: bool }  -> same, for a single domain
 *
 * Domains are validated against the user's own keyword matches before queueing.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/report_queue.php';

header('Content-Type: application/json');
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $domain = reportQueueNormalizeDomain((string)($_GET['domain'] ?? ''));
    if ($domain === '') {
        echo json_encode(['success' => false, 'error' => 'Invalid domain']);
        exit;
    }
    $status = reportQueueStatus($db, $userId, [$domain]);
    $row = $status[$domain] ?? null;
    echo json_encode([
        'success'  => true,
        'queued'   => $row !== null && $row['reported_at'] === null,
        'reported' => $row !== null && $row['reported_at'] !== null,
        'added_at' => $row['added_at'] ?? null,
    ]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
    $input = json_decode(file_get_contents('php://input'), true) ?: [];

    $domains = [];
    if (isset($input['domains']) && is_array($input['domains'])) {
        $domains = $input['domains'];
    } elseif (!empty($input['domain'])) {
        $domains = [$input['domain']];
    }
    $queued = !(isset($input['queued']) && ($input['queued'] === false || $input['queued'] === 0 || $input['queued'] === '0'));

    if (empty($domains)) {
        echo json_encode(['success' => false, 'error' => 'No domains provided']);
        exit;
    }

    // Optional explicit group (from the "send to report" selector). When absent,
    // the queue assigns each domain to every group of its matched keywords.
    $groupKey = array_key_exists('group_key', $input) ? (string)$input['group_key'] : null;

    $count = $queued
        ? reportQueueAdd($db, $userId, $domains, $groupKey)
        : reportQueueRemove($db, $userId, $domains, $groupKey);

    // Return the resulting status for every requested domain.
    $status = reportQueueStatus($db, $userId, $domains);
    $result = [];
    foreach ($domains as $d) {
        $d = reportQueueNormalizeDomain((string)$d);
        if ($d === '') {
            continue;
        }
        $row = $status[$d] ?? null;
        $result[$d] = ($row !== null && $row['reported_at'] === null);
    }

    echo json_encode(['success' => true, 'queued' => $queued, 'count' => $count, 'status' => $result]);
    exit;
}

echo json_encode(['success' => false, 'error' => 'Method not allowed']);
