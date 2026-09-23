<?php
/**
 * Returns the rendered rich domain detail block for one domain (used by the
 * Dashboard lookup, which is dynamic). Watchlist and Notifications render the
 * same block server-side.
 *
 * GET ?domain=<domain> -> { success: true, html: "<div class=...>" }
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/domain_detail.php';

header('Content-Type: application/json');
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$domain = strtolower(trim((string)($_GET['domain'] ?? '')));

if ($domain === '') {
    echo json_encode(['success' => false, 'error' => 'Invalid domain']);
    exit;
}

$data = domainDetailPresent($db, $userId, $domain);
if (!$data) {
    echo json_encode(['success' => false, 'error' => 'Invalid domain']);
    exit;
}

$rules = reportReviewRules($db);
$html = renderDomainDetail($data['present'], $data['keywords'], $rules);

echo json_encode(['success' => true, 'html' => $html]);
