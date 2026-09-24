<?php
/**
 * Due dormant-domain tracking entries for the worker.
 *
 * Returns the tracking rows whose next_check_at elapsed and whose window is
 * still open (optionally limited to an explicit `domains` list for "Check now").
 */
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/tracking.php';

$apiKey = $_SERVER['HTTP_X_API_KEY'] ?? '';
if (!$apiKey) {
    jsonResponse(['success' => false, 'error' => 'Missing API key'], 401);
}

$db = Database::get();
if (checkApiRateLimit($db, getClientIp(), $apiKey, basename(__FILE__))) {
    jsonResponse(['success' => false, 'error' => 'Rate limit exceeded. Try again later.'], 429);
}
$user = verifyApiKey($db, $apiKey);
if (!$user || empty($user['is_admin'])) {
    jsonResponse(['success' => false, 'error' => 'Invalid API key'], 401);
}

// Expire stale windows before computing the due set.
trackingExpireDue($db);

$limit = (int)($_GET['limit'] ?? 200);
$limit = max(1, min(500, $limit));

$domainsParam = trim((string)($_GET['domains'] ?? ''));
$domains = [];
if ($domainsParam !== '') {
    foreach (explode(',', $domainsParam) as $d) {
        $d = strtolower(trim($d));
        if ($d !== '' && strlen($d) <= 253 && preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $d)) {
            $domains[$d] = true;
        }
    }
    $domains = array_keys($domains);
}

$baseSelect = "SELECT dt.domain, dt.keyword_id, dt.user_id, dt.first_seen, dt.enrolled_at, dt.expires_at,
        dt.baseline, dt.check_count, k.keyword, k.tracking_interval_hours, k.tracking_days
    FROM domain_tracking dt
    JOIN keywords k ON k.id = dt.keyword_id
    WHERE dt.status = 'tracking'";

if ($domains) {
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $stmt = $db->prepare($baseSelect . " AND dt.domain IN ($placeholders) ORDER BY dt.domain ASC");
    $stmt->execute($domains);
} else {
    $stmt = $db->prepare($baseSelect
        . " AND (dt.next_check_at IS NULL OR dt.next_check_at <= datetime('now'))"
        . " AND (dt.expires_at IS NULL OR dt.expires_at > datetime('now'))"
        . " ORDER BY dt.next_check_at ASC LIMIT ?");
    $stmt->bindValue(1, $limit, PDO::PARAM_INT);
    $stmt->execute();
}

$entries = [];
foreach ($stmt->fetchAll() as $r) {
    $entries[] = [
        'domain'         => $r['domain'],
        'keyword_id'     => (int)$r['keyword_id'],
        'keyword'        => $r['keyword'],
        'user_id'        => (int)$r['user_id'],
        'first_seen'     => $r['first_seen'],
        'enrolled_at'    => $r['enrolled_at'],
        'expires_at'     => $r['expires_at'],
        'baseline'       => json_decode((string)$r['baseline'], true) ?: [],
        'check_count'    => (int)$r['check_count'],
        'interval_hours' => (int)$r['tracking_interval_hours'],
    ];
}

jsonResponse(['success' => true, 'entries' => $entries]);
