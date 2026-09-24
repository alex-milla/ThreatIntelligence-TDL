<?php
/**
 * Enroll keyword-matched domains into the dormant-domain tracking list.
 * Sent by the worker after a cycle; the web applies the per-keyword policy.
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
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
}

$input = json_decode(file_get_contents('php://input'), true) ?: [];
$entries = $input['entries'] ?? [];
if (!is_array($entries)) {
    jsonResponse(['success' => false, 'error' => 'Invalid entries payload'], 400);
}

$kwStmt = $db->prepare("SELECT id, user_id, tracking_days, tracking_interval_hours, tracking_enroll_max_age_days
    FROM keywords WHERE id = ? AND is_active = 1 AND tracking_enabled = 1 LIMIT 1");

$enrolled = 0;
$skipped = 0;
$swept = 0;

$db->beginTransaction();
try {
    // 1) Candidates proposed by the worker (new matches of the cycle).
    foreach (array_slice($entries, 0, 5000) as $entry) {
        if (!is_array($entry)) {
            $skipped++;
            continue;
        }
        $domain = strtolower(trim((string)($entry['domain'] ?? '')));
        $keywordId = (int)($entry['keyword_id'] ?? 0);
        if ($domain === '' || $keywordId <= 0) {
            $skipped++;
            continue;
        }
        $kwStmt->execute([$keywordId]);
        $kw = $kwStmt->fetch();
        if (!$kw) {
            $skipped++; // tracking disabled for this keyword
            continue;
        }
        if (trackingTryEnroll($db, $kw, $domain,
                (string)($entry['first_seen'] ?? ''), (string)($entry['creation_date'] ?? ''))) {
            $enrolled++;
        } else {
            $skipped++;
        }
    }

    // 2) Sweep: domains already tagged `excluded` (benign, out of reports) whose
    // keyword tracks them. This is how an excluded domain gets monitored even
    // though it is not a "new" match of the cycle.
    $sweepStmt = $db->query("SELECT DISTINCT m.domain, m.first_seen,
            k.id AS keyword_id, k.user_id, k.tracking_days, k.tracking_enroll_max_age_days
        FROM matches m
        JOIN keywords k ON k.id = m.keyword_id
        JOIN domain_tags dt ON dt.domain = m.domain AND dt.tag = 'excluded'
        JOIN domain_whois dw ON dw.domain = m.domain
        WHERE k.is_active = 1 AND k.tracking_enabled = 1
        ORDER BY m.domain
        LIMIT 500");
    foreach ($sweepStmt->fetchAll() as $row) {
        $kw = [
            'id' => (int)$row['keyword_id'],
            'user_id' => (int)$row['user_id'],
            'tracking_days' => (int)$row['tracking_days'],
            'tracking_enroll_max_age_days' => (int)$row['tracking_enroll_max_age_days'],
        ];
        if (trackingTryEnroll($db, $kw, (string)$row['domain'], (string)$row['first_seen'], null)) {
            $swept++;
        }
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to enroll tracking entries'], 500);
}

jsonResponse(['success' => true, 'enrolled' => $enrolled, 'skipped' => $skipped, 'swept' => $swept]);
