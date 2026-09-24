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
$tagStmt = $db->prepare("SELECT tag FROM domain_tags WHERE domain = ? LIMIT 1");
$abStmt = $db->prepare("SELECT verdict FROM domain_abusech WHERE domain = ? LIMIT 1");
$wlStmt = $db->prepare("SELECT creation_date FROM domain_whois WHERE domain = ? LIMIT 1");
$insStmt = $db->prepare("INSERT OR IGNORE INTO domain_tracking
    (domain, keyword_id, user_id, first_seen, enrolled_at, expires_at, status, baseline, next_check_at)
    VALUES (?, ?, ?, ?, ?, ?, 'tracking', ?, ?)");

$enrolled = 0;
$skipped = 0;
$now = trackingNow();

$db->beginTransaction();
try {
    foreach (array_slice($entries, 0, 5000) as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $domain = strtolower(trim((string)($entry['domain'] ?? '')));
        $keywordId = (int)($entry['keyword_id'] ?? 0);
        if ($domain === '' || strlen($domain) > 253 || strpos($domain, '..') !== false
            || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $domain) || $keywordId <= 0) {
            $skipped++;
            continue;
        }

        $kwStmt->execute([$keywordId]);
        $kw = $kwStmt->fetch();
        if (!$kw) {
            $skipped++; // tracking disabled for this keyword
            continue;
        }

        $tagStmt->execute([$domain]);
        $tag = (string)$tagStmt->fetchColumn();
        if (in_array($tag, ['bad', 'excluded'], true)) {
            $skipped++;
            continue;
        }

        $abStmt->execute([$domain]);
        $abVerdict = (string)$abStmt->fetchColumn();
        if (in_array($abVerdict, ['malicious', 'suspicious'], true)) {
            $skipped++; // already flagged: not a dormant candidate
            continue;
        }

        // Only recently registered domains are worth following.
        $creationDate = trim((string)($entry['creation_date'] ?? ''));
        if ($creationDate === '') {
            $wlStmt->execute([$domain]);
            $creationDate = (string)($wlStmt->fetchColumn() ?: '');
        }
        $age = trackingAgeDays($creationDate);
        $maxAge = max(1, (int)($kw['tracking_enroll_max_age_days'] ?? 30));
        if ($age === null || $age > $maxAge) {
            $skipped++;
            continue;
        }

        $firstSeen = (string)($entry['first_seen'] ?? '');
        $expires = trackingAddDays($now, max(1, (int)($kw['tracking_days'] ?? 90)));
        $baseline = json_encode(trackingBaseline($db, $domain), JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        $insStmt->execute([$domain, (int)$kw['id'], (int)$kw['user_id'], $firstSeen ?: null, $now, $expires, $baseline, $now]);
        if ($insStmt->rowCount() > 0) {
            $tid = (int)$db->lastInsertId();
            trackingEvent($db, $tid, 'enrolled', 'age ' . $age . 'd');
            $enrolled++;
        } else {
            $skipped++; // already tracked
        }
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to enroll tracking entries'], 500);
}

jsonResponse(['success' => true, 'enrolled' => $enrolled, 'skipped' => $skipped]);
