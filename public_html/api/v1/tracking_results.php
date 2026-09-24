<?php
/**
 * Tracking check results sent by the worker: update the tracking rows, activate
 * or reschedule them, and raise an Intelligence notification on activation.
 */
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
require_once __DIR__ . '/../../includes/tracking.php';
require_once __DIR__ . '/../../includes/mail.php';

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

$rowsStmt = $db->prepare("SELECT dt.id, dt.keyword_id, dt.user_id, k.tracking_interval_hours, k.keyword
    FROM domain_tracking dt JOIN keywords k ON k.id = dt.keyword_id
    WHERE dt.domain = ? AND dt.status = 'tracking'");
$matchStmt = $db->prepare("SELECT m.id AS match_id, k.user_id, k.keyword, u.email, u.username, u.email_notifications
    FROM matches m JOIN keywords k ON k.id = m.keyword_id JOIN users u ON u.id = k.user_id
    WHERE m.domain = ? AND m.keyword_id = ? LIMIT 1");
$existNotif = $db->prepare("SELECT 1 FROM notifications WHERE user_id = ? AND match_id = ? AND kind = 'intelligence' LIMIT 1");
$insNotif = $db->prepare("INSERT INTO notifications (user_id, match_id, kind) VALUES (?, ?, 'intelligence')");
$updCheck = $db->prepare("UPDATE domain_tracking SET check_count = check_count + 1, last_checked_at = ?, next_check_at = ? WHERE id = ?");
$updActivated = $db->prepare("UPDATE domain_tracking SET check_count = check_count + 1, last_checked_at = ?, next_check_at = NULL WHERE id = ?");

$applied = 0;
$activatedCount = 0;
$emailQueue = []; // user_id => [email, username, items[]]
$now = trackingNow();

$db->beginTransaction();
try {
    foreach (array_slice($entries, 0, 1000) as $entry) {
        if (!is_array($entry)) {
            continue;
        }
        $domain = strtolower(trim((string)($entry['domain'] ?? '')));
        if ($domain === '' || strlen($domain) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $domain)) {
            continue;
        }
        $activated = !empty($entry['activated']);
        $reason = trim((string)($entry['activated_reason'] ?? 'activation signal'));
        $whoisChanged = !empty($entry['whois_changed']);
        $whoisDetail = trim((string)($entry['whois_detail'] ?? ''));

        $rowsStmt->execute([$domain]);
        $rows = $rowsStmt->fetchAll();
        if (!$rows) {
            continue;
        }
        $applied++;

        if ($activated) {
            trackingActivate($db, $domain, $reason);
            foreach ($rows as $row) {
                $updActivated->execute([$now, (int)$row['id']]);
                $activatedCount++;
            }
            // One Intelligence notification per (domain, keyword) that has a match.
            foreach ($rows as $row) {
                $matchStmt->execute([$domain, (int)$row['keyword_id']]);
                $m = $matchStmt->fetch();
                if (!$m) {
                    continue;
                }
                $existNotif->execute([(int)$m['user_id'], (int)$m['match_id']]);
                if ($existNotif->fetchColumn()) {
                    continue;
                }
                $insNotif->execute([(int)$m['user_id'], (int)$m['match_id']]);
                if (!empty($m['email_notifications']) && filter_var($m['email'], FILTER_VALIDATE_EMAIL)) {
                    $uid = (int)$m['user_id'];
                    if (!isset($emailQueue[$uid])) {
                        $emailQueue[$uid] = ['email' => $m['email'], 'username' => $m['username'], 'items' => []];
                    }
                    $emailQueue[$uid]['items'][] = [
                        'domain'  => $domain,
                        'keyword' => $m['keyword'],
                        'reason'  => $reason,
                    ];
                }
            }
        } else {
            foreach ($rows as $row) {
                $interval = max(1, (int)($row['tracking_interval_hours'] ?? 24));
                $updCheck->execute([$now, trackingNextCheck($interval, $now), (int)$row['id']]);
                if ($whoisChanged) {
                    trackingEvent($db, (int)$row['id'], 'whois_change', $whoisDetail !== '' ? $whoisDetail : 'WHOIS/NS changed');
                }
            }
        }
    }
    $db->commit();
} catch (Exception $e) {
    $db->rollBack();
    jsonResponse(['success' => false, 'error' => 'Failed to apply tracking results'], 500);
}

foreach ($emailQueue as $queue) {
    sendIntelligenceEmail($queue['email'], $queue['username'], $queue['items']);
}

jsonResponse(['success' => true, 'applied' => $applied, 'activated' => $activatedCount]);
