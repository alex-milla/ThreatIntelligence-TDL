<?php
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';

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

$input = json_decode(file_get_contents('php://input'), true);
if (!isset($input['matches']) || !is_array($input['matches'])) {
    jsonResponse(['success' => false, 'error' => 'Invalid payload'], 400);
}

$matches = $input['matches'];
$discoveredAt = $input['discovered_at'] ?? date('c');
$inserted = 0;

$db->beginTransaction();

try {
    $insertMatch = $db->prepare("INSERT OR IGNORE INTO matches (keyword_id, domain, tld, discovered_at) VALUES (?, ?, ?, ?)");
    $insertNotif = $db->prepare("INSERT INTO notifications (user_id, match_id) VALUES (?, ?)");
    $updateCount = $db->prepare("UPDATE keywords SET match_count = match_count + 1 WHERE id = ?");
    $getKeywordOwner = $db->prepare("SELECT user_id FROM keywords WHERE id = ?");

    foreach ($matches as $m) {
        $keywordId = (int)($m['keyword_id'] ?? 0);
        $domain = $m['domain'] ?? '';
        $tld = $m['tld'] ?? '';
        if (!$keywordId || !$domain) {
            continue;
        }

        $insertMatch->execute([$keywordId, $domain, $tld, $discoveredAt]);
        if ($insertMatch->rowCount() > 0) {
            $matchId = (int)$db->lastInsertId();
            $inserted++;

            // Find keyword owner and create notification
            $getKeywordOwner->execute([$keywordId]);
            $keywordRow = $getKeywordOwner->fetch();
            if ($keywordRow) {
                $insertNotif->execute([$keywordRow['user_id'], $matchId]);
            }

            $updateCount->execute([$keywordId]);
        }
    }

    // Log sync
    $logStmt = $db->prepare("INSERT INTO sync_logs (source, records_received, records_inserted) VALUES (?, ?, ?)");
    $logStmt->execute(['worker', count($matches), $inserted]);

    $db->commit();
    jsonResponse(['success' => true, 'inserted' => $inserted]);
} catch (Exception $e) {
    $db->rollBack();
    // Log error
    $logStmt = $db->prepare("INSERT INTO sync_logs (source, records_received, error) VALUES (?, ?, ?)");
    $logStmt->execute(['worker', count($matches), $e->getMessage()]);
    jsonResponse(['success' => false, 'error' => $e->getMessage()], 500);
}
