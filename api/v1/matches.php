<?php
require_once __DIR__ . '/../../includes/db.php';
require_once __DIR__ . '/../../includes/auth.php';
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

$input = json_decode(file_get_contents('php://input'), true);
if (!isset($input['matches']) || !is_array($input['matches'])) {
    jsonResponse(['success' => false, 'error' => 'Invalid payload'], 400);
}

$matches = $input['matches'];
$discoveredAt = $input['discovered_at'] ?? date('c');
$inserted = 0;

// Track emails to send per user
$emailQueue = []; // [user_id => [email, username, matches[]]]

$db->beginTransaction();

try {
    $insertMatch = $db->prepare("INSERT OR IGNORE INTO matches (keyword_id, domain, tld, discovered_at, first_seen) VALUES (?, ?, ?, ?, ?)");
    $insertNotif = $db->prepare("INSERT INTO notifications (user_id, match_id) VALUES (?, ?)");
    $updateCount = $db->prepare("UPDATE keywords SET match_count = match_count + 1 WHERE id = ?");
    $getKeywordOwner = $db->prepare("SELECT k.user_id, k.keyword, u.email, u.username, u.email_notifications FROM keywords k JOIN users u ON k.user_id = u.id WHERE k.id = ? LIMIT 1");

    foreach ($matches as $m) {
        $keywordId = (int)($m['keyword_id'] ?? 0);
        $domain = $m['domain'] ?? '';
        $tld = $m['tld'] ?? '';
        if (!$keywordId || !$domain) {
            continue;
        }

        // Basic domain sanitization
        $domain = strtolower(trim($domain));
        if (strlen($domain) > 253 || !preg_match('/^[a-z0-9\-\.]+$/', $domain)) {
            continue; // skip invalid domain
        }
        if (strpos($domain, '..') !== false) {
            continue; // skip malformed
        }

        $firstSeen = $m['first_seen'] ?? $discoveredAt;
        $insertMatch->execute([$keywordId, $domain, $tld, $discoveredAt, $firstSeen]);
        if ($insertMatch->rowCount() > 0) {
            $matchId = (int)$db->lastInsertId();
            $inserted++;

            // Find keyword owner and create notification
            $getKeywordOwner->execute([$keywordId]);
            $keywordRow = $getKeywordOwner->fetch();
            if ($keywordRow) {
                $insertNotif->execute([$keywordRow['user_id'], $matchId]);

                // Queue email if user wants notifications
                if (!empty($keywordRow['email_notifications'])) {
                    $uid = (int)$keywordRow['user_id'];
                    if (!isset($emailQueue[$uid])) {
                        $emailQueue[$uid] = [
                            'email' => $keywordRow['email'],
                            'username' => $keywordRow['username'],
                            'matches' => [],
                        ];
                    }
                    $emailQueue[$uid]['matches'][] = [
                        'domain' => $domain,
                        'keyword' => $keywordRow['keyword'],
                    ];
                }
            }

            $updateCount->execute([$keywordId]);
        }
    }

    $db->commit();

    // Log sync
    $logStmt = $db->prepare("INSERT INTO sync_logs (source, records_received, records_inserted) VALUES (?, ?, ?)");
    $logStmt->execute(['worker', count($matches), $inserted]);

    // Respond immediately so the worker gets 200 before email delay
    http_response_code(200);
    header('Content-Type: application/json');
    echo json_encode(['success' => true, 'inserted' => $inserted], JSON_PRETTY_PRINT);

    if (function_exists('fastcgi_finish_request')) {
        fastcgi_finish_request();
    } else {
        ob_flush();
        flush();
    }

    ignore_user_abort(true);

    // Send emails after response (so DB is not blocked and worker doesn't timeout)
    foreach ($emailQueue as $queue) {
        sendMatchEmail($queue['email'], $queue['username'], $queue['matches']);
    }

    exit;
} catch (Exception $e) {
    $db->rollBack();
    // Log error
    $logStmt = $db->prepare("INSERT INTO sync_logs (source, records_received, error) VALUES (?, ?, ?)");
    $logStmt->execute(['worker', count($matches), $e->getMessage()]);
    jsonResponse(['success' => false, 'error' => $e->getMessage()], 500);
}
