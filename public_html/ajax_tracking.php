<?php
/**
 * Intelligence tracking actions from the UI: queue a check (admin), clear,
 * extend or delete a tracked domain (owner).
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
require_once __DIR__ . '/includes/tracking.php';

header('Content-Type: application/json');
requireAuth();
validateCsrf();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);
$input = json_decode(file_get_contents('php://input'), true) ?: [];
$action = (string)($input['action'] ?? '');
$id = (int)($input['id'] ?? 0);

// Load the row, enforcing ownership for non-admins.
$row = null;
if ($id > 0) {
    $stmt = $db->prepare("SELECT id, user_id, domain, keyword_id, expires_at FROM domain_tracking WHERE id = ? LIMIT 1");
    $stmt->execute([$id]);
    $row = $stmt->fetch() ?: null;
    if (!$row || (!$isAdmin && (int)$row['user_id'] !== $userId)) {
        echo json_encode(['success' => false, 'error' => 'Not found']);
        exit;
    }
}

if ($action === 'check') {
    if (!$isAdmin) {
        echo json_encode(['success' => false, 'error' => 'Only administrators can run a check.']);
        exit;
    }
    $domains = $input['domains'] ?? null;
    if (is_array($domains) && $domains) {
        $clean = [];
        foreach (array_slice($domains, 0, 200) as $d) {
            $d = strtolower(trim((string)$d));
            if ($d !== '' && strlen($d) <= 253 && preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $d)) {
                $clean[$d] = true;
            }
        }
        $clean = array_keys($clean);
        $payload = $clean ? json_encode(['domains' => $clean]) : '';
    } else {
        $payload = '';
    }
    $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)")->execute(['tracking_check', $payload]);
    echo json_encode(['success' => true, 'queued' => 1, 'command_id' => (int)$db->lastInsertId()]);
    exit;
}

if ($action === 'clear') {
    $db->prepare("UPDATE domain_tracking SET status = 'dormant', next_check_at = NULL WHERE id = ?")->execute([$id]);
    trackingEvent($db, $id, 'cleared', 'cleared from Intelligence');
    echo json_encode(['success' => true]);
    exit;
}

if ($action === 'extend') {
    $days = max(1, min(3650, (int)($input['days'] ?? 90)));
    $base = (string)($row['expires_at'] ?? '');
    $newExpiry = ($base !== '') ? trackingAddDays($base, $days) : trackingAddDays(trackingNow(), $days);
    $db->prepare("UPDATE domain_tracking SET expires_at = ?, status = 'tracking', next_check_at = ? WHERE id = ?")
       ->execute([$newExpiry, trackingNow(), $id]);
    trackingEvent($db, $id, 'extended', '+' . $days . 'd');
    echo json_encode(['success' => true, 'expires_at' => $newExpiry]);
    exit;
}

if ($action === 'delete') {
    $db->prepare("DELETE FROM domain_tracking_events WHERE tracking_id = ?")->execute([$id]);
    $db->prepare("DELETE FROM domain_tracking WHERE id = ?")->execute([$id]);
    echo json_encode(['success' => true]);
    exit;
}

echo json_encode(['success' => false, 'error' => 'Unknown action']);
