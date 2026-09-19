<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

header('Content-Type: application/json');
$db = Database::get();
$userId = (int)$_SESSION['user_id'];

// GET: Check if a domain is in the user's watchlist
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['check'])) {
    $domain = trim($_GET['check']);
    $stmt = $db->prepare("SELECT w.id, w.note, w.group_id, g.name as group_name 
        FROM watchlist w 
        LEFT JOIN watchlist_groups g ON w.group_id = g.id AND g.user_id = ?
        WHERE w.user_id = ? AND w.domain = ? LIMIT 1");
    $stmt->execute([$userId, $userId, $domain]);
    $row = $stmt->fetch();
    echo json_encode([
        'success' => true,
        'in_watchlist' => (bool)$row,
        'note' => $row['note'] ?? null,
        'group_id' => $row['group_id'] ?? null,
        'group_name' => $row['group_name'] ?? null
    ]);
    exit;
}

// POST: Toggle add/remove from watchlist, or group actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $action = $input['action'] ?? 'toggle';

    // Toggle add/remove
    if ($action === 'toggle') {
        $domain = trim($input['domain'] ?? '');
        if ($domain === '') {
            echo json_encode(['success' => false, 'error' => 'Domain required']);
            exit;
        }

        $stmt = $db->prepare("SELECT id FROM watchlist WHERE user_id = ? AND domain = ? LIMIT 1");
        $stmt->execute([$userId, $domain]);
        $existing = $stmt->fetch();

        if ($existing) {
            $db->prepare("DELETE FROM watchlist WHERE id = ? AND user_id = ?")
                ->execute([(int)$existing['id'], $userId]);
            echo json_encode(['success' => true, 'action' => 'removed']);
        } else {
            $groupId = isset($input['group_id']) && $input['group_id'] !== '' ? (int)$input['group_id'] : null;
            $db->prepare("INSERT INTO watchlist (user_id, domain, note, group_id) VALUES (?, ?, ?, ?)")
                ->execute([$userId, $domain, null, $groupId]);
            echo json_encode(['success' => true, 'action' => 'added']);
        }
        exit;
    }

    // Set group for a watchlist entry
    if ($action === 'set_group') {
        $watchId = (int)($input['watch_id'] ?? 0);
        $groupId = isset($input['group_id']) && $input['group_id'] !== '' ? (int)$input['group_id'] : null;
        $db->prepare("UPDATE watchlist SET group_id = ? WHERE id = ? AND user_id = ?")
            ->execute([$groupId, $watchId, $userId]);
        echo json_encode(['success' => true]);
        exit;
    }

    echo json_encode(['success' => false, 'error' => 'Invalid action']);
    exit;
}

echo json_encode(['success' => false, 'error' => 'Invalid request']);
