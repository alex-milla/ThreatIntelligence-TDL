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
    $stmt = $db->prepare("SELECT id, note FROM watchlist WHERE user_id = ? AND domain = ? LIMIT 1");
    $stmt->execute([$userId, $domain]);
    $row = $stmt->fetch();
    echo json_encode([
        'success' => true,
        'in_watchlist' => (bool)$row,
        'note' => $row['note'] ?? null
    ]);
    exit;
}

// POST: Toggle add/remove from watchlist
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true);
    $domain = trim($input['domain'] ?? '');

    if ($domain === '') {
        echo json_encode(['success' => false, 'error' => 'Domain required']);
        exit;
    }

    // Check if already in watchlist
    $stmt = $db->prepare("SELECT id FROM watchlist WHERE user_id = ? AND domain = ? LIMIT 1");
    $stmt->execute([$userId, $domain]);
    $existing = $stmt->fetch();

    if ($existing) {
        // Remove
        $db->prepare("DELETE FROM watchlist WHERE id = ? AND user_id = ?")
            ->execute([(int)$existing['id'], $userId]);
        echo json_encode(['success' => true, 'action' => 'removed']);
    } else {
        // Add
        $db->prepare("INSERT INTO watchlist (user_id, domain, note) VALUES (?, ?, ?)")
            ->execute([$userId, $domain, null]);
        echo json_encode(['success' => true, 'action' => 'added']);
    }
    exit;
}

echo json_encode(['success' => false, 'error' => 'Invalid request']);
