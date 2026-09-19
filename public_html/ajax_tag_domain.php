<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $domain = strtolower(trim($_GET['domain'] ?? ''));
    if (!$domain) {
        echo json_encode(['success' => false, 'error' => 'Invalid domain']);
        exit;
    }
    $stmt = $db->prepare("SELECT domain, tag, note, created_at FROM domain_tags WHERE domain = ? LIMIT 1");
    $stmt->execute([$domain]);
    $tag = $stmt->fetch();
    echo json_encode(['success' => true, 'tag' => $tag ?: null]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $domain = strtolower(trim($input['domain'] ?? ''));
    $tag = $input['tag'] ?? '';

    if (!$domain) {
        echo json_encode(['success' => false, 'error' => 'Invalid domain']);
        exit;
    }

    if ($tag === '' || $tag === null) {
        $db->prepare("DELETE FROM domain_tags WHERE domain = ?")->execute([$domain]);
        echo json_encode(['success' => true]);
        exit;
    }

    if (!in_array($tag, ['good', 'bad'], true)) {
        echo json_encode(['success' => false, 'error' => 'Invalid tag']);
        exit;
    }

    $note = trim($input['note'] ?? '');
    $stmt = $db->prepare("INSERT OR REPLACE INTO domain_tags (domain, tag, note, created_by) VALUES (?, ?, ?, ?)");
    $stmt->execute([$domain, $tag, $note, $userId]);
    echo json_encode(['success' => true]);
    exit;
}

echo json_encode(['success' => false, 'error' => 'Method not allowed']);
