<?php
/**
 * Domain search against the worker's local cache.
 *
 * The web cannot read the worker SQLite directly, so it queues a `search_domain`
 * command and polls its result. Available to any logged-in user; searches are
 * rate limited and identical pending searches are reused to avoid overloading
 * the worker.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');
requireAuth();

$db = Database::get();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();

    $input = json_decode(file_get_contents('php://input'), true) ?: [];
    $q = strtolower(trim((string)($input['q'] ?? '')));
    $mode = (string)($input['mode'] ?? '');

    if ($q === '' || strlen($q) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $q)) {
        echo json_encode(['success' => false, 'error' => 'Invalid search query']);
        exit;
    }

    // Auto-detect: a dotted / full domain is exact, otherwise partial.
    if (!in_array($mode, ['exact', 'prefix', 'contains'], true)) {
        if (strpos($q, '.') !== false) {
            $mode = 'exact';
        } elseif (strlen($q) >= 4) {
            $mode = 'contains';
        } else {
            $mode = 'prefix';
        }
    }

    // Simple per-session rate limit (max 15 searches / minute).
    $now = time();
    $times = $_SESSION['domain_search_times'] ?? [];
    if (!is_array($times)) {
        $times = [];
    }
    $times = array_values(array_filter($times, function ($t) use ($now) {
        return is_numeric($t) && (int)$t > $now - 60;
    }));
    if (count($times) >= 15) {
        echo json_encode(['success' => false, 'error' => 'Too many searches, please slow down.']);
        exit;
    }
    $times[] = $now;
    $_SESSION['domain_search_times'] = $times;

    $payload = json_encode(['q' => $q, 'mode' => $mode, 'limit' => 100]);

    // Reuse an identical search still pending/running in the last few minutes.
    $stmt = $db->prepare(
        "SELECT id FROM commands WHERE command = 'search_domain' AND payload = ? "
        . "AND status IN ('pending','running') AND created_at >= datetime('now','-5 minutes') "
        . "ORDER BY id DESC LIMIT 1"
    );
    $stmt->execute([$payload]);
    $commandId = (int)$stmt->fetchColumn();

    if (!$commandId) {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)")
           ->execute(['search_domain', $payload]);
        $commandId = (int)$db->lastInsertId();
    }

    echo json_encode(['success' => true, 'command_id' => $commandId, 'mode' => $mode]);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    $commandId = (int)($_GET['command_id'] ?? 0);
    if (!$commandId) {
        echo json_encode(['success' => false, 'error' => 'Missing command_id']);
        exit;
    }

    $stmt = $db->prepare("SELECT status, result FROM commands WHERE id = ? AND command = 'search_domain' LIMIT 1");
    $stmt->execute([$commandId]);
    $cmd = $stmt->fetch();

    $status = $cmd ? (string)$cmd['status'] : 'missing';
    $results = [];
    $partial = false;
    $note = '';

    if ($status === 'completed' && !empty($cmd['result'])) {
        $decoded = json_decode($cmd['result'], true);
        if (is_array($decoded)) {
            $results = isset($decoded['results']) && is_array($decoded['results']) ? $decoded['results'] : [];
            $partial = !empty($decoded['partial']);
            $note = (string)($decoded['note'] ?? '');
        }
    }

    echo json_encode([
        'success' => true,
        'status' => $status,
        'partial' => $partial,
        'note' => $note,
        'results' => $results,
    ]);
    exit;
}

jsonResponse(['success' => false, 'error' => 'Method not allowed'], 405);
