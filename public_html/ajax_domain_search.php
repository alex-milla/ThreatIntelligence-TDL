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
    $raw = (string)($input['q'] ?? '');
    $mode = (string)($input['mode'] ?? '');
    $allowedModes = ['exact', 'prefix', 'contains', 'glob'];
    if (!in_array($mode, $allowedModes, true)) {
        $mode = '';
    }

    if ($mode === 'glob') {
        // A glob keeps its metacharacters: lowercase + trim only (no URL/host
        // normalisation, which would strip '?' and '/' meaning). Validated
        // against the same charset the keyword engine understands.
        $q = strtolower(trim($raw));
        if ($q === '' || strlen($q) > 253
            || !preg_match('/^[a-z0-9\p{L}\-\.\*\?\[\]\{\}!^]+$/u', $q)) {
            echo json_encode(['success' => false, 'error' => 'Invalid glob pattern']);
            exit;
        }
    } else {
        // Accept defanged IOCs (my-passkeys[.]com) and URLs; keep only the hostname.
        $q = normalizeDomainSearch($raw);
        if ($q === '' || strlen($q) > 253 || !preg_match('/^[a-z0-9\p{L}\-\.]+$/u', $q)) {
            echo json_encode(['success' => false, 'error' => 'Invalid search query']);
            exit;
        }
    }

    // Auto-detect: a dotted / full domain is exact, otherwise partial.
    if ($mode === '') {
        if (strpos($q, '.') !== false) {
            $mode = 'exact';
        } elseif (strlen($q) >= 4) {
            $mode = 'contains';
        } else {
            $mode = 'prefix';
        }
    }

    // Optional discovery-date window. Only the glob search uses it; it defaults
    // to the last 7 days and is capped at 90 days to keep the scan bounded.
    $after = null;
    $before = null;
    if ($mode === 'glob') {
        $maxSpanDays = 90;
        $today = gmdate('Y-m-d');
        $rawAfter = trim((string)($input['after'] ?? ''));
        $rawBefore = trim((string)($input['before'] ?? ''));
        $isDate = function (string $d): bool {
            return (bool)preg_match('/^\d{4}-\d{2}-\d{2}$/', $d)
                && checkdate((int)substr($d, 5, 2), (int)substr($d, 8, 2), (int)substr($d, 0, 4));
        };
        if ($rawBefore === '') {
            $rawBefore = $today;
        }
        if ($rawAfter === '') {
            // UTC arithmetic (avoids a one-day drift from a non-UTC server TZ).
            $rawAfter = gmdate('Y-m-d', time() - 7 * 86400);
        }
        if (!$isDate($rawAfter) || !$isDate($rawBefore)) {
            echo json_encode(['success' => false, 'error' => 'Invalid date range']);
            exit;
        }
        if ($rawAfter > $rawBefore) {
            echo json_encode(['success' => false, 'error' => 'The start date must be on or before the end date.']);
            exit;
        }
        if ($rawBefore > $today || $rawAfter > $today) {
            echo json_encode(['success' => false, 'error' => 'Dates cannot be in the future.']);
            exit;
        }
        $span = (int)floor((strtotime($rawBefore) - strtotime($rawAfter)) / 86400);
        if ($span > $maxSpanDays) {
            echo json_encode(['success' => false, 'error' => 'The maximum search period is 90 days.']);
            exit;
        }
        $after = $rawAfter;
        $before = $rawBefore;
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

    $payloadData = ['q' => $q, 'mode' => $mode, 'limit' => 100];
    if ($mode === 'glob') {
        $payloadData['after'] = $after;
        $payloadData['before'] = $before;
    }
    $payload = json_encode($payloadData);

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
