<?php
/**
 * Cancel a queued enrichment command ("undo" after a mistaken queue).
 *
 * Only pending commands of the user-triggered enrichment types can be
 * cancelled; a command the worker has already picked up (running) or an
 * admin/system command (run_worker, update_worker, ...) is rejected. The
 * worker only executes commands in status 'pending' (api/v1/commands.php), so
 * cancelling here reliably prevents it from running.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';

header('Content-Type: application/json');
requireAuth();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    echo json_encode(['success' => false, 'error' => 'Method not allowed']);
    exit;
}

validateCsrf();

$input = json_decode(file_get_contents('php://input'), true) ?: [];
$commandId = (int)($input['command_id'] ?? 0);
if ($commandId <= 0) {
    echo json_encode(['success' => false, 'error' => 'Missing command_id']);
    exit;
}

// Commands the UI queues on behalf of a user (bulk/domain-detail actions).
$cancellable = [
    'whois_lookup', 'vt_lookup', 'abusech_lookup',
    'cf_scan_lookup', 'cf_dns_lookup', 'tracking_check',
];

$db = Database::get();
$stmt = $db->prepare("SELECT id, command, status FROM commands WHERE id = ? LIMIT 1");
$stmt->execute([$commandId]);
$cmd = $stmt->fetch();
if (!$cmd) {
    echo json_encode(['success' => false, 'error' => 'Command not found']);
    exit;
}
if (!in_array((string)$cmd['command'], $cancellable, true)) {
    echo json_encode(['success' => false, 'error' => 'This command cannot be cancelled from here']);
    exit;
}
if ($cmd['status'] === 'running') {
    echo json_encode(['success' => false, 'error' => 'The command already started and cannot be cancelled']);
    exit;
}
if ($cmd['status'] !== 'pending') {
    echo json_encode(['success' => false, 'error' => 'The command is no longer pending']);
    exit;
}

$upd = $db->prepare(
    "UPDATE commands SET status = 'cancelled', "
    . "executed_at = COALESCE(executed_at, datetime('now')), finished_at = datetime('now') "
    . "WHERE id = ? AND status = 'pending'"
);
$upd->execute([$commandId]);

if ($upd->rowCount() < 1) {
    echo json_encode(['success' => false, 'error' => 'The command already started and cannot be cancelled']);
    exit;
}

echo json_encode(['success' => true, 'cancelled' => true, 'command_id' => $commandId]);
