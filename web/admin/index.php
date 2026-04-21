<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

$db = Database::get();
$message = '';

// Actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
    $action = $_POST['action'] ?? '';
    
    if ($action === 'toggle_user') {
        $uid = (int)($_POST['user_id'] ?? 0);
        $db->prepare("UPDATE users SET is_active = NOT is_active WHERE id = ?")->execute([$uid]);
        $message = 'User status updated.';
    }
    
    if ($action === 'regen_api') {
        $uid = (int)($_POST['user_id'] ?? 0);
        $newKey = bin2hex(random_bytes(32));
        $db->prepare("UPDATE users SET api_key = ? WHERE id = ?")->execute([$newKey, $uid]);
        $message = 'API key regenerated.';
    }
    
    if ($action === 'run_worker') {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['run_worker', '']);
        $message = 'Worker execution queued. It will run on next poll.';
    }
    
    if ($action === 'update_whitelist') {
        $whitelist = trim($_POST['whitelist'] ?? '');
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['update_whitelist', $whitelist]);
        $message = 'Whitelist update queued for worker.';
    }
}

// Data
$users = $db->query("SELECT id, username, email, is_active, is_admin, api_key, created_at FROM users ORDER BY created_at DESC")->fetchAll();
$syncLogs = $db->query("SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT 20")->fetchAll();
$workerStatus = $db->query("SELECT * FROM worker_status WHERE id = 1")->fetch();
$workerLogs = $db->query("SELECT * FROM worker_logs ORDER BY created_at DESC LIMIT 20")->fetchAll();
$pendingCommands = $db->query("SELECT COUNT(*) FROM commands WHERE status = 'pending'")->fetchColumn();

$pageTitle = 'Admin Panel';
require __DIR__ . '/../templates/header.php';
?>

<?php if ($message): ?>
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="card">
    <h2>Worker Status</h2>
    <?php if ($workerStatus): ?>
        <table>
            <tr><td>Last Heartbeat</td><td><?= htmlspecialchars($workerStatus['last_heartbeat'] ?? 'Never') ?></td></tr>
            <tr><td>Last Run</td><td><?= htmlspecialchars($workerStatus['last_run'] ?? 'Never') ?></td></tr>
            <tr><td>TLDs Processed</td><td><?= (int)($workerStatus['tlds_processed'] ?? 0) ?></td></tr>
            <tr><td>Domains Processed</td><td><?= (int)($workerStatus['domains_processed'] ?? 0) ?></td></tr>
            <tr><td>Matches Found</td><td><?= (int)($workerStatus['matches_found'] ?? 0) ?></td></tr>
            <tr><td>Currently Running</td><td><?= ($workerStatus['is_running'] ?? 0) ? 'Yes' : 'No' ?></td></tr>
            <tr><td>Version</td><td><?= htmlspecialchars($workerStatus['version'] ?? 'Unknown') ?></td></tr>
            <tr><td>Pending Commands</td><td><?= (int)$pendingCommands ?></td></tr>
        </table>
    <?php else: ?>
        <p>No worker status received yet. Is the worker running?</p>
    <?php endif; ?>
    
    <div style="margin-top: 15px; display: flex; gap: 10px; flex-wrap: wrap;">
        <form method="POST" style="display: inline;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="run_worker">
            <button type="submit" class="btn">Run Worker Now</button>
        </form>
        <a href="/admin/tlds.php" class="btn">Manage TLDs</a>
        <a href="/admin/update.php" class="btn">Check for Updates</a>
    </div>
</div>

<div class="card">
    <h2>Worker TLD Whitelist</h2>
    <form method="POST">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="update_whitelist">
        <label>TLDs to process (comma separated, empty = all approved)</label>
        <input type="text" name="whitelist" value="zip, wine" placeholder="zip, wine, xyz" style="width: 100%; margin-bottom: 10px;">
        <button type="submit" class="btn">Update Whitelist</button>
    </form>
</div>

<div class="card">
    <h2>Worker Logs</h2>
    <?php if (empty($workerLogs)): ?>
        <p>No worker logs yet.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr><th>Time</th><th>Level</th><th>Message</th></tr>
            </thead>
            <tbody>
                <?php foreach ($workerLogs as $log): ?>
                <tr>
                    <td><?= htmlspecialchars($log['created_at']) ?></td>
                    <td><?= htmlspecialchars($log['level']) ?></td>
                    <td><?= htmlspecialchars($log['message']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<div class="card">
    <h2>Users</h2>
    <table>
        <thead>
            <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Active</th>
                <th>Admin</th>

                <th>API Key</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($users as $u): ?>
            <tr>
                <td><?= (int)$u['id'] ?></td>
                <td><?= htmlspecialchars($u['username']) ?></td>
                <td><?= htmlspecialchars($u['email']) ?></td>
                <td><?= $u['is_active'] ? 'Yes' : 'No' ?></td>
                <td><?= $u['is_admin'] ? 'Yes' : 'No' ?></td>

                <td style="font-family: monospace; font-size: 0.8rem;"><?= substr(htmlspecialchars($u['api_key']), 0, 16) ?>...</td>
                <td>
                    <form method="POST" style="display: inline;">
                        <?php csrfField(); ?>
                        <input type="hidden" name="action" value="toggle_user">
                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                        <button type="submit" class="btn btn-small"><?= $u['is_active'] ? 'Disable' : 'Enable' ?></button>
                    </form>
                    <form method="POST" style="display: inline;">
                        <?php csrfField(); ?>
                        <input type="hidden" name="action" value="regen_api">
                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                        <button type="submit" class="btn btn-small btn-danger" onclick="return confirm('Regenerate API key?')">Regen Key</button>
                    </form>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<div class="card">
    <h2>Sync Logs</h2>
    <table>
        <thead>
            <tr><th>Time</th><th>Source</th><th>Received</th><th>Inserted</th><th>Error</th></tr>
        </thead>
        <tbody>
            <?php foreach ($syncLogs as $log): ?>
            <tr>
                <td><?= htmlspecialchars($log['created_at']) ?></td>
                <td><?= htmlspecialchars($log['source']) ?></td>
                <td><?= (int)$log['records_received'] ?></td>
                <td><?= (int)$log['records_inserted'] ?></td>
                <td><?= htmlspecialchars($log['error'] ?? '-') ?></td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<div class="card">
    <h2>System</h2>
    <p><a href="/admin/update.php" class="btn">Check for Updates</a></p>
</div>

<?php require __DIR__ . '/../templates/footer.php'; ?>
