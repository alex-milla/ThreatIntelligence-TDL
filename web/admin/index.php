<?php
require __DIR__ . '/../includes/db.php';
require __DIR__ . '/../includes/auth.php';
requireAdmin();

$db = Database::get();
$message = '';

// Actions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    if ($action === 'toggle_user') {
        $uid = (int)($_POST['user_id'] ?? 0);
        $db->prepare("UPDATE users SET is_active = NOT is_active WHERE id = ?")->execute([$uid]);
        $message = 'User status updated.';
    }
    
    if ($action === 'set_limit') {
        $uid = (int)($_POST['user_id'] ?? 0);
        $limit = (int)($_POST['max_keywords'] ?? 10);
        $db->prepare("UPDATE users SET max_keywords = ? WHERE id = ?")->execute([$limit, $uid]);
        $message = 'Keyword limit updated.';
    }
    
    if ($action === 'regen_api') {
        $uid = (int)($_POST['user_id'] ?? 0);
        $newKey = bin2hex(random_bytes(32));
        $db->prepare("UPDATE users SET api_key = ? WHERE id = ?")->execute([$newKey, $uid]);
        $message = 'API key regenerated.';
    }
}

// Data
$users = $db->query("SELECT id, username, email, is_active, is_admin, max_keywords, api_key, created_at FROM users ORDER BY created_at DESC")->fetchAll();
$syncLogs = $db->query("SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT 20")->fetchAll();

$pageTitle = 'Admin Panel';
require __DIR__ . '/../templates/header.php';
?>

<?php if ($message): ?>
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

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
                <th>Keyword Limit</th>
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
                <td>
                    <form method="POST" style="display: flex; gap: 5px;">
                        <input type="hidden" name="action" value="set_limit">
                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                        <input type="number" name="max_keywords" value="<?= (int)$u['max_keywords'] ?>" style="width: 60px;">
                        <button type="submit" class="btn btn-small">Save</button>
                    </form>
                </td>
                <td style="font-family: monospace; font-size: 0.8rem;"><?= substr(htmlspecialchars($u['api_key']), 0, 16) ?>...</td>
                <td>
                    <form method="POST" style="display: inline;">
                        <input type="hidden" name="action" value="toggle_user">
                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                        <button type="submit" class="btn btn-small"><?= $u['is_active'] ? 'Disable' : 'Enable' ?></button>
                    </form>
                    <form method="POST" style="display: inline;">
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
