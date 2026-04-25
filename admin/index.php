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
        if ($uid === (int)$_SESSION['user_id']) {
            $message = 'You cannot disable your own account.';
        } else {
            $db->prepare("UPDATE users SET is_active = NOT is_active WHERE id = ?")->execute([$uid]);
            $message = 'User status updated.';
        }
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
    
    if ($action === 'recheck_keywords') {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['recheck_keywords', '']);
        $message = 'Keyword recheck queued. The worker will scan all cached domains against current keywords.';
    }
    
    if ($action === 'update_whitelist') {
        $whitelist = trim($_POST['whitelist'] ?? '');
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['update_whitelist', $whitelist]);
        $message = 'Whitelist update queued for worker.';
    }
    
    if ($action === 'toggle_registration') {
        $current = isRegistrationOpen($db);
        setSetting($db, 'registration_open', $current ? '0' : '1');
        $message = $current ? 'Registration closed.' : 'Registration opened.';
    }
    
    if ($action === 'set_max_keywords') {
        $uid = (int)($_POST['user_id'] ?? 0);
        $max = (int)($_POST['max_keywords'] ?? 10);
        if ($max < 0) $max = 0;
        $db->prepare("UPDATE users SET max_keywords = ? WHERE id = ?")->execute([$max, $uid]);
        $message = 'Keyword limit updated.';
    }
    
    if ($action === 'set_new_domain_days') {
        $days = (int)($_POST['new_domain_days'] ?? 1);
        if ($days < 1) $days = 1;
        if ($days > 365) $days = 365;
        setSetting($db, 'new_domain_days', (string)$days);
        $message = "New domain threshold updated to {$days} day(s).";
    }
}

// Data
$users = $db->query("SELECT id, username, email, is_active, is_admin, api_key, max_keywords, created_at FROM users ORDER BY created_at DESC")->fetchAll();
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
    <h2>Keyword Recheck Status</h2>
    <?php
    $recheckStatus = $db->query("SELECT * FROM recheck_status WHERE id = 1")->fetch();
    $recheckRunning = !empty($recheckStatus['is_running']);
    $recheckTotal = (int)($recheckStatus['total_domains'] ?? 0);
    $recheckChecked = (int)($recheckStatus['checked_domains'] ?? 0);
    $recheckMatches = (int)($recheckStatus['matches_found'] ?? 0);
    $recheckPct = $recheckTotal > 0 ? round($recheckChecked / $recheckTotal * 100, 1) : 0;
    ?>
    <div id="recheck-container" data-running="<?= $recheckRunning ? '1' : '0' ?>">
        <?php if ($recheckRunning): ?>
            <p><strong>Status:</strong> <span style="color: #e67e22;">Running</span></p>
            <div style="background: #f0f0f0; border-radius: 4px; height: 24px; margin: 10px 0; overflow: hidden;">
                <div id="recheck-bar" style="background: #3498db; width: <?= $recheckPct ?>%; height: 100%; transition: width 0.5s;"></div>
            </div>
            <p id="recheck-text">
                Checked <strong><?= number_format($recheckChecked) ?></strong> of <strong><?= number_format($recheckTotal) ?></strong> domains
                (<?= $recheckPct ?>%) — <strong><?= number_format($recheckMatches) ?></strong> matches found
            </p>
        <?php elseif ($recheckStatus && $recheckStatus['completed_at'] && $recheckTotal == 0): ?>
            <p><strong>Status:</strong> <span style="color: #c0392b;">No cached domains</span></p>
            <p style="color: #c0392b;">The worker has not downloaded any zones yet. Run the worker first to build the domain cache.</p>
        <?php elseif ($recheckStatus && $recheckStatus['completed_at']): ?>
            <p><strong>Status:</strong> <span style="color: #27ae60;">Completed</span> at <?= htmlspecialchars($recheckStatus['completed_at']) ?></p>
            <p>Checked <strong><?= number_format($recheckChecked) ?></strong> domains — <strong><?= number_format($recheckMatches) ?></strong> matches found</p>
        <?php else: ?>
            <p><strong>Status:</strong> <span style="color: #7f8c8d;">Idle</span></p>
        <?php endif; ?>
    </div>
</div>

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
        <form method="POST" style="display: inline;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="recheck_keywords">
            <button type="submit" class="btn btn-danger">Recheck Keywords</button>
        </form>
        <a href="/admin/tlds.php" class="btn">Manage TLDs</a>
        <a href="/admin/cleanup.php" class="btn btn-danger">Cleanup False Matches</a>
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
                <th>Max Keywords</th>
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
                    <form method="POST" style="display: inline; white-space: nowrap;">
                        <?php csrfField(); ?>
                        <input type="hidden" name="action" value="set_max_keywords">
                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                        <input type="number" name="max_keywords" value="<?= (int)$u['max_keywords'] ?>" min="0" style="width: 55px; padding: 4px;">
                        <button type="submit" class="btn btn-small" title="0 = unlimited">Set</button>
                    </form>
                </td>
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

<?php $regOpen = isRegistrationOpen($db); ?>
<div class="card">
    <h2>System</h2>
    <p><a href="/admin/update.php" class="btn">Check for Updates</a></p>
    
    <h3 style="margin-top: 20px;">Registration</h3>
    <p>Status: <strong><?= $regOpen ? 'Open' : 'Closed' ?></strong></p>
    <form method="POST" style="margin-top: 10px;">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="toggle_registration">
        <button type="submit" class="btn <?= $regOpen ? 'btn-danger' : '' ?>"><?= $regOpen ? 'Close Registration' : 'Open Registration' ?></button>
    </form>
    
    <hr style="margin: 15px 0; border: none; border-top: 1px solid #eee;">
    
    <form method="POST" style="display: flex; gap: 10px; align-items: center;">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="set_new_domain_days">
        <label style="white-space: nowrap;">New domain threshold:</label>
        <input type="number" name="new_domain_days" value="<?= (int)getSetting($db, 'new_domain_days', '1') ?>" min="1" max="365" style="width: 70px; padding: 6px;">
        <span style="color: #666; font-size: 0.9rem;">day(s)</span>
        <button type="submit" class="btn btn-small">Save</button>
    </form>
    <p style="color: #666; font-size: 0.85rem; margin-top: 5px;">Domains created within this window will show the 🆕 badge and appear in the "New only" filter.</p>
</div>

<script>
(function() {
    const container = document.getElementById('recheck-container');
    if (!container || container.dataset.running !== '1') return;

    function updateStatus() {
        fetch('/ajax_recheck_status.php')
            .then(r => r.json())
            .then(data => {
                if (!data.success || !data.status) return;
                const s = data.status;
                const running = s.is_running == 1;
                const pct = s.progress_pct || 0;
                const checked = parseInt(s.checked_domains || 0).toLocaleString();
                const total = parseInt(s.total_domains || 0).toLocaleString();
                const matches = parseInt(s.matches_found || 0).toLocaleString();

                if (!running) {
                    container.dataset.running = '0';
                    container.innerHTML = `
                        <p><strong>Status:</strong> <span style="color: #27ae60;">Completed</span> at ${s.completed_at || 'just now'}</p>
                        <p>Checked <strong>${checked}</strong> domains — <strong>${matches}</strong> matches found</p>
                    `;
                    return;
                }

                let bar = document.getElementById('recheck-bar');
                let text = document.getElementById('recheck-text');
                if (bar) bar.style.width = pct + '%';
                if (text) {
                    text.innerHTML = `Checked <strong>${checked}</strong> of <strong>${total}</strong> domains (${pct}%) — <strong>${matches}</strong> matches found`;
                }
            })
            .catch(() => {});
    }

    setInterval(updateStatus, 5000);
})();
</script>

<?php require __DIR__ . '/../templates/footer.php'; ?>
