<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

$db = Database::get();
$message = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_message']);

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
        $_SESSION['flash_message'] = 'Worker execution queued. It will run on next poll.';
        header('Location: /admin/');
        exit;
    }
    
    if ($action === 'recheck_keywords') {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['recheck_keywords', '']);
        $_SESSION['flash_message'] = 'Keyword recheck queued. The worker will scan all cached domains against current keywords.';
        header('Location: /admin/');
        exit;
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
    
    if ($action === 'cancel_command') {
        $cmdId = (int)($_POST['command_id'] ?? 0);
        $db->prepare("UPDATE commands SET status = 'cancelled', executed_at = datetime('now') WHERE id = ? AND status = 'pending'") ->execute([$cmdId]);
        $message = 'Command cancelled.';
    }
    
    if ($action === 'clear_pending_commands') {
        $db->prepare("UPDATE commands SET status = 'cancelled', executed_at = datetime('now') WHERE status = 'pending'") ->execute();
        $message = 'All pending commands cleared.';
    }
    
    if ($action === 'save_tlds') {
        validateCsrf();
        $active = $_POST['active'] ?? [];
        $db->beginTransaction();
        $db->exec("UPDATE tlds SET is_active = 0");
        $stmt = $db->prepare("UPDATE tlds SET is_active = 1 WHERE name = ?");
        foreach ($active as $tld) {
            $stmt->execute([$tld]);
        }
        $db->commit();
        $message = 'TLD selection saved. The worker will use these on next run.';
    }
}

// Data
$tlds = $db->query("SELECT id, name, is_active, last_sync, status FROM tlds ORDER BY name")->fetchAll();
$users = $db->query("SELECT id, username, email, is_active, is_admin, api_key, max_keywords, created_at FROM users ORDER BY created_at DESC")->fetchAll();
$syncLogs = $db->query("SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT 20")->fetchAll();
$workerStatus = $db->query("SELECT * FROM worker_status WHERE id = 1")->fetch();
$workerLogs = $db->query("SELECT * FROM worker_logs ORDER BY created_at DESC LIMIT 20")->fetchAll();
$pendingCommands = $db->query("SELECT COUNT(*) FROM commands WHERE status = 'pending'")->fetchColumn();
$pendingCommandsList = $db->query("SELECT id, command, payload, created_at FROM commands WHERE status = 'pending' ORDER BY created_at ASC")->fetchAll();

$pageTitle = 'Admin Panel';
require __DIR__ . '/../templates/header.php';
?>

<?php if ($message): ?>
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<style>
.admin-tabs { display: flex; gap: 4px; margin-bottom: 20px; border-bottom: 2px solid #e0e0e0; padding-bottom: 0; }
.admin-tabs .tab-btn { background: #f5f5f5; border: none; padding: 10px 20px; cursor: pointer; border-radius: 4px 4px 0 0; font-size: 0.95rem; color: #555; transition: background 0.2s; }
.admin-tabs .tab-btn:hover { background: #e8e8e8; }
.admin-tabs .tab-btn.active { background: #3498db; color: white; font-weight: 600; }
.tab-content { display: none; }
.tab-content.active { display: block; }
#tld-search { width: 100%; padding: 10px 14px; font-size: 1rem; border: 1px solid #ddd; border-radius: 4px; margin-bottom: 15px; box-sizing: border-box; }
#tld-search:focus { outline: none; border-color: #3498db; }
.tld-table-container { max-height: 600px; overflow-y: auto; border: 1px solid #e0e0e0; border-radius: 4px; }
.tld-row.hidden { display: none; }
#tld-count { font-size: 0.9rem; color: #666; margin-bottom: 10px; }
</style>

<div class="admin-tabs">
    <button type="button" class="tab-btn active" onclick="showTab('dashboard', this)">Dashboard</button>
    <button type="button" class="tab-btn" onclick="showTab('tlds', this)">Manage TLDs (<?= count($tlds) ?>)</button>
</div>

<div id="tab-dashboard" class="tab-content active">

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

<?php
// Worker health calculation
$heartbeatStale = false;
$secondsSinceHb = null;
if (!empty($workerStatus['last_heartbeat'])) {
    $hbTime = strtotime($workerStatus['last_heartbeat']);
    if ($hbTime) {
        $secondsSinceHb = time() - $hbTime;
        $heartbeatStale = $secondsSinceHb > 300; // 5 minutes
    }
}
?>
<div class="card" id="live-worker-card" style="display: <?= (($workerStatus['is_running'] ?? 0) && ($workerStatus['total_tlds'] ?? 0) > 0) ? 'block' : 'none' ?>">
    <h2>Live Worker Progress</h2>
    <div id="live-worker-container">
        <?php
        $lwTotal = (int)($workerStatus['total_tlds'] ?? 0);
        $lwDone = (int)($workerStatus['tlds_processed'] ?? 0);
        $lwPct = $lwTotal > 0 ? round($lwDone / $lwTotal * 100, 1) : 0;
        ?>
        <p><strong>Action:</strong> <span id="live-action"><?= htmlspecialchars($workerStatus['current_action'] ?? '—') ?></span></p>
        <p><strong>Current TLD:</strong> <span id="live-tld"><?= htmlspecialchars($workerStatus['current_tld'] ?? '—') ?></span></p>
        <div style="background: #f0f0f0; border-radius: 4px; height: 24px; margin: 10px 0; overflow: hidden;">
            <div id="live-bar" style="background: #3498db; width: <?= $lwPct ?>%; height: 100%; transition: width 0.5s;"></div>
        </div>
        <p id="live-text">
            Processed <strong id="live-done"><?= number_format($lwDone) ?></strong> of <strong id="live-total"><?= number_format($lwTotal) ?></strong> TLDs
            (<?= $lwPct ?>%) — <strong id="live-domains"><?= number_format((int)($workerStatus['domains_processed'] ?? 0)) ?></strong> domains
        </p>
    </div>
</div>

<div class="card">
    <h2>Worker Status</h2>
    <?php if ($workerStatus): ?>
        <?php if (($workerStatus['is_running'] ?? 0)): ?>
            <div style="margin-bottom: 12px; padding: 10px 14px; background: #fff3cd; border-radius: 4px; font-size: 0.9rem; color: #856404;">
                🔧 <strong>Worker is busy.</strong> It is currently processing a command (downloading zones or rechecking keywords). New commands will execute once it finishes and returns to the polling loop. This may take several minutes or even hours depending on the workload.
            </div>
        <?php elseif ($heartbeatStale): ?>
            <div style="margin-bottom: 12px; padding: 10px 14px; background: #f8d7da; border-radius: 4px; font-size: 0.9rem; color: #721c24;">
                ⚠️ <strong>Worker heartbeat is stale.</strong> Last seen <?= $secondsSinceHb !== null ? floor($secondsSinceHb / 60) . ' min ago' : 'a while ago' ?>. The worker may have crashed or lost connectivity. Check the LXC and run <code>systemctl status tdl-worker</code>.
            </div>
        <?php else: ?>
            <div style="margin-bottom: 12px; padding: 10px 14px; background: #d4edda; border-radius: 4px; font-size: 0.9rem; color: #155724;">
                ✅ <strong>Worker is online.</strong> Polling normally. Last heartbeat <?= $secondsSinceHb !== null ? floor($secondsSinceHb / 60) . ' min ago' : 'recently' ?>.
            </div>
        <?php endif; ?>

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
        <a href="/admin/cleanup.php" class="btn btn-danger">Cleanup False Matches</a>
        <a href="/admin/update.php" class="btn">Check for Updates</a>
    </div>
</div>

<div class="card">
    <h2>Pending Commands</h2>
    <?php if (empty($pendingCommandsList)): ?>
        <p style="color: #666;">No pending commands. The queue is clear.</p>
    <?php else: ?>
        <form method="POST" style="margin-bottom: 12px;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="clear_pending_commands">
            <button type="submit" class="btn btn-danger btn-small" onclick="return confirm('Cancel ALL <?= count($pendingCommandsList) ?> pending command(s)? This cannot be undone.')">Clear All Pending</button>
        </form>
        <table>
            <thead>
                <tr><th>ID</th><th>Command</th><th>Payload</th><th>Queued At</th><th>In Queue</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <?php foreach ($pendingCommandsList as $cmd):
                    $queuedSeconds = time() - strtotime($cmd['created_at']);
                    $queuedMins = floor($queuedSeconds / 60);
                    $queuedStr = $queuedMins < 1 ? 'Just now' : ($queuedMins < 60 ? $queuedMins . ' min' : floor($queuedMins / 60) . ' h ' . ($queuedMins % 60) . ' min');
                ?>
                <tr>
                    <td><?= (int)$cmd['id'] ?></td>
                    <td><?= htmlspecialchars($cmd['command']) ?></td>
                    <td><?= htmlspecialchars($cmd['payload'] ?? '—') ?></td>
                    <td><?= htmlspecialchars($cmd['created_at']) ?></td>
                    <td><?= $queuedStr ?></td>
                    <td>
                        <form method="POST" style="display: inline; margin: 0;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="cancel_command">
                            <input type="hidden" name="command_id" value="<?= (int)$cmd['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger" onclick="return confirm('Cancel command #<?= (int)$cmd['id'] ?>?')">Cancel</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
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

// Live Worker Progress polling
(function() {
    const card = document.getElementById('live-worker-card');
    if (!card) return;

    function updateLiveWorker() {
        fetch('/api/v1/worker_status.php')
            .then(r => r.json())
            .then(data => {
                if (!data.success || !data.status) return;
                const s = data.status;
                const running = s.is_running == 1;
                const total = parseInt(s.total_tlds || 0);

                if (!running || total === 0) {
                    card.style.display = 'none';
                    return;
                }

                card.style.display = 'block';
                const done = parseInt(s.tlds_processed || 0);
                const domains = parseInt(s.domains_processed || 0);
                const pct = total > 0 ? Math.round(done / total * 100) : 0;

                document.getElementById('live-action').textContent = s.current_action || '—';
                document.getElementById('live-tld').textContent = s.current_tld || '—';
                document.getElementById('live-bar').style.width = pct + '%';
                document.getElementById('live-done').textContent = done.toLocaleString();
                document.getElementById('live-total').textContent = total.toLocaleString();
                document.getElementById('live-domains').textContent = domains.toLocaleString();
            })
            .catch(() => {});
    }

    setInterval(updateLiveWorker, 5000);
})();
</script>

</div><!-- /tab-dashboard -->

<div id="tab-tlds" class="tab-content">
    <div class="card">
        <h2>Approved TLDs (<?= count($tlds) ?>)</h2>
        <p>Check the TLDs you want the worker to monitor. Unchecked TLDs will be ignored.</p>
        
        <?php if (empty($tlds)): ?>
        <div class="alert alert-error">
            No TLDs found. The worker must run at least once to populate this list from ICANN CZDS.
            <br>Click <strong>Run Worker Now</strong> in the Dashboard tab to populate the list.
        </div>
        <?php else: ?>
        <input type="text" id="tld-search" placeholder="Search TLDs..." onkeyup="filterTlds()">
        <form method="POST">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="save_tlds">
            <div style="margin-bottom: 12px; display: flex; gap: 8px; flex-wrap: wrap; align-items: center;">
                <button type="button" class="btn btn-small" onclick="selectAllTlds(true)">Select All</button>
                <button type="button" class="btn btn-small" onclick="selectAllTlds(false)">Deselect All</button>
                <button type="submit" class="btn">Save Selection</button>
                <span id="tld-count"></span>
            </div>
            
            <div class="tld-table-container">
                <table style="margin: 0;">
                    <thead style="position: sticky; top: 0; background: white; z-index: 1;">
                        <tr>
                            <th style="width: 40px;">Active</th>
                            <th>TLD</th>
                            <th>Last Sync</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody id="tld-tbody">
                        <?php foreach ($tlds as $t): ?>
                        <tr class="tld-row" data-name="<?= htmlspecialchars($t['name']) ?>">
                            <td style="text-align: center;">
                                <input type="checkbox" name="active[]" value="<?= htmlspecialchars($t['name']) ?>" <?= $t['is_active'] ? 'checked' : '' ?> onchange="updateTldCount()">
                            </td>
                            <td><?= htmlspecialchars($t['name']) ?></td>
                            <td><?= htmlspecialchars($t['last_sync'] ?? '-') ?></td>
                            <td><?= htmlspecialchars($t['status'] ?? '-') ?></td>
                        </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>
            
            <div style="margin-top: 15px;">
                <button type="submit" class="btn">Save Selection</button>
            </div>
        </form>
        <?php endif; ?>
    </div>
</div><!-- /tab-tlds -->

<script>
function showTab(tabId, btn) {
    document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
    document.querySelectorAll('.admin-tabs .tab-btn').forEach(el => el.classList.remove('active'));
    document.getElementById('tab-' + tabId).classList.add('active');
    if (btn) btn.classList.add('active');
    if (tabId === 'tlds') updateTldCount();
}

function filterTlds() {
    const query = document.getElementById('tld-search').value.toLowerCase().trim();
    document.querySelectorAll('.tld-row').forEach(row => {
        const name = row.dataset.name.toLowerCase();
        row.classList.toggle('hidden', query && !name.includes(query));
    });
    updateTldCount();
}

function selectAllTlds(checked) {
    document.querySelectorAll('.tld-row:not(.hidden) input[name="active[]"]').forEach(cb => cb.checked = checked);
    updateTldCount();
}

function updateTldCount() {
    const visible = document.querySelectorAll('.tld-row:not(.hidden)').length;
    const checked = document.querySelectorAll('.tld-row:not(.hidden) input[name="active[]"]:checked').length;
    document.getElementById('tld-count').textContent = checked + ' of ' + visible + ' visible TLDs selected';
}

// Auto-activate TLDs tab if URL hash is #tlds
if (window.location.hash === '#tlds') {
    const tldsBtn = document.querySelector('.admin-tabs .tab-btn:nth-child(2)');
    showTab('tlds', tldsBtn);
}
</script>

<?php require __DIR__ . '/../templates/footer.php'; ?>
