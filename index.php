<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);
$message = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_message']);

// Toggle email notifications
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'toggle_email') {
    validateCsrf();
    $stmt = $db->prepare("UPDATE users SET email_notifications = NOT email_notifications WHERE id = ?");
    $stmt->execute([$userId]);
    header('Location: /');
    exit;
}

// Admin recheck
if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'recheck_keywords') {
    validateCsrf();
    $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)")
        ->execute(['recheck_keywords', '']);
    $_SESSION['flash_message'] = 'Keyword recheck queued. The worker will process it on its next poll.';
    header('Location: /');
    exit;
}

// Get current preference
$stmt = $db->prepare("SELECT email_notifications FROM users WHERE id = ? LIMIT 1");
$stmt->execute([$userId]);
$emailNotifications = (bool)$stmt->fetchColumn();

// Period filter for dashboard
$period = $_GET['period'] ?? '30d';
$validPeriods = ['24h' => '-1 day', '7d' => '-7 days', '30d' => '-30 days', 'all' => ''];
$periodSql = '';
$periodParams = [];
if (!empty($validPeriods[$period])) {
    $periodSql = " AND m.discovered_at >= datetime('now', ?)";
    $periodParams[] = $validPeriods[$period];
}

// Stats
$stmt = $db->prepare("SELECT COUNT(*) FROM keywords WHERE user_id = ?");
$stmt->execute([$userId]);
$keywordCount = (int)$stmt->fetchColumn();

$matchSql = "SELECT COUNT(*) FROM matches m JOIN keywords k ON m.keyword_id = k.id WHERE k.user_id = ?" . $periodSql;
$stmt = $db->prepare($matchSql);
$stmt->execute(array_merge([$userId], $periodParams));
$matchCount = (int)$stmt->fetchColumn();

$stmt = $db->prepare("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0");
$stmt->execute([$userId]);
$unreadCount = (int)$stmt->fetchColumn();

// Recent matches
$stmt = $db->prepare("SELECT m.id, m.domain, m.tld, m.discovered_at, m.first_seen, k.keyword 
    FROM matches m 
    JOIN keywords k ON m.keyword_id = k.id 
    WHERE k.user_id = ? $periodSql
    ORDER BY m.discovered_at DESC 
    LIMIT 20");
$stmt->execute(array_merge([$userId], $periodParams));
$recentMatches = $stmt->fetchAll();

$pageTitle = 'Dashboard';
require __DIR__ . '/templates/header.php';
?>

<?php if ($message): ?>
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<div class="stats">
    <div class="stat-box">
        <div class="number"><?= $keywordCount ?></div>
        <div class="label">Keywords</div>
    </div>
    <div class="stat-box">
        <div class="number"><?= $matchCount ?></div>
        <div class="label">Total Matches</div>
    </div>
    <div class="stat-box">
        <div class="number"><?= $unreadCount ?></div>
        <div class="label">Unread Notifications</div>
    </div>
</div>

<div class="card">
    <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 10px;">
        <h2>Recent Matches</h2>
        <form method="GET" style="display: flex; gap: 10px; align-items: center;">
            <select name="period" style="padding: 6px;">
                <option value="24h" <?= $period === '24h' ? 'selected' : '' ?>>Last 24h</option>
                <option value="7d" <?= $period === '7d' ? 'selected' : '' ?>>Last 7 days</option>
                <option value="30d" <?= $period === '30d' ? 'selected' : '' ?>>Last 30 days</option>
                <option value="all" <?= $period === 'all' ? 'selected' : '' ?>>All time</option>
            </select>
            <button type="submit" class="btn btn-small">Filter</button>
        </form>
    </div>
    <?php if (empty($recentMatches)): ?>
        <p>No matches in this period. Start by adding <a href="/keywords.php">keywords</a>.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr>
                    <th>Domain</th>
                    <th>TLD</th>
                    <th>Keyword</th>
                    <th>First Seen</th>
                    <th>Discovered</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($recentMatches as $m): ?>
                <tr>
                    <td><?= htmlspecialchars($m['domain']) ?></td>
                    <td><?= htmlspecialchars($m['tld']) ?></td>
                    <td><?= htmlspecialchars($m['keyword']) ?></td>
                    <td><?= htmlspecialchars($m['first_seen'] ?? '-') ?></td>
                    <td><?= htmlspecialchars($m['discovered_at']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<div class="card">
    <h2>Email Notifications</h2>
    <p>Status: <strong><?= $emailNotifications ? 'Enabled' : 'Disabled' ?></strong></p>
    <p style="color: #666; font-size: 0.9rem;">When enabled, you will receive an email summary each time new domains match your keywords.</p>
    <form method="POST" style="margin-top: 10px;">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="toggle_email">
        <button type="submit" class="btn btn-small <?= $emailNotifications ? 'btn-danger' : '' ?>"><?= $emailNotifications ? 'Disable' : 'Enable' ?></button>
    </form>
</div>

<?php if ($isAdmin): ?>
<div class="card">
    <h2>Admin — Keyword Recheck</h2>
    <?php
    $recheckStatus = $db->query("SELECT * FROM recheck_status WHERE id = 1")->fetch();
    $recheckRunning = !empty($recheckStatus['is_running']);
    $recheckTotal = (int)($recheckStatus['total_domains'] ?? 0);
    $recheckChecked = (int)($recheckStatus['checked_domains'] ?? 0);
    $recheckMatches = (int)($recheckStatus['matches_found'] ?? 0);
    $recheckPct = $recheckTotal > 0 ? round($recheckChecked / $recheckTotal * 100, 1) : 0;
    ?>
    <?php
    $pendingRecheck = $db->query("SELECT COUNT(*) FROM commands WHERE command = 'recheck_keywords' AND status = 'pending'")->fetchColumn();
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
        <?php if ((int)$pendingRecheck > 0 && !$recheckRunning): ?>
            <p style="color: #e67e22; font-size: 0.9rem;"><strong><?= (int)$pendingRecheck ?></strong> recheck command(s) queued — waiting for worker.</p>
        <?php endif; ?>
        <form method="POST" style="margin-top: 10px;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="recheck_keywords">
            <button type="submit" class="btn" <?= ($recheckRunning || (int)$pendingRecheck > 0) ? 'disabled' : '' ?>>
                <?= $recheckRunning ? 'Recheck in progress...' : ((int)$pendingRecheck > 0 ? 'Queued — waiting for worker' : 'Recheck All Cached Domains') ?>
            </button>
        </form>
        <p style="color: #666; font-size: 0.85rem; margin-top: 8px;">
            The worker must be running (daemon mode) for recheck to start immediately. Otherwise it will run on the next cron schedule.
        </p>
    </div>
</div>

<div class="card">
    <h2>Admin — Last Sync</h2>
    <?php
    $stmt = $db->query("SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT 5");
    $logs = $stmt->fetchAll();
    $workerStatus = $db->query("SELECT * FROM worker_status WHERE id = 1")->fetch();
    ?>
    <?php if ($workerStatus): ?>
    <div class="stats" style="margin-bottom: 15px;">
        <div class="stat-box">
            <div class="number"><?= (int)($workerStatus['tlds_processed'] ?? 0) ?></div>
            <div class="label">TLDs Processed</div>
        </div>
        <div class="stat-box">
            <div class="number"><?= (int)($workerStatus['domains_processed'] ?? 0) ?></div>
            <div class="label">Domains Processed</div>
        </div>
        <div class="stat-box">
            <div class="number"><?= (int)($workerStatus['matches_found'] ?? 0) ?></div>
            <div class="label">Matches Found</div>
        </div>
    </div>
    <?php endif; ?>
    <?php if (empty($logs)): ?>
        <p>No sync logs yet.</p>
    <?php else: ?>
        <table>
            <thead>
                <tr><th>Time</th><th>Received</th><th>Inserted</th><th>Error</th></tr>
            </thead>
            <tbody>
                <?php foreach ($logs as $log): ?>
                <tr>
                    <td><?= htmlspecialchars($log['created_at']) ?></td>
                    <td><?= (int)$log['records_received'] ?></td>
                    <td><?= (int)$log['records_inserted'] ?></td>
                    <td><?= htmlspecialchars($log['error'] ?? '-') ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
        <p style="margin-top: 10px;"><a href="/admin/" class="btn">Admin Panel</a></p>
    <?php endif; ?>
</div>
<?php endif; ?>

<?php if ($isAdmin): ?>
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
                        <form method="POST" style="margin-top: 10px;">
                            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token'] ?? '') ?>">
                            <input type="hidden" name="action" value="recheck_keywords">
                            <button type="submit" class="btn">Recheck All Cached Domains</button>
                        </form>
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
<?php endif; ?>

<?php require __DIR__ . '/templates/footer.php'; ?>
