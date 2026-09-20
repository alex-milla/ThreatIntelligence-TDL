<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

$db = Database::get();
$message = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_message']);

function commandStatusBadge(string $status): string {
    $map = [
        'pending'   => 'Pending',
        'running'   => 'Running',
        'completed' => 'Completed',
        'failed'    => 'Failed',
        'cancelled' => 'Cancelled',
    ];
    $known = isset($map[$status]);
    $cls = $known ? $status : 'cancelled';
    $label = $known ? $map[$status] : htmlspecialchars($status);
    return '<span class="status-badge status-' . $cls . '">' . $label . '</span>';
}

function humanDuration(?string $from, ?string $to): string {
    if (!$from || !$to) {
        return '&mdash;';
    }
    $seconds = strtotime($to) - strtotime($from);
    if ($seconds < 0) {
        return '&mdash;';
    }
    if ($seconds < 60) {
        return $seconds . 's';
    }
    $mins = floor($seconds / 60);
    if ($mins < 60) {
        return $mins . 'm ' . ($seconds % 60) . 's';
    }
    return floor($mins / 60) . 'h ' . ($mins % 60) . 'm';
}

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
        if (hasPendingCommand($db, 'run_worker')) {
            $_SESSION['flash_message'] = 'A worker run is already queued. Wait for it to finish before queuing another.';
        } else {
            $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['run_worker', '']);
            $_SESSION['flash_message'] = 'Worker execution queued. It will run on next poll.';
        }
        header('Location: /admin/');
        exit;
    }
    
    if ($action === 'recheck_keywords') {
        if (hasPendingCommand($db, 'recheck_keywords')) {
            $_SESSION['flash_message'] = 'A keyword recheck is already queued.';
        } else {
            if (!empty($_POST['recheck_form'])) {
                $sources = [];
                if (!empty($_POST['source_openintel'])) $sources[] = 'openintel';
                if (!empty($_POST['source_czds'])) $sources[] = 'czds';
                if (!$sources) $sources[] = 'openintel';
                $tlds = is_array($_POST['tlds'] ?? null)
                    ? array_values(array_filter(array_map('strval', $_POST['tlds'])))
                    : [];
                $keywordIds = is_array($_POST['keyword_ids'] ?? null)
                    ? array_values(array_filter(array_map('intval', $_POST['keyword_ids']), fn($v) => $v > 0))
                    : [];
                $payloadData = [
                    'sources' => $sources,
                    'tlds' => $tlds,
                    'max_age_days' => max(0, (int)($_POST['max_age_days'] ?? 30)),
                    'max_domains' => max(0, (int)($_POST['max_domains'] ?? 0)),
                ];
                if ($keywordIds) {
                    $payloadData['keyword_ids'] = $keywordIds;
                }
                $payload = json_encode($payloadData);
            } else {
                // Quick action: the worker defaults to the fast ccTLD cache only.
                $payload = '';
            }
            $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)")->execute(['recheck_keywords', $payload]);
            $_SESSION['flash_message'] = 'Keyword recheck queued.';
        }
        header('Location: /admin/#recheck');
        exit;
    }

    if ($action === 'stop_recheck') {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['stop_recheck', '']);
        $_SESSION['flash_message'] = 'Stop recheck queued. The worker will stop at the next batch boundary.';
        header('Location: /admin/');
        exit;
    }

    if ($action === 'update_worker') {
        if (hasPendingCommand($db, 'update_worker')) {
            $_SESSION['flash_message'] = 'A worker update is already queued.';
        } else {
            $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['update_worker', '']);
            $_SESSION['flash_message'] = 'Worker update queued. It will pull the latest code and restart itself.';
        }
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
        $max = (int)($_POST['max_keywords'] ?? DEFAULT_MAX_KEYWORDS);
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

    if ($action === 'archive_historical') {
        $db->exec("UPDATE matches SET is_historical = 1 WHERE is_historical = 0");
        $message = 'Existing matches archived. They are hidden from the "new" listings until restored.';
    }

    if ($action === 'unarchive_historical') {
        $db->exec("UPDATE matches SET is_historical = 0 WHERE is_historical = 1");
        $message = 'Archived matches restored to the "new" listings.';
    }
    
    if ($action === 'cancel_command') {
        $cmdId = (int)($_POST['command_id'] ?? 0);
        $db->prepare(
            "UPDATE commands SET status = 'cancelled', "
            . "executed_at = COALESCE(executed_at, datetime('now')), finished_at = datetime('now') "
            . "WHERE id = ? AND status IN ('pending', 'running')"
        )->execute([$cmdId]);
        $message = 'Command cancelled.';
    }
    
    if ($action === 'clear_pending_commands') {
        $db->prepare("UPDATE commands SET status = 'cancelled', executed_at = datetime('now') WHERE status = 'pending'") ->execute();
        $message = 'All pending commands cleared.';
    }
    
}

// Data
$users = $db->query("SELECT id, username, email, is_active, is_admin, api_key, max_keywords, created_at FROM users ORDER BY created_at DESC")->fetchAll();
$syncLogs = $db->query("SELECT * FROM sync_logs ORDER BY created_at DESC LIMIT 20")->fetchAll();
$workerStatus = $db->query("SELECT * FROM worker_status WHERE id = 1")->fetch();
$workerLogs = $db->query("SELECT * FROM worker_logs ORDER BY created_at DESC LIMIT 20")->fetchAll();
$historicalMatchCount = (int)$db->query("SELECT COUNT(*) FROM matches WHERE is_historical = 1")->fetchColumn();
$pendingCommands = $db->query("SELECT COUNT(*) FROM commands WHERE status = 'pending'")->fetchColumn();
$pendingCommandsList = $db->query("SELECT id, command, payload, created_at FROM commands WHERE status = 'pending' ORDER BY created_at ASC")->fetchAll();
$recentCommands = $db->query("SELECT id, command, payload, status, result, created_at, executed_at, finished_at FROM commands ORDER BY id DESC LIMIT 20")->fetchAll();
$versionMismatch = workerVersionMismatch($db);
$activity = getWorkerActivity($db);
$recheckCzdsTlds = $db->query("SELECT name, records_total FROM tlds WHERE source = 'czds' AND is_active = 1 ORDER BY name")->fetchAll();
$recheckCcTlds = $db->query("SELECT name, records_total FROM tlds WHERE source = 'openintel' AND is_active = 1 ORDER BY name")->fetchAll();
$recheckKeywords = $db->query("SELECT k.id, k.keyword, u.username FROM keywords k JOIN users u ON u.id = k.user_id WHERE k.is_active = 1 ORDER BY k.keyword ASC, u.username ASC")->fetchAll();

$pageTitle = 'Admin Panel';
require __DIR__ . '/../templates/header.php';
?>

<?php if ($message): ?>
<div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<?php if ($versionMismatch): ?>
<div class="alert alert-error">
    <i class="material-icons left">warning</i>
    <strong>Worker out of date.</strong>
    The web app is <strong>v<?= htmlspecialchars($versionMismatch['app']) ?></strong> but the worker is running
    <strong>v<?= htmlspecialchars($versionMismatch['worker']) ?></strong>.
    Queue an update below (or run <code>bash worker/update.sh --restart</code> on the worker host).
    <form method="POST" style="display: inline; margin-left: 8px;">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="update_worker">
        <button type="submit" class="btn btn-small waves-effect">Update Worker Now</button>
    </form>
</div>
<?php endif; ?>

<span id="activity-watcher" hidden
      data-url="/ajax_worker_activity.php"
      data-interval="5000"
      data-refresh-interval="5000"
      data-active="<?= $activity['active'] ? '1' : '0' ?>"
      data-version="<?= htmlspecialchars($activity['worker_version']) ?>"></span>

<div class="card <?= (($workerStatus['is_running'] ?? 0) && ($workerStatus['total_tlds'] ?? 0) > 0) ? '' : 'is-hidden' ?>" id="live-worker-card" data-live-section data-live-class>
    <div class="card-head">
        <h2><i class="material-icons left">memory</i>Live Worker Progress</h2>
    </div>
    <div id="live-worker-container">
        <?php
        $lwTotal = (int)($workerStatus['total_tlds'] ?? 0);
        $lwDone = (int)($workerStatus['tlds_processed'] ?? 0);
        $lwPct = $lwTotal > 0 ? round($lwDone / $lwTotal * 100, 1) : 0;
        ?>
        <p><strong>Command:</strong> <span id="live-command"><?= htmlspecialchars($workerStatus['current_command'] ?? '—') ?></span></p>
        <p><strong>Action:</strong> <span id="live-action"><?= htmlspecialchars($workerStatus['current_action'] ?? '—') ?></span></p>
        <p><strong>Current TLD:</strong> <span id="live-tld"><?= htmlspecialchars($workerStatus['current_tld'] ?? '—') ?></span></p>
        <div class="progress">
            <div id="live-bar" class="determinate" style="width: <?= $lwPct ?>%;"></div>
        </div>
        <p id="live-text">
            Processed <strong id="live-done"><?= number_format($lwDone) ?></strong> of <strong id="live-total"><?= number_format($lwTotal) ?></strong> TLDs
            (<?= $lwPct ?>%) — <strong id="live-domains"><?= number_format((int)($workerStatus['domains_processed'] ?? 0)) ?></strong> domains
        </p>
    </div>
</div>

<nav class="admin-tabs" id="admin-tabs">
    <a href="#overview" data-tab="overview" class="active">Overview</a>
    <a href="#worker" data-tab="worker">Worker</a>
    <a href="#commands" data-tab="commands">Commands</a>
    <a href="#recheck" data-tab="recheck">Recheck</a>
    <a href="/admin/tlds.php" data-tab="tlds">TLDs</a>
    <a href="#users" data-tab="users">Users</a>
    <a href="#sync" data-tab="sync">Sync</a>
    <a href="#system" data-tab="system">System</a>
</nav>

<div class="card admin-pane active" data-tab="overview">
    <div class="card-head"><h2>Quick actions</h2></div>
    <p class="muted">Queue a command for the worker. It runs on the next poll (every ~20 s).</p>
    <div class="section-actions">
        <form method="POST">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="run_worker">
            <button type="submit" class="btn waves-effect"><i class="material-icons left">play_arrow</i>Run Worker Now</button>
        </form>
        <form method="POST">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="recheck_keywords">
            <button type="submit" class="btn btn-outline waves-effect"><i class="material-icons left">search</i>Recheck Keywords</button>
        </form>
        <form method="POST">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="update_worker">
            <button type="submit" class="btn waves-effect" onclick="return confirm('Update the worker on its host (git pull + restart)? The web app is not affected.')"><i class="material-icons left">system_update</i>Update Worker</button>
        </form>
    </div>
</div>

<div class="card admin-pane" data-tab="tlds">
    <div class="card-head"><h2>TLDs</h2></div>
    <p class="muted">Manage the list of approved TLDs the worker will download and process.</p>
    <p><a href="/admin/tlds.php" class="btn waves-effect"><i class="material-icons left">public</i>Open TLD management</a></p>
</div>

<div class="card admin-pane" data-tab="recheck">
    <div class="card-head"><h2>Keyword Recheck Status</h2></div>
    <?php
    $recheckStatus = $db->query("SELECT * FROM recheck_status WHERE id = 1")->fetch();
    $recheckRunning = !empty($recheckStatus['is_running']);
    $recheckTotal = (int)($recheckStatus['total_domains'] ?? 0);
    $recheckChecked = (int)($recheckStatus['checked_domains'] ?? 0);
    $recheckMatches = (int)($recheckStatus['matches_found'] ?? 0);
    $recheckPct = $recheckTotal > 0 ? round($recheckChecked / $recheckTotal * 100, 1) : 0;
    ?>
    <div id="recheck-status" data-live-section>
        <?php if ($recheckRunning): ?>
            <p><strong>Status:</strong> <span class="status-badge status-running">Running</span></p>
            <div class="progress">
                <div id="recheck-bar" class="determinate" style="width: <?= $recheckPct ?>%;"></div>
            </div>
            <p id="recheck-text">
                Checked <strong><?= number_format($recheckChecked) ?></strong> of <strong><?= number_format($recheckTotal) ?></strong> domains
                (<?= $recheckPct ?>%) — <strong><?= number_format($recheckMatches) ?></strong> matches found
            </p>
        <?php elseif ($recheckStatus && $recheckStatus['completed_at'] && $recheckTotal == 0): ?>
            <p><strong>Status:</strong> <span class="status-badge status-failed">No cached domains</span></p>
            <p class="text-danger">The worker has not downloaded any zones yet. Run the worker first to build the domain cache.</p>
        <?php elseif ($recheckStatus && $recheckStatus['completed_at']): ?>
            <p><strong>Status:</strong> <span class="status-badge status-completed">Completed</span> at <?= htmlspecialchars(fmt_date($recheckStatus['completed_at'])) ?></p>
            <p>Checked <strong><?= number_format($recheckChecked) ?></strong> domains — <strong><?= number_format($recheckMatches) ?></strong> matches found</p>
        <?php else: ?>
            <p><strong>Status:</strong> <span class="status-badge status-cancelled">Idle</span></p>
        <?php endif; ?>
        <?php
        $pendingRecheck = $db->query("SELECT COUNT(*) FROM commands WHERE command = 'recheck_keywords' AND status = 'pending'")->fetchColumn();
        $recheckSource = (string)($recheckStatus['source'] ?? '');
        if ((int)$pendingRecheck > 0 && !$recheckRunning): ?>
            <p class="text-success"><strong><?= (int)$pendingRecheck ?></strong> recheck command(s) queued — waiting for worker.</p>
        <?php endif; ?>
        <?php if ($recheckSource !== ''): ?>
            <p class="muted">Source: <strong><?= htmlspecialchars($recheckSource) ?></strong></p>
        <?php endif; ?>
    </div>

        <?php if ($recheckRunning): ?>
        <form method="POST" style="margin-bottom:8px;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="stop_recheck">
            <button type="submit" class="btn btn-danger waves-effect"><i class="material-icons left">stop</i>Stop Recheck</button>
        </form>
        <?php endif; ?>

        <form method="POST" id="recheck-form" style="margin-top:12px;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="recheck_keywords">
            <input type="hidden" name="recheck_form" value="1">
            <div class="section-actions" style="gap:18px;">
                <label class="check-inline">
                    <input type="checkbox" name="source_openintel" value="1" checked onchange="recheckEstimate()">
                    <span>ccTLD cache (OpenINTEL)</span>
                </label>
                <label class="check-inline">
                    <input type="checkbox" name="source_czds" value="1" onchange="recheckEstimate()">
                    <span>ICANN cache (CZDS)</span>
                </label>
            </div>
            <div class="input-field">
                <label for="recheck-tlds" style="position:static;">TLDs to recheck (optional; empty = all configured)</label>
                <select name="tlds[]" id="recheck-tlds" class="browser-default" multiple size="8" style="height:auto;" onchange="recheckEstimate()">
                    <?php if ($recheckCcTlds): ?>
                    <optgroup label="ccTLD (OpenINTEL)">
                        <?php foreach ($recheckCcTlds as $t): ?>
                        <option value="<?= htmlspecialchars($t['name']) ?>" data-origin="openintel" data-total="<?= (int)$t['records_total'] ?>"><?= htmlspecialchars($t['name']) ?> (<?= number_format((int)$t['records_total']) ?> cached)</option>
                        <?php endforeach; ?>
                    </optgroup>
                    <?php endif; ?>
                    <?php if ($recheckCzdsTlds): ?>
                    <optgroup label="ICANN (CZDS)">
                        <?php foreach ($recheckCzdsTlds as $t): ?>
                        <option value="<?= htmlspecialchars($t['name']) ?>" data-origin="czds" data-total="<?= (int)$t['records_total'] ?>"><?= htmlspecialchars($t['name']) ?> (<?= number_format((int)$t['records_total']) ?> cached)</option>
                        <?php endforeach; ?>
                    </optgroup>
                    <?php endif; ?>
                </select>
                <span class="helper-text">Leave TLDs empty to recheck the whole ccTLD cache. For ICANN, select TLDs, set a max-domains cap, or set a max age (bounded by time).</span>
            </div>
            <?php if ($recheckKeywords): ?>
            <div class="input-field">
                <label for="recheck-keywords" style="position:static;">Keywords to recheck (optional; empty = all keywords)</label>
                <select name="keyword_ids[]" id="recheck-keywords" class="browser-default" multiple size="6" style="height:auto;">
                    <?php foreach ($recheckKeywords as $kw): ?>
                    <option value="<?= (int)$kw['id'] ?>"><?= htmlspecialchars($kw['keyword']) ?> — <?= htmlspecialchars($kw['username']) ?></option>
                    <?php endforeach; ?>
                </select>
                <span class="helper-text">Only the selected keywords are matched during this recheck.</span>
            </div>
            <?php endif; ?>
            <div class="section-actions">
                <label class="nowrap">Max age (days) <input type="number" name="max_age_days" value="30" min="0" max="3650" class="browser-default compact num-input"></label>
                <label class="nowrap">Max domains <input type="number" name="max_domains" value="0" min="0" class="browser-default compact num-input" title="0 = no cap"></label>
                <span id="recheck-estimate" class="muted"></span>
                <button type="submit" class="btn waves-effect" <?= ($recheckRunning || (int)$pendingRecheck > 0) ? 'disabled' : '' ?>>
                    <i class="material-icons left">search</i><?= $recheckRunning ? 'Recheck in progress...' : ((int)$pendingRecheck > 0 ? 'Queued — waiting for worker' : 'Recheck selected') ?>
                </button>
            </div>
        </form>
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

<div class="card admin-pane" data-tab="worker" id="live-worker-status" data-live-section>
    <div class="card-head"><h2>Worker Status</h2></div>
    <?php if ($workerStatus): ?>
        <?php if (($workerStatus['is_running'] ?? 0)): ?>
            <div class="notice notice-warning">
                <i class="material-icons">build</i>
                <div><strong>Worker is busy.</strong> It is currently processing a command (downloading zones or rechecking keywords). New commands will execute once it finishes and returns to the polling loop. This may take several minutes or even hours depending on the workload.</div>
            </div>
        <?php elseif ($heartbeatStale): ?>
            <div class="notice notice-error">
                <i class="material-icons">error</i>
                <div><strong>Worker heartbeat is stale.</strong> Last seen <?= $secondsSinceHb !== null ? floor($secondsSinceHb / 60) . ' min ago' : 'a while ago' ?>. The worker may have crashed or lost connectivity. Check the LXC and run <code>systemctl status tdl-worker</code>.</div>
            </div>
        <?php else: ?>
            <div class="notice notice-success">
                <i class="material-icons">check_circle</i>
                <div><strong>Worker is online.</strong> Polling normally. Last heartbeat <?= $secondsSinceHb !== null ? floor($secondsSinceHb / 60) . ' min ago' : 'recently' ?>.</div>
            </div>
        <?php endif; ?>

        <table class="striped highlight">
            <tr><td>Last Heartbeat</td><td><?= htmlspecialchars(fmt_date($workerStatus['last_heartbeat'])) ?></td></tr>
            <tr><td>Last Run</td><td><?= htmlspecialchars(fmt_date($workerStatus['last_run'])) ?></td></tr>
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
</div>

<div class="card admin-pane" data-tab="commands" id="live-recent-commands" data-live-section>
    <div class="card-head"><h2>Recent Commands</h2></div>
    <?php if (empty($recentCommands)): ?>
        <p class="muted">No commands have been queued yet.</p>
    <?php else: ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr><th>ID</th><th>Command</th><th>Status</th><th>Queued</th><th>Started</th><th>Duration</th><th>Result</th><th>Actions</th></tr>
            </thead>
            <tbody>
                <?php foreach ($recentCommands as $cmd): ?>
                <tr>
                    <td><?= (int)$cmd['id'] ?></td>
                    <td><?= htmlspecialchars($cmd['command']) ?></td>
                    <td><?= commandStatusBadge((string)$cmd['status']) ?></td>
                    <td><?= htmlspecialchars(fmt_date($cmd['created_at'])) ?></td>
                    <td><?= htmlspecialchars(fmt_date($cmd['executed_at'])) ?></td>
                    <td><?= humanDuration($cmd['executed_at'], $cmd['finished_at']) ?></td>
                    <td style="font-size:0.82rem; max-width:340px; word-break:break-word;"><?= htmlspecialchars(mb_substr((string)($cmd['result'] ?? ''), 0, 300)) ?></td>
                    <td>
                        <?php if (in_array($cmd['status'], ['pending', 'running'], true)): ?>
                        <form method="POST" style="display:inline; margin:0;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="cancel_command">
                            <input type="hidden" name="command_id" value="<?= (int)$cmd['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger waves-effect"
                                    title="<?= $cmd['status'] === 'running' ? 'Only if the worker is stuck; a live run may overwrite this.' : '' ?>"
                                    onclick="return confirm('Cancel command #<?= (int)$cmd['id'] ?>?')"><i class="material-icons left">cancel</i>Cancel</button>
                        </form>
                        <?php else: ?>
                        <span class="muted">&mdash;</span>
                        <?php endif; ?>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<div class="card admin-pane" data-tab="commands" id="live-pending-commands" data-live-section>
    <div class="card-head"><h2>Pending Commands</h2></div>
    <?php if (empty($pendingCommandsList)): ?>
        <p class="muted">No pending commands. The queue is clear.</p>
    <?php else: ?>
        <form method="POST" class="section-actions">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="clear_pending_commands">
            <button type="submit" class="btn btn-danger btn-small waves-effect" onclick="return confirm('Cancel ALL <?= count($pendingCommandsList) ?> pending command(s)? This cannot be undone.')"><i class="material-icons left">delete_sweep</i>Clear All Pending</button>
        </form>
        <table class="striped highlight responsive-table">
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
                    <td><?= htmlspecialchars(fmt_date($cmd['created_at'])) ?></td>
                    <td><?= $queuedStr ?></td>
                    <td>
                        <form method="POST" style="display: inline; margin: 0;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="cancel_command">
                            <input type="hidden" name="command_id" value="<?= (int)$cmd['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger waves-effect" onclick="return confirm('Cancel command #<?= (int)$cmd['id'] ?>?')"><i class="material-icons left">cancel</i>Cancel</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<div class="card admin-pane" data-tab="worker" id="live-worker-logs" data-live-section>
    <div class="card-head"><h2>Worker Logs</h2></div>
    <?php if (empty($workerLogs)): ?>
        <p class="muted">No worker logs yet.</p>
    <?php else: ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr><th>Time</th><th>Level</th><th>Message</th></tr>
            </thead>
            <tbody>
                <?php foreach ($workerLogs as $log): ?>
                <tr>
                    <td><?= htmlspecialchars(fmt_date($log['created_at'])) ?></td>
                    <td><?= htmlspecialchars($log['level']) ?></td>
                    <td><?= htmlspecialchars($log['message']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<div class="card admin-pane" data-tab="users">
    <div class="card-head"><h2>Users</h2></div>
    <table class="striped highlight responsive-table">
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
                <td><?= $u['is_active'] ? '<span class="text-success">Yes</span>' : '<span class="muted">No</span>' ?></td>
                <td><?= $u['is_admin'] ? '<span class="text-success">Yes</span>' : '<span class="muted">No</span>' ?></td>
                <td>
                    <?php if ($u['is_admin']): ?>
                        <span class="text-success" title="Admins are always unlimited">Unlimited</span>
                    <?php else: ?>
                    <form method="POST" class="inline-form-nowrap">
                        <?php csrfField(); ?>
                        <input type="hidden" name="action" value="set_max_keywords">
                        <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                        <input type="number" name="max_keywords" value="<?= (int)$u['max_keywords'] ?>" min="0" class="browser-default compact num-input">
                        <button type="submit" class="btn btn-small waves-effect" title="0 = unlimited">Set</button>
                    </form>
                    <?php endif; ?>
                </td>
                <td class="mono-sm"><?= substr(htmlspecialchars($u['api_key']), 0, 16) ?>...</td>
                <td>
                    <div class="action-group">
                        <form method="POST" style="display:inline; margin:0;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="toggle_user">
                            <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                            <button type="submit" class="btn btn-small waves-effect"><?= $u['is_active'] ? 'Disable' : 'Enable' ?></button>
                        </form>
                        <form method="POST" style="display:inline; margin:0;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="regen_api">
                            <input type="hidden" name="user_id" value="<?= (int)$u['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger waves-effect" onclick="return confirm('Regenerate API key?')">Regen Key</button>
                        </form>
                    </div>
                </td>
            </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>

<div class="card admin-pane" data-tab="sync" id="live-sync-logs" data-live-section>
    <div class="card-head"><h2>Sync Logs</h2></div>
    <table class="striped highlight responsive-table">
        <thead>
            <tr><th>Time</th><th>Source</th><th>Received</th><th>Inserted</th><th>Error</th></tr>
        </thead>
        <tbody>
            <?php foreach ($syncLogs as $log): ?>
            <tr>
                <td><?= htmlspecialchars(fmt_date($log['created_at'])) ?></td>
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
<div class="card admin-pane" data-tab="system">
    <div class="card-head"><h2>System</h2></div>
    <h5>Maintenance</h5>
    <div class="section-actions">
        <a href="/admin/update.php" class="btn waves-effect"><i class="material-icons left">system_update</i>Check for Updates / Update Web App</a>
        <a href="/admin/cleanup.php" class="btn btn-danger waves-effect"><i class="material-icons left">cleaning_services</i>Cleanup False Matches</a>
    </div>

    <div class="divider"></div>

    <h5>New-domain listing</h5>
    <p class="muted">
        Domains already tagged good/bad and matches produced by a <strong>recheck</strong> are hidden from the
        "new" listings by default. Use this to archive every match that predates the new baseline rule
        (one-off, reversible): <strong><?= number_format($historicalMatchCount) ?></strong> match(es) archived.
    </p>
    <div class="section-actions">
        <form method="POST" style="margin:0;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="archive_historical">
            <button type="submit" class="btn waves-effect" onclick="return confirm('Archive all current matches? They will be hidden from the new listings. You can restore them later.')"><i class="material-icons left">inventory_2</i>Archive all current matches</button>
        </form>
        <?php if ($historicalMatchCount > 0): ?>
        <form method="POST" style="margin:0;">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="unarchive_historical">
            <button type="submit" class="btn btn-outline waves-effect" onclick="return confirm('Restore all archived matches to the new listings?')"><i class="material-icons left">unarchive</i>Restore archived</button>
        </form>
        <?php endif; ?>
    </div>

    <div class="divider"></div>

    <h5>Registration</h5>
    <p>Status: <strong><?= $regOpen ? '<span class="text-success">Open</span>' : '<span class="muted">Closed</span>' ?></strong></p>
    <form method="POST">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="toggle_registration">
        <button type="submit" class="btn waves-effect <?= $regOpen ? 'btn-danger' : '' ?>"><i class="material-icons left"><?= $regOpen ? 'lock' : 'lock_open' ?></i><?= $regOpen ? 'Close Registration' : 'Open Registration' ?></button>
    </form>

    <div class="divider"></div>

    <form method="POST" class="section-actions">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="set_new_domain_days">
        <label class="nowrap">New domain threshold:</label>
        <input type="number" name="new_domain_days" value="<?= (int)getSetting($db, 'new_domain_days', '1') ?>" min="1" max="365" class="browser-default compact num-input">
        <span class="muted">day(s)</span>
        <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">save</i>Save</button>
    </form>
    <p class="muted">Domains created within this window will show the NEW badge and appear in the "New only" filter.</p>
</div>

<script>
(function() {
    const tabs = document.querySelectorAll('#admin-tabs a[data-tab]');
    const panes = document.querySelectorAll('.admin-pane[data-tab]');
    function activate(tab) {
        tabs.forEach(a => a.classList.toggle('active', a.dataset.tab === tab));
        panes.forEach(p => p.classList.toggle('active', p.dataset.tab === tab));
    }
    tabs.forEach(a => {
        a.addEventListener('click', function(e) {
            // TLDs is a direct link (href to another page); let it navigate.
            if (a.dataset.tab === 'tlds') return;
            e.preventDefault();
            const t = a.dataset.tab;
            if (history.replaceState) history.replaceState(null, '', '#'+t);
            activate(t);
        });
    });
    const hash = (location.hash || '').replace('#','');
    const valid = ['overview','worker','commands','recheck','users','sync','system'];
    if (hash && valid.includes(hash)) activate(hash);
})();

// Estimate the number of cached domains a scoped recheck would scan.
function recheckEstimate() {
    const sel = document.getElementById('recheck-tlds');
    const out = document.getElementById('recheck-estimate');
    const czds = document.querySelector('input[name="source_czds"]');
    if (!sel || !out) return;
    let total = 0;
    let selected = 0;
    sel.querySelectorAll('option:checked').forEach(function (o) {
        total += parseInt(o.dataset.total || '0', 10);
        selected++;
    });
    let msg = selected ? (selected + ' TLD(s) selected · ~' + total.toLocaleString() + ' cached domains') : 'No TLDs selected';
    if (czds && czds.checked && selected === 0) {
        msg += ' — ICANN needs selected TLDs, a max-domains cap, or a max age to bound the scan.';
    }
    out.textContent = msg;
}
document.addEventListener('DOMContentLoaded', recheckEstimate);
</script>

<?php require __DIR__ . '/../templates/footer.php'; ?>
