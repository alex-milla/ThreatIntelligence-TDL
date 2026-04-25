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

// Admin stop recheck
if ($isAdmin && $_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'stop_recheck') {
    validateCsrf();
    $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)")
        ->execute(['stop_recheck', '']);
    $_SESSION['flash_message'] = 'Stop recheck queued. The worker will stop at the next batch boundary.';
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

// Load domain tags for recent matches
$domainTags = [];
if (!empty($recentMatches)) {
    $domains = array_column($recentMatches, 'domain');
    $placeholders = implode(',', array_fill(0, count($domains), '?'));
    $tagStmt = $db->prepare("SELECT domain, tag FROM domain_tags WHERE domain IN ($placeholders)");
    $tagStmt->execute($domains);
    foreach ($tagStmt->fetchAll() as $t) {
        $domainTags[$t['domain']] = $t['tag'];
    }
}

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
                <?php foreach ($recentMatches as $m): 
                    $dtag = $domainTags[$m['domain']] ?? null;
                    $tagBadge = '';
                    if ($dtag) {
                        $color = $dtag === 'good' ? '#27ae60' : '#c0392b';
                        $label = $dtag === 'good' ? 'GOOD' : 'BAD';
                        $tagBadge = ' <span style="display:inline-block;background:'.$color.';color:#fff;font-size:0.7rem;padding:1px 5px;border-radius:3px;margin-left:4px;">'.$label.'</span>';
                    }
                ?>
                <tr>
                    <td><a href="javascript:void(0)" onclick="openDomainModal('<?= htmlspecialchars(addslashes($m['domain'])) ?>')" style="color: #3498db; text-decoration: underline; cursor: pointer;"><?= htmlspecialchars($m['domain']) ?></a><?= $tagBadge ?></td>
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
        <div style="display: flex; gap: 10px; margin-top: 10px; flex-wrap: wrap;">
            <form method="POST">
                <?php csrfField(); ?>
                <input type="hidden" name="action" value="recheck_keywords">
                <button type="submit" class="btn" <?= ($recheckRunning || (int)$pendingRecheck > 0) ? 'disabled' : '' ?>>
                    <?= $recheckRunning ? 'Recheck in progress...' : ((int)$pendingRecheck > 0 ? 'Queued — waiting for worker' : 'Recheck All Cached Domains') ?>
                </button>
            </form>
            <?php if ($recheckRunning): ?>
            <form method="POST">
                <?php csrfField(); ?>
                <input type="hidden" name="action" value="stop_recheck">
                <button type="submit" class="btn btn-danger">⏹ Stop Recheck</button>
            </form>
            <?php endif; ?>
        </div>
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

<!-- Domain detail modal -->
<div id="domain-modal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); align-items: center; justify-content: center;">
    <div style="background: white; padding: 25px; border-radius: 8px; max-width: 520px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.3); max-height: 90vh; overflow-y: auto;">
        <h3 id="modal-domain-title" style="margin-top: 0; word-break: break-all;"></h3>
        <div id="modal-whois-box" style="margin: 15px 0;">
            <button type="button" id="modal-whois-btn" class="btn" style="width: 100%;" onclick="fetchWhois()">🔍 Consultar Whois (RDAP)</button>
            <div id="modal-whois-loading" style="display: none; color: #666; font-size: 0.9rem; margin-top: 10px;">Consultando whois...</div>
            <div id="modal-whois-content" style="display: none; margin-top: 10px;">
                <table style="width: 100%; font-size: 0.9rem;">
                    <tr><td style="color: #666; padding: 4px 8px 4px 0;">Creation Date</td><td id="modal-creation" style="font-weight: 600;"></td></tr>
                    <tr><td style="color: #666; padding: 4px 8px 4px 0;">Expiration Date</td><td id="modal-expiration" style="font-weight: 600;"></td></tr>
                    <tr><td style="color: #666; padding: 4px 8px 4px 0;">Registrar</td><td id="modal-registrar" style="font-weight: 600;"></td></tr>
                    <tr><td style="color: #666; padding: 4px 8px 4px 0; vertical-align: top;">Name Servers</td><td id="modal-ns" style="font-weight: 600;"></td></tr>
                </table>
            </div>
            <div id="modal-whois-error" style="display: none; color: #c0392b; font-size: 0.9rem; margin-top: 10px;"></div>
        </div>
        <div id="modal-watchlist-box" style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 4px; display: none;">
            <div style="font-size: 0.85rem; color: #666; margin-bottom: 6px;">Watchlist</div>
            <div id="modal-watchlist-current" style="font-weight: 600; margin-bottom: 8px;"></div>
            <div id="modal-watchlist-actions" style="display: flex; gap: 8px;">
                <button type="button" id="modal-watchlist-btn" class="btn btn-small" style="flex:1;" onclick="toggleWatchlist(_modalDomain)">⭐ Add to Watchlist</button>
            </div>
        </div>
        <div id="modal-tag-box" style="margin: 10px 0; padding: 10px; background: #f8f9fa; border-radius: 4px; display: none;">
            <div style="font-size: 0.85rem; color: #666; margin-bottom: 6px;">Domain classification</div>
            <div id="modal-tag-current" style="font-weight: 600; margin-bottom: 8px;"></div>
            <div style="display: flex; gap: 8px;">
                <button type="button" class="btn btn-small" style="background:#27ae60; flex:1;" onclick="tagDomain(_modalDomain, 'good')">Mark Good</button>
                <button type="button" class="btn btn-small" style="background:#c0392b; flex:1;" onclick="tagDomain(_modalDomain, 'bad')">Mark Bad</button>
                <button type="button" class="btn btn-small btn-danger" style="flex:1;" onclick="tagDomain(_modalDomain, '')">Remove</button>
            </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 10px; margin-top: 15px;">
            <a id="modal-vt" href="#" target="_blank" class="btn" style="text-align: center; background: #3949ab;">🛡️ Open in VirusTotal</a>
        </div>
        <button onclick="document.getElementById('domain-modal').style.display='none'" class="btn btn-danger" style="margin-top: 15px; width: 100%;">Close</button>
    </div>
</div>

<script>
let _modalDomain = '';
function openDomainModal(domain) {
    _modalDomain = domain;
    document.getElementById('modal-domain-title').textContent = domain;
    document.getElementById('modal-vt').href = 'https://www.virustotal.com/gui/domain/' + encodeURIComponent(domain);
    document.getElementById('modal-whois-btn').style.display = 'block';
    document.getElementById('modal-whois-loading').style.display = 'none';
    document.getElementById('modal-whois-content').style.display = 'none';
    document.getElementById('modal-whois-error').style.display = 'none';
    document.getElementById('modal-tag-box').style.display = 'block';
    document.getElementById('modal-tag-current').textContent = 'Loading...';
    document.getElementById('modal-watchlist-box').style.display = 'block';
    document.getElementById('modal-watchlist-current').textContent = 'Loading...';
    document.getElementById('domain-modal').style.display = 'flex';
    loadDomainTag(domain);
    loadWatchlistStatus(domain);
}
function loadDomainTag(domain) {
    fetch('/ajax_tag_domain.php?domain=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            const box = document.getElementById('modal-tag-current');
            if (data.success && data.tag) {
                const color = data.tag.tag === 'good' ? '#27ae60' : '#c0392b';
                box.innerHTML = '<span style="color:' + color + '; font-weight:700;">' + data.tag.tag.toUpperCase() + '</span>';
                if (data.tag.note) box.innerHTML += ' — ' + htmlspecialchars(data.tag.note);
            } else {
                box.textContent = 'Not classified';
            }
        })
        .catch(() => {
            document.getElementById('modal-tag-current').textContent = 'Unable to load tag';
        });
}
function loadWatchlistStatus(domain) {
    fetch('/ajax_watchlist.php?check=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            const box = document.getElementById('modal-watchlist-current');
            const btn = document.getElementById('modal-watchlist-btn');
            if (data.in_watchlist) {
                box.innerHTML = '<span style="color: #f39c12;">⭐ In watchlist</span>' + (data.note ? ' — ' + htmlspecialchars(data.note) : '');
                btn.textContent = 'Remove from Watchlist';
                btn.style.background = '#e74c3c';
            } else {
                box.textContent = 'Not in watchlist';
                btn.textContent = '⭐ Add to Watchlist';
                btn.style.background = '';
            }
        })
        .catch(() => {
            document.getElementById('modal-watchlist-current').textContent = 'Unable to load watchlist status';
        });
}
function toggleWatchlist(domain) {
    fetch('/ajax_watchlist.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain: domain})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            loadWatchlistStatus(domain);
        } else {
            alert(data.error || 'Failed to update watchlist');
        }
    })
    .catch(() => alert('Failed to update watchlist'));
}
function tagDomain(domain, tag) {
    fetch('/ajax_tag_domain.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({domain: domain, tag: tag})
    })
    .then(r => r.json())
    .then(data => {
        if (data.success) {
            loadDomainTag(domain);
            window.location.reload();
        } else {
            alert(data.error || 'Failed to tag domain');
        }
    })
    .catch(() => alert('Failed to tag domain'));
}
function htmlspecialchars(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
function fetchWhois() {
    if (!_modalDomain) return;
    document.getElementById('modal-whois-btn').style.display = 'none';
    document.getElementById('modal-whois-loading').style.display = 'block';
    document.getElementById('modal-whois-error').style.display = 'none';

    fetch('/ajax_whois.php?domain=' + encodeURIComponent(_modalDomain))
        .then(r => r.json())
        .then(data => {
            document.getElementById('modal-whois-loading').style.display = 'none';
            if (data.success) {
                document.getElementById('modal-creation').textContent = data.creationDate ? new Date(data.creationDate).toLocaleString() : 'N/A';
                document.getElementById('modal-expiration').textContent = data.expirationDate ? new Date(data.expirationDate).toLocaleString() : 'N/A';
                document.getElementById('modal-registrar').textContent = data.registrar || 'N/A';
                document.getElementById('modal-ns').innerHTML = data.nameServers.length ? data.nameServers.map(ns => '<div>' + ns + '</div>').join('') : 'N/A';
                document.getElementById('modal-whois-content').style.display = 'block';
            } else {
                document.getElementById('modal-whois-error').textContent = 'Whois unavailable: ' + (data.error || 'Unknown error');
                document.getElementById('modal-whois-error').style.display = 'block';
                document.getElementById('modal-whois-btn').style.display = 'block';
            }
        })
        .catch(() => {
            document.getElementById('modal-whois-loading').style.display = 'none';
            document.getElementById('modal-whois-error').textContent = 'Whois query failed. Try again later.';
            document.getElementById('modal-whois-error').style.display = 'block';
            document.getElementById('modal-whois-btn').style.display = 'block';
        });
}
document.getElementById('domain-modal').addEventListener('click', function(e) {
    if (e.target === this) this.style.display = 'none';
});
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
