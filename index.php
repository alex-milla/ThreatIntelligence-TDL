<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);
$message = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_message']);

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

$stmt = $db->prepare("SELECT COUNT(*) FROM notifications n JOIN matches m ON n.match_id = m.id WHERE n.user_id = ? AND n.is_read = 0 AND NOT EXISTS (SELECT 1 FROM watchlist w WHERE w.user_id = ? AND w.domain = m.domain)");
$stmt->execute([$userId, $userId]);
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

// New matches in the last 24h (trend KPI)
$stmt = $db->prepare("SELECT COUNT(*) FROM matches m JOIN keywords k ON m.keyword_id = k.id WHERE k.user_id = ? AND m.discovered_at >= datetime('now','-1 day')");
$stmt->execute([$userId]);
$new24h = (int)$stmt->fetchColumn();

// Matches per day for the last 30 days (sparkline)
$stmt = $db->prepare("SELECT date(m.discovered_at) AS d, COUNT(*) AS c FROM matches m JOIN keywords k ON m.keyword_id = k.id WHERE k.user_id = ? AND m.discovered_at >= datetime('now','-30 days') GROUP BY date(m.discovered_at) ORDER BY d ASC");
$stmt->execute([$userId]);
$matchesPerDay = $stmt->fetchAll();

// Admin: at-a-glance worker health
$workerHealth = null;
if ($isAdmin) {
    $workerHealth = $db->query("SELECT is_running, last_heartbeat, current_command, current_tld FROM worker_status WHERE id = 1")->fetch();
}

$pageTitle = 'Dashboard';
require __DIR__ . '/templates/header.php';
?>

<?php if ($message): ?>
<div class="alert alert-success"><?= htmlspecialchars($message) ?></div>
<?php endif; ?>

<?php if ($isAdmin && $workerHealth): ?>
<?php
    $hbStale = false;
    if (!empty($workerHealth['last_heartbeat'])) {
        $hbStale = (time() - strtotime($workerHealth['last_heartbeat'])) > 300;
    }
    $isBusy = (int)($workerHealth['is_running'] ?? 0) === 1;
    if ($isBusy) { $hState = 'busy'; $hLabel = 'Worker busy'; $hColor = '#e67e22'; }
    elseif (empty($workerHealth['last_heartbeat'])) { $hState = 'unknown'; $hLabel = 'Worker never seen'; $hColor = '#7f8c8d'; }
    elseif ($hbStale) { $hState = 'down'; $hLabel = 'Worker unreachable'; $hColor = '#c0392b'; }
    else { $hState = 'ok'; $hLabel = 'Worker online'; $hColor = '#27ae60'; }
?>
<a href="/admin/#worker" style="display:flex; align-items:center; gap:8px; text-decoration:none; padding:8px 14px; border-radius:6px; background:<?= htmlspecialchars($hColor) ?>1a; border:1px solid <?= htmlspecialchars($hColor) ?>55; margin-bottom:16px; color:#333; font-size:0.9rem;">
    <span style="width:9px; height:9px; border-radius:50%; background:<?= htmlspecialchars($hColor) ?>; display:inline-block;"></span>
    <strong><?= $hLabel ?></strong>
    <?php if ($isBusy && !empty($workerHealth['current_command'])): ?>
        <span style="color:#666;">— <?= htmlspecialchars($workerHealth['current_command']) ?><?php if (!empty($workerHealth['current_tld'])) echo ' · ' . htmlspecialchars($workerHealth['current_tld']); ?></span>
    <?php endif; ?>
    <span style="margin-left:auto; color:#888;">Admin →</span>
</a>
<?php endif; ?>

<div class="stats">
    <div class="stat-box">
        <div class="number"><?= $keywordCount ?></div>
        <div class="label">Active keywords</div>
    </div>
    <div class="stat-box">
        <div class="number"><?= $matchCount ?></div>
        <div class="label">Matches (<?= htmlspecialchars($period) === 'all' ? 'all time' : htmlspecialchars($period) ?>)</div>
    </div>
    <div class="stat-box">
        <div class="number"><?= $unreadCount ?></div>
        <div class="label">Unread notifications</div>
    </div>
    <div class="stat-box">
        <div class="number"><?= $new24h ?></div>
        <div class="label">New in last 24h</div>
    </div>
</div>

<?php
// Sparkline: matches per day (last 30 days), pure CSS/SVG
$sparkMax = 0;
foreach ($matchesPerDay as $row) {
    if ((int)$row['c'] > $sparkMax) $sparkMax = (int)$row['c'];
}
$sparkDays = [];
for ($i = 29; $i >= 0; $i--) {
    $d = date('Y-m-d', strtotime("-{$i} days"));
    $sparkDays[$d] = 0;
}
foreach ($matchesPerDay as $row) {
    if (isset($sparkDays[$row['d']])) $sparkDays[$row['d']] = (int)$row['c'];
}
$sparkTotal = array_sum($sparkDays);
$sparkNonZero = count(array_filter($sparkDays));
?>
<div class="card">
    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:8px; margin-bottom:12px;">
        <h2 style="margin:0;">Matches per day <span style="color:#888; font-weight:normal; font-size:0.85rem;">last 30 days · <?= number_format($sparkTotal) ?> total</span></h2>
        <?php if ($sparkMax === 0): ?>
            <span style="color:#999; font-size:0.85rem;">No matches in this window</span>
        <?php endif; ?>
    </div>
    <?php if ($sparkMax > 0): ?>
    <div style="display:flex; align-items:flex-end; gap:2px; height:80px; width:100%;">
        <?php foreach ($sparkDays as $d => $c):
            $h = $sparkMax > 0 ? max(round($c / $sparkMax * 100), $c > 0 ? 6 : 2) : ($c > 0 ? 6 : 2);
            $bg = $c > 0 ? '#3498db' : '#eef0f4';
        ?>
        <div title="<?= htmlspecialchars($d) ?>: <?= $c ?>" style="flex:1; height:<?= $h ?>%; min-width:3px; background:<?= $bg ?>; border-radius:2px 2px 0 0; transition:height .2s;"></div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
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
                    <td><?= htmlspecialchars(fmt_date($m['first_seen'])) ?></td>
                    <td><?= htmlspecialchars(fmt_date($m['discovered_at'])) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<!-- Domain detail modal -->
<div id="domain-modal" style="display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); align-items: center; justify-content: center;">
    <div style="background: white; padding: 25px; border-radius: 8px; max-width: 520px; width: 90%; box-shadow: 0 4px 20px rgba(0,0,0,0.3); max-height: 90vh; overflow-y: auto;">
        <h3 id="modal-domain-title" style="margin-top: 0; word-break: break-all;"></h3>
        <div id="modal-whois-box" style="margin: 15px 0;">
            <button type="button" id="modal-whois-btn" class="btn" style="width: 100%;" onclick="fetchWhois()">🔍 Fetch WHOIS (worker)</button>
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
    document.getElementById('modal-whois-loading').style.display = 'none';
    document.getElementById('modal-whois-content').style.display = 'none';
    document.getElementById('modal-whois-error').style.display = 'none';
    loadCachedWhois();
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
                let html = '<span style="color: #f39c12;">⭐ In watchlist</span>';
                if (data.group_name) html += ' <span style="color:#666;font-size:0.85rem;">(' + htmlspecialchars(data.group_name) + ')</span>';
                if (data.note) html += ' — ' + htmlspecialchars(data.note);
                box.innerHTML = html;
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
document.getElementById('domain-modal').addEventListener('click', function(e) {
    if (e.target === this) this.style.display = 'none';
});
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
