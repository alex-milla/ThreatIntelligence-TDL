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
<div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
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
<a href="/admin/#worker" class="card worker-health">
    <span class="dot" style="background:<?= htmlspecialchars($hColor) ?>;"></span>
    <strong><?= $hLabel ?></strong>
    <?php if ($isBusy && !empty($workerHealth['current_command'])): ?>
        <span class="wh-extra">&mdash; <?= htmlspecialchars($workerHealth['current_command']) ?><?php if (!empty($workerHealth['current_tld'])) echo ' &middot; ' . htmlspecialchars($workerHealth['current_tld']); ?></span>
    <?php endif; ?>
    <span class="wh-goto">Admin <i class="material-icons tiny">arrow_forward</i></span>
</a>
<?php endif; ?>

<div class="row">
    <div class="col s6 m6 l3">
        <div class="card stat-card deep-purple">
            <i class="material-icons stat-icon">vpn_key</i>
            <div class="number"><?= $keywordCount ?></div>
            <div class="label">Active keywords</div>
        </div>
    </div>
    <div class="col s6 m6 l3">
        <div class="card stat-card blue darken-1">
            <i class="material-icons stat-icon">find_in_page</i>
            <div class="number"><?= $matchCount ?></div>
            <div class="label">Matches (<?= htmlspecialchars($period) === 'all' ? 'all time' : htmlspecialchars($period) ?>)</div>
        </div>
    </div>
    <div class="col s6 m6 l3">
        <div class="card stat-card orange darken-2">
            <i class="material-icons stat-icon">notifications</i>
            <div class="number"><?= $unreadCount ?></div>
            <div class="label">Unread notifications</div>
        </div>
    </div>
    <div class="col s6 m6 l3">
        <div class="card stat-card teal darken-1">
            <i class="material-icons stat-icon">fiber_new</i>
            <div class="number"><?= $new24h ?></div>
            <div class="label">New in last 24h</div>
        </div>
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
    <div class="card-head">
        <h2>Matches per day <span class="card-sub">last 30 days &middot; <?= number_format($sparkTotal) ?> total</span></h2>
        <?php if ($sparkMax === 0): ?>
            <span class="muted">No matches in this window</span>
        <?php endif; ?>
    </div>
    <?php if ($sparkMax > 0): ?>
    <div class="sparkline">
        <?php foreach ($sparkDays as $d => $c):
            $h = $sparkMax > 0 ? max(round($c / $sparkMax * 100), $c > 0 ? 6 : 2) : ($c > 0 ? 6 : 2);
            $bg = $c > 0 ? '#512da8' : '#eceff1';
        ?>
        <div title="<?= htmlspecialchars($d) ?>: <?= $c ?>" style="height:<?= $h ?>%; background:<?= $bg ?>;"></div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>

<div class="card">
    <div class="card-head">
        <h2>Recent Matches</h2>
        <form method="GET" class="inline-filter">
            <select name="period" class="browser-default compact" onchange="this.form.submit()">
                <option value="24h" <?= $period === '24h' ? 'selected' : '' ?>>Last 24h</option>
                <option value="7d" <?= $period === '7d' ? 'selected' : '' ?>>Last 7 days</option>
                <option value="30d" <?= $period === '30d' ? 'selected' : '' ?>>Last 30 days</option>
                <option value="all" <?= $period === 'all' ? 'selected' : '' ?>>All time</option>
            </select>
            <noscript><button type="submit" class="btn btn-small">Filter</button></noscript>
        </form>
    </div>
    <?php if (empty($recentMatches)): ?>
        <p class="muted">No matches in this period. Start by adding <a href="/keywords.php">keywords</a>.</p>
    <?php else: ?>
        <table class="striped highlight responsive-table">
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
                        $cls = $dtag === 'good' ? 'good' : 'bad';
                        $label = $dtag === 'good' ? 'GOOD' : 'BAD';
                        $tagBadge = ' <span class="tag-chip ' . $cls . '">' . $label . '</span>';
                    }
                ?>
                <tr>
                    <td><a href="javascript:void(0)" class="domain-link" onclick="toggleDomainDetail(this, '<?= htmlspecialchars(addslashes($m['domain'])) ?>')"><?= htmlspecialchars($m['domain']) ?></a><?= $tagBadge ?></td>
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

<script>
let _modalDomain = '';
function buildPanelHtml(domain) {
    return '<div class="dpanel">'
        + '<div class="dpanel-header">'
        +   '<h3 id="modal-domain-title"></h3>'
        +   '<button type="button" class="dpanel-close" aria-label="Close panel" onclick="closeDomainDetail()"><i class="material-icons">close</i></button>'
        + '</div>'
        + '<div class="dpanel-section">'
        +   '<div class="dpanel-section-label">WHOIS Registry Data</div>'
        +   '<button type="button" id="modal-whois-btn" class="btn btn-small waves-effect" style="width:100%; margin-bottom:8px;" onclick="fetchWhois()">Fetch WHOIS via worker</button>'
        +   '<div id="modal-whois-loading" class="muted" style="display:none; padding:4px 0;">Consultando WHOIS...</div>'
        +   '<div id="modal-whois-content" style="display:none;">'
        +     '<div class="dpanel-whois-grid">'
        +       '<div>Creation Date</div><div id="modal-creation"></div>'
        +       '<div>Expiration Date</div><div id="modal-expiration"></div>'
        +       '<div>Registrar</div><div id="modal-registrar"></div>'
        +       '<div>Name Servers</div><div id="modal-ns"></div>'
        +     '</div>'
        +   '</div>'
        +   '<div id="modal-whois-error" class="text-danger" style="display:none; padding:4px 0;"></div>'
        + '</div>'
        + '<div class="dpanel-section" id="modal-tag-box">'
        +   '<div class="dpanel-section-label">Classification</div>'
        +   '<div class="dpanel-status-row"><span class="muted">Status:</span><span class="status-value" id="modal-tag-current">Loading...</span></div>'
        +   '<div class="dpanel-btn-row">'
        +     '<button type="button" class="btn btn-small green waves-effect" onclick="tagDomain(_modalDomain, \'good\')">Mark Good</button>'
        +     '<button type="button" class="btn btn-small red waves-effect" onclick="tagDomain(_modalDomain, \'bad\')">Mark Bad</button>'
        +     '<button type="button" class="btn btn-small btn-danger waves-effect" onclick="tagDomain(_modalDomain, \'\')">Clear</button>'
        +   '</div>'
        + '</div>'
        + '<div class="dpanel-section" id="modal-watchlist-box">'
        +   '<div class="dpanel-section-label">Watchlist</div>'
        +   '<div class="dpanel-status-row"><span class="muted">Status:</span><span class="status-value" id="modal-watchlist-current">Loading...</span></div>'
        +   '<div class="dpanel-btn-row"><button type="button" id="modal-watchlist-btn" class="btn btn-small waves-effect" onclick="toggleWatchlist(_modalDomain)">Add to Watchlist</button></div>'
        + '</div>'
        + '<div class="dpanel-footer"><a id="modal-vt" href="#" target="_blank" class="btn waves-effect indigo"><i class="material-icons left">shield</i>Open in VirusTotal</a></div>'
        + '</div>';
}
function toggleDomainDetail(linkEl, domain) {
    var row = linkEl.closest('tr');
    var existing = row.nextElementSibling;
    if (existing && existing.classList.contains('dpanel-row') && existing.dataset.domain === domain) {
        existing.remove();
        return;
    }
    document.querySelectorAll('.dpanel-row').forEach(function(r) { r.remove(); });
    _modalDomain = domain;
    var detailRow = document.createElement('tr');
    detailRow.className = 'dpanel-row';
    detailRow.dataset.domain = domain;
    detailRow.innerHTML = '<td colspan="5">' + buildPanelHtml(domain) + '</td>';
    row.parentNode.insertBefore(detailRow, row.nextSibling);
    document.getElementById('modal-domain-title').textContent = domain;
    document.getElementById('modal-vt').href = 'https://www.virustotal.com/gui/domain/' + encodeURIComponent(domain);
    loadCachedWhois();
    loadDomainTag(domain);
    loadWatchlistStatus(domain);
    detailRow.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}
function closeDomainDetail() {
    document.querySelectorAll('.dpanel-row').forEach(function(r) { r.remove(); });
}
function loadDomainTag(domain) {
    fetch('/ajax_tag_domain.php?domain=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            const box = document.getElementById('modal-tag-current');
            if (!box) return;
            if (data.success && data.tag) {
                const color = data.tag.tag === 'good' ? '#2e7d32' : '#c62828';
                box.innerHTML = '<span style="color:' + color + '; font-weight:700;">' + data.tag.tag.toUpperCase() + '</span>';
                if (data.tag.note) box.innerHTML += ' &mdash; ' + htmlspecialchars(data.tag.note);
            } else {
                box.textContent = 'Not classified';
            }
        })
        .catch(() => {
            const box = document.getElementById('modal-tag-current');
            if (box) box.textContent = 'Unable to load tag';
        });
}
function loadWatchlistStatus(domain) {
    fetch('/ajax_watchlist.php?check=' + encodeURIComponent(domain))
        .then(r => r.json())
        .then(data => {
            const box = document.getElementById('modal-watchlist-current');
            const btn = document.getElementById('modal-watchlist-btn');
            if (!box) return;
            if (data.in_watchlist) {
                let html = '<span style="color:#f39c12; font-weight:700;">In watchlist</span>';
                if (data.group_name) html += ' <span class="muted">(' + htmlspecialchars(data.group_name) + ')</span>';
                if (data.note) html += ' &mdash; ' + htmlspecialchars(data.note);
                box.innerHTML = html;
                btn.textContent = 'Remove from Watchlist';
                btn.classList.add('btn-danger');
            } else {
                box.textContent = 'Not in watchlist';
                btn.textContent = 'Add to Watchlist';
                btn.classList.remove('btn-danger');
            }
        })
        .catch(() => {
            const box = document.getElementById('modal-watchlist-current');
            if (box) box.textContent = 'Unable to load watchlist status';
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
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
