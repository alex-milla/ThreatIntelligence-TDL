<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);
$message = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_message']);
$activity = getWorkerActivity($db);

// Hide from the "new" dashboard view (matching the notifications page default):
// historical (recheck) matches, domains classified good/bad, and domains whose
// WHOIS creation date proves they were already registered before the last
// successful scan of their TLD. Domains under observation are never hidden.
$newDomainDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));
$oldDomainSql = "EXISTS (SELECT 1 FROM domain_whois dw JOIN tlds t ON t.name = m.tld "
    . "WHERE dw.domain = m.domain AND t.last_ok_sync IS NOT NULL "
    . "AND COALESCE(dw.creation_ts, datetime(dw.creation_date)) IS NOT NULL "
    . "AND COALESCE(dw.creation_ts, datetime(dw.creation_date)) < datetime(t.last_ok_sync, '-{$newDomainDays} days'))";
$archiveSql = " AND m.is_historical = 0"
    . " AND NOT EXISTS (SELECT 1 FROM domain_tags dt WHERE dt.domain = m.domain AND dt.tag IN ('good','bad'))"
    . " AND NOT EXISTS (SELECT 1 FROM domain_tags dx WHERE dx.domain = m.domain AND dx.tag = 'excluded')"
    . " AND (EXISTS (SELECT 1 FROM domain_tags do WHERE do.domain = m.domain AND do.tag = 'observing')"
    . " OR NOT " . $oldDomainSql . ")";

// Stats
$stmt = $db->prepare("SELECT COUNT(*) FROM keywords WHERE user_id = ?");
$stmt->execute([$userId]);
$keywordCount = (int)$stmt->fetchColumn();

$matchSql = "SELECT COUNT(*) FROM matches m JOIN keywords k ON m.keyword_id = k.id WHERE k.user_id = ?" . $archiveSql;
$stmt = $db->prepare($matchSql);
$stmt->execute([$userId]);
$matchCount = (int)$stmt->fetchColumn();

$stmt = $db->prepare("SELECT COUNT(*) FROM notifications n JOIN matches m ON n.match_id = m.id WHERE n.user_id = ? AND n.is_read = 0 AND NOT EXISTS (SELECT 1 FROM watchlist w WHERE w.user_id = ? AND w.domain = m.domain)" . $archiveSql);
$stmt->execute([$userId, $userId]);
$unreadCount = (int)$stmt->fetchColumn();

// New matches in the last 24h (trend KPI)
$stmt = $db->prepare("SELECT COUNT(*) FROM matches m JOIN keywords k ON m.keyword_id = k.id WHERE k.user_id = ?" . $archiveSql . " AND m.discovered_at >= datetime('now','-1 day')");
$stmt->execute([$userId]);
$new24h = (int)$stmt->fetchColumn();

// Matches per day for the last 30 days (sparkline)
$stmt = $db->prepare("SELECT date(m.discovered_at) AS d, COUNT(*) AS c FROM matches m JOIN keywords k ON m.keyword_id = k.id WHERE k.user_id = ?" . $archiveSql . " AND m.discovered_at >= datetime('now','-30 days') GROUP BY date(m.discovered_at) ORDER BY d ASC");
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

<span id="activity-watcher" hidden
      data-url="/ajax_worker_activity.php"
      data-interval="5000"
      data-refresh-interval="10000"
      data-active="<?= $activity['active'] ? '1' : '0' ?>"
      data-version="<?= htmlspecialchars($activity['worker_version']) ?>"></span>

<?php if ($isAdmin && $workerHealth): ?>
<?php
    $hbStale = false;
    if (!empty($workerHealth['last_heartbeat'])) {
        $hbStale = (time() - strtotime($workerHealth['last_heartbeat'])) > 300;
    }
    $isBusy = (int)($workerHealth['is_running'] ?? 0) === 1;
    if ($isBusy) { $hState = 'busy'; $hLabel = 'Worker busy'; }
    elseif (empty($workerHealth['last_heartbeat'])) { $hState = 'unknown'; $hLabel = 'Worker never seen'; }
    elseif ($hbStale) { $hState = 'down'; $hLabel = 'Worker unreachable'; }
    else { $hState = 'ok'; $hLabel = 'Worker online'; }
?>
<a href="/admin/#worker" class="card worker-health" id="live-worker-health" data-live-section>
    <span class="dot <?= $hState ?>"></span>
    <strong><?= $hLabel ?></strong>
    <?php if ($isBusy && !empty($workerHealth['current_command'])): ?>
        <span class="wh-extra">&mdash; <?= htmlspecialchars($workerHealth['current_command']) ?><?php if (!empty($workerHealth['current_tld'])) echo ' &middot; ' . htmlspecialchars($workerHealth['current_tld']); ?></span>
    <?php endif; ?>
    <span class="wh-goto">Admin <i class="material-icons tiny">arrow_forward</i></span>
</a>
<?php endif; ?>

<div class="row" id="live-stats" data-live-section>
    <div class="col s6 m6 l3">
        <div class="card stat-card">
            <i class="material-icons stat-icon">vpn_key</i>
            <div class="number"><?= $keywordCount ?></div>
            <div class="label">Active keywords</div>
        </div>
    </div>
    <div class="col s6 m6 l3">
        <div class="card stat-card">
            <i class="material-icons stat-icon tone-info">find_in_page</i>
            <div class="number"><?= $matchCount ?></div>
            <div class="label">Matches (all time)</div>
        </div>
    </div>
    <div class="col s6 m6 l3">
        <div class="card stat-card">
            <i class="material-icons stat-icon tone-warning">notifications</i>
            <div class="number"><?= $unreadCount ?></div>
            <div class="label">Unread notifications</div>
        </div>
    </div>
    <div class="col s6 m6 l3">
        <div class="card stat-card">
            <i class="material-icons stat-icon tone-success">fiber_new</i>
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
<div class="card" id="live-sparkline" data-live-section>
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
            $barClass = $c > 0 ? 'has-data' : 'empty';
        ?>
        <div title="<?= htmlspecialchars($d) ?>: <?= $c ?>" class="spark-bar <?= $barClass ?>" style="height:<?= $h ?>%"></div>
        <?php endforeach; ?>
    </div>
    <?php endif; ?>
</div>

<div class="card" id="domain-lookup">
    <div class="card-head">
        <h2>Domain lookup <span class="card-sub">exact domain lookup</span></h2>
    </div>
    <form id="lookup-form" class="filter-form" onsubmit="runDomainLookup(); return false;">
        <div class="input-field">
            <i class="material-icons prefix">search</i>
            <input id="lookup-q" type="text" placeholder=" " autocomplete="off" spellcheck="false" autocapitalize="off">
            <label for="lookup-q">Exact domain (e.g. example.com)</label>
        </div>
        <button type="submit" class="btn waves-effect"><i class="material-icons left">travel_explore</i>Search</button>
    </form>
    <p class="muted" style="font-size:.82rem; margin-top:-4px;">
        Enter the full domain, e.g. <code>example.com</code>. This is an <strong>exact domain</strong> lookup,
        not a keyword search. Exact search covers every cached domain (including hash-cached TLDs like .com).
    </p>
    <div id="lookup-status" class="muted" style="display:none; padding:6px 0;"></div>
    <div id="lookup-results"></div>
    <div id="lookup-panel" style="display:none;"></div>
</div>

<script>
let _modalDomain = '';
function showLookupPanel(domain) {
    _modalDomain = domain;
    var panel = document.getElementById('lookup-panel');
    var results = document.getElementById('lookup-results');
    if (results) results.innerHTML = '';
    if (!panel) return;
    panel.style.display = 'block';
    panel.innerHTML = '<p class="muted" style="padding:8px 0;">Loading details\u2026</p>';
    fetch('/ajax_domain_detail.php?domain=' + encodeURIComponent(domain), {cache: 'no-store'})
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (!d || !d.success) { panel.innerHTML = '<p class="muted">Unable to load details.</p>'; return; }
            panel.innerHTML = d.html;
            panel.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        })
        .catch(function () { panel.innerHTML = '<p class="muted">Unable to load details.</p>'; });
}
// Keep the lookup result on screen after an action instead of reloading the page.
window.ddAfterAction = function (domain) { showLookupPanel(domain); };

function closeDomainDetail() {
    var panel = document.getElementById('lookup-panel');
    if (panel) { panel.style.display = 'none'; panel.innerHTML = ''; }
}
function lookupCsrf() {
    var m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : '';
}
function runDomainLookup() {
    var qEl = document.getElementById('lookup-q');
    var q = qEl ? qEl.value.trim().toLowerCase() : '';
    var status = document.getElementById('lookup-status');
    var results = document.getElementById('lookup-results');
    if (!q) return;
    // Exact domain only: this is not a keyword/partial search.
    if (q.indexOf('.') === -1) {
        closeDomainDetail();
        if (results) results.innerHTML = '';
        if (status) { status.style.display = 'block'; status.textContent = 'Enter the full domain, e.g. example.com'; }
        if (qEl) qEl.focus();
        return;
    }
    closeDomainDetail();
    if (results) results.innerHTML = '';
    if (status) { status.style.display = 'block'; status.textContent = 'Searching the worker cache\u2026 (the worker polls every ~20 s)'; }
    fetch('/ajax_domain_search.php', {
        method: 'POST',
        headers: {'Content-Type': 'application/json', 'X-CSRF-Token': lookupCsrf()},
        body: JSON.stringify({q: q, mode: 'exact'})
    })
    .then(function (r) { return r.json(); })
    .then(function (d) {
        if (!d.success) { if (status) status.textContent = d.error || 'Search failed'; return; }
        pollDomainLookup(d.command_id, 0);
    })
    .catch(function () { if (status) status.textContent = 'Search failed'; });
}
function pollDomainLookup(commandId, tries) {
    var status = document.getElementById('lookup-status');
    if (tries > 60) { if (status) status.textContent = 'Timed out waiting for the worker.'; return; }
    fetch('/ajax_domain_search.php?command_id=' + encodeURIComponent(commandId), {cache: 'no-store'})
        .then(function (r) { return r.json(); })
        .then(function (d) {
            if (!d.success) { if (status) status.textContent = d.error || 'Search failed'; return; }
            if (d.status === 'completed') { renderLookupResults(d); return; }
            if (d.status === 'failed' || d.status === 'cancelled') { if (status) status.textContent = 'Search ' + d.status + '.'; return; }
            setTimeout(function () { pollDomainLookup(commandId, tries + 1); }, 3000);
        })
        .catch(function () { setTimeout(function () { pollDomainLookup(commandId, tries + 1); }, 5000); });
}
function renderLookupResults(data) {
    var status = document.getElementById('lookup-status');
    var results = document.getElementById('lookup-results');
    if (!results) return;
    var list = data.results || [];
    if (status) {
        if (data.partial) { status.style.display = 'block'; status.textContent = data.note || 'Partial results.'; }
        else if (!list.length) { status.style.display = 'block'; status.textContent = 'No cached domain found.'; }
        else { status.style.display = 'none'; }
    }
    if (!list.length) { results.innerHTML = ''; return; }
    var qEl = document.getElementById('lookup-q');
    var q = qEl ? qEl.value.trim().toLowerCase() : '';
    if (list.length === 1 && list[0].domain === q) { showLookupPanel(list[0].domain); return; }
    var rows = list.map(function (r) {
        var label = '';
        if (r.source === 'ct') { label += ' <span class="muted">(ccTLD/CT)</span>'; }
        else if (r.source === 'zone') { label += ' <span class="muted">(gTLD)</span>'; }
        if (r.hash_cached) { label += ' <span class="muted">(hash-cached)</span>'; }
        var seen = r.first_seen ? String(r.first_seen).substring(0, 10) : '\u2014';
        return '<tr><td><a href="javascript:void(0)" class="domain-link" onclick="showLookupPanel(\''
            + htmlspecialchars(r.domain) + '\')">' + htmlspecialchars(r.domain) + '</a>' + label
            + '</td><td>' + htmlspecialchars(r.tld || '') + '</td><td>' + htmlspecialchars(seen) + '</td></tr>';
    }).join('');
    results.innerHTML = '<table class="striped highlight responsive-table"><thead><tr>'
        + '<th>Domain</th><th>TLD</th><th>First seen</th></tr></thead><tbody>' + rows + '</tbody></table>';
}
function htmlspecialchars(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
