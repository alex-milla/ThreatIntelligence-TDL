<?php
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/auth.php';
requireAdmin();

$db = Database::get();
$message = $_SESSION['flash_message'] ?? '';
unset($_SESSION['flash_message']);

function tldStatusBadge(?string $status): string {
    $map = [
        'downloaded'    => 'Downloaded',
        'not_modified'  => 'Unchanged',
        'skipped_today' => 'Skipped today',
        'failed'        => 'Failed',
        'pending'       => 'Pending',
        'incomplete'    => 'Incomplete',
        'skipped_large' => 'Skipped (large)',
        'no_space'      => 'No space',
        'retrying'      => 'Retrying',
        'parse_error'   => 'Parse error',
    ];
    if ($status === null || $status === '' || !isset($map[$status])) {
        return '<span class="muted">&mdash;</span>';
    }
    return '<span class="status-badge status-' . $status . '">' . $map[$status] . '</span>';
}

function formatBytes(int $bytes): string {
    if ($bytes <= 0) {
        return '&mdash;';
    }
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = 0;
    $value = (float)$bytes;
    while ($value >= 1024 && $i < count($units) - 1) {
        $value /= 1024;
        $i++;
    }
    return round($value, $i >= 2 ? 1 : 0) . ' ' . $units[$i];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
    $action = $_POST['action'] ?? 'save_selection';
    $active = $_POST['active'] ?? [];

    // Always persist the current selection before queuing any worker command.
    $db->beginTransaction();
    $db->exec("UPDATE tlds SET is_active = 0");
    $stmt = $db->prepare("UPDATE tlds SET is_active = 1 WHERE name = ?");
    foreach ($active as $tld) {
        $stmt->execute([$tld]);
    }
    $db->commit();

    if ($action === 'run_worker_refresh' || $action === 'run_worker_force') {
        if (hasPendingCommand($db, 'run_worker')) {
            $_SESSION['flash_message'] = 'A worker run is already queued or running. Wait for it to finish.';
            header('Location: /admin/tlds.php');
            exit;
        }
        $refresh = $action === 'run_worker_refresh';
        $payload = json_encode($refresh ? ['refresh' => true] : ['force' => true]);
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)")
           ->execute(['run_worker', $payload]);
        $_SESSION['flash_message'] = $refresh
            ? 'Refresh queued for the selected TLD(s). The worker will download them only if they changed.'
            : 'Force re-download queued for the selected TLD(s). The worker will download them again regardless of cache.';
        header('Location: /admin/tlds.php');
        exit;
    }

    $_SESSION['flash_message'] = 'TLD selection saved. The worker will use these on next run.';
    header('Location: /admin/tlds.php');
    exit;
}

$tlds = $db->query(
    "SELECT id, name, is_active, last_sync, status, records_total, records_new, "
    . "zone_size, zone_file_mtime, last_error, retry_attempts, next_retry FROM tlds ORDER BY is_active DESC, name"
)->fetchAll();
$workerStatus = $db->query("SELECT is_running FROM worker_status WHERE id = 1")->fetch();
$workerRunning = !empty($workerStatus['is_running']);
$versionMismatch = workerVersionMismatch($db);

$summary = ['downloaded' => 0, 'not_modified' => 0, 'skipped_today' => 0, 'failed' => 0];
foreach ($tlds as $t) {
    if ($t['is_active'] && isset($summary[$t['status']])) {
        $summary[$t['status']]++;
    }
}
$activeCount = 0;
foreach ($tlds as $t) {
    if ($t['is_active']) {
        $activeCount++;
    }
}

$pageTitle = 'Manage TLDs';
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
    <strong>v<?= htmlspecialchars($versionMismatch['worker']) ?></strong>, so new commands (force/refresh) may be ignored.
    Update it from <a href="/admin/">Admin &rarr; Update Worker</a> or run <code>bash worker/update.sh --restart</code> on the worker host.
</div>
<?php endif; ?>

<div class="card">
    <div class="card-head">
        <h2>Approved TLDs (<?= count($tlds) ?>)</h2>
        <span class="muted">Check the TLDs you want the worker to monitor. Unchecked TLDs will be ignored.</span>
    </div>

    <?php if (empty($tlds)): ?>
    <div class="alert alert-error">
        <i class="material-icons left">error</i>
        No TLDs found. The worker must run at least once to populate this list from ICANN CZDS.
        <br>Go to <a href="/admin/"><strong>Admin Panel</strong></a> and click <strong>Run Worker Now</strong>.
    </div>
    <?php else: ?>

    <div class="status-summary">
        <span><strong><?= $activeCount ?></strong> active</span>
        <span class="text-success"><strong><?= $summary['downloaded'] ?></strong> downloaded</span>
        <span><strong><?= $summary['not_modified'] ?></strong> unchanged</span>
        <span class="muted"><strong><?= $summary['skipped_today'] ?></strong> skipped today</span>
        <span class="text-danger"><strong><?= $summary['failed'] ?></strong> failed</span>
        <?php if ($workerRunning): ?>
        <span class="text-warning"><i class="material-icons tiny">autorenew</i> worker running&hellip;</span>
        <?php endif; ?>
    </div>

    <div class="input-field">
        <i class="material-icons prefix">search</i>
        <input type="text" id="tld-search" onkeyup="filterTlds()" placeholder=" ">
        <label for="tld-search">Search TLDs</label>
    </div>

    <form method="POST" id="tld-form">
        <?php csrfField(); ?>
        <div class="section-actions">
            <button type="button" class="btn btn-small waves-effect" onclick="selectAllTlds(true)"><i class="material-icons left">check_box</i>Select All</button>
            <button type="button" class="btn btn-small waves-effect" onclick="selectAllTlds(false)"><i class="material-icons left">check_box_outline_blank</i>Deselect All</button>
            <button type="submit" class="btn waves-effect" name="action" value="save_selection"><i class="material-icons left">save</i>Save Selection</button>
            <button type="submit" class="btn waves-effect" name="action" value="run_worker_refresh"
                    title="Download the selected TLDs only if they changed (uses ETag/Last-Modified)"
                    onclick="return confirmLargeSelection()">
                <i class="material-icons left">refresh</i>Refresh Selected
            </button>
            <button type="submit" class="btn btn-danger waves-effect" name="action" value="run_worker_force"
                    onclick="return confirmLargeSelection() && confirm('Re-download the selected TLDs unconditionally? This ignores the local cache and the daily guard.')">
                <i class="material-icons left">download</i>Force Re-download
            </button>
            <span id="tld-count"></span>
        </div>
        <p class="muted">
            <strong>Refresh</strong> downloads only if the zone changed (conditional request).
            <strong>Force</strong> re-downloads the full zone files. Save the selection first if you changed the checkboxes.
        </p>

        <div class="tld-table-container">
            <table class="striped highlight">
                <thead>
                    <tr>
                        <th style="width: 40px;">Active</th>
                        <th>TLD</th>
                        <th>Last Sync</th>
                        <th>Status</th>
                        <th>Domains</th>
                        <th>New</th>
                        <th>Size</th>
                        <th>Retry</th>
                        <th>Error</th>
                    </tr>
                </thead>
                <tbody id="tld-tbody">
                    <?php foreach ($tlds as $t): ?>
                    <tr class="tld-row" data-name="<?= htmlspecialchars($t['name']) ?>" data-size="<?= (int)$t['zone_size'] ?>">
                        <td class="center-align">
                            <label><input type="checkbox" name="active[]" value="<?= htmlspecialchars($t['name']) ?>" <?= $t['is_active'] ? 'checked' : '' ?> onchange="updateTldCount()"><span></span></label>
                        </td>
                        <td><?= htmlspecialchars($t['name']) ?></td>
                        <td class="tld-last-sync"><?= htmlspecialchars(fmt_date($t['last_sync'])) ?></td>
                        <td class="tld-status"><?= tldStatusBadge($t['status']) ?></td>
                        <td class="tld-domains"><?= (int)$t['records_total'] > 0 ? number_format((int)$t['records_total']) : '<span class="muted">&mdash;</span>' ?></td>
                        <td class="tld-new"><?= (int)$t['records_new'] > 0 ? '<strong>' . number_format((int)$t['records_new']) . '</strong>' : '<span class="muted">&mdash;</span>' ?></td>
                        <td class="tld-size"><?= formatBytes((int)$t['zone_size']) ?></td>
                        <td class="tld-retry mono-sm"><?= (int)($t['retry_attempts'] ?? 0) > 0 ? '#' . (int)$t['retry_attempts'] . (empty($t['next_retry']) ? '' : ' @ ' . htmlspecialchars(substr(fmt_date($t['next_retry']), 11, 8))) : '<span class="muted">&mdash;</span>' ?></td>
                        <td class="tld-error text-danger mono-sm"><?= htmlspecialchars($t['last_error'] ?? '') ?></td>
                    </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>

        <div class="section-actions">
            <button type="submit" class="btn waves-effect" name="action" value="save_selection"><i class="material-icons left">save</i>Save Selection</button>
        </div>
    </form>
    <?php endif; ?>
</div>

<script>
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

// Warn before downloading a very large selection (e.g. .com is ~4.6 GB).
const LARGE_SELECTION_BYTES = 1024 * 1024 * 1024; // 1 GB compressed
const LARGE_TLD_BYTES = 512 * 1024 * 1024;        // 512 MB per TLD

function confirmLargeSelection() {
    let total = 0;
    const big = [];
    document.querySelectorAll('.tld-row input[name="active[]"]:checked').forEach(cb => {
        const row = cb.closest('.tld-row');
        const size = parseInt(row.dataset.size || '0');
        total += size;
        if (size >= LARGE_TLD_BYTES) big.push(row.dataset.name + ' (' + (size / 1073741824).toFixed(2) + ' GB)');
    });
    if (total <= LARGE_SELECTION_BYTES) return true;
    let msg = 'Selected zones total ~' + (total / 1073741824).toFixed(1) + ' GB compressed.\n' +
              'Downloading and parsing can take a long time and use significant disk/DB space.';
    if (big.length) {
        msg += '\n\nLarge TLDs: ' + big.join(', ') +
               '\nZones above the hash threshold are cached by hash to save disk.';
    }
    msg += '\n\nContinue?';
    return confirm(msg);
}

updateTldCount();

// Live refresh of per-TLD download status while the worker is running.
(function() {
    const workerRunning = <?= $workerRunning ? 'true' : 'false' ?>;
    if (!workerRunning || !document.getElementById('tld-tbody')) return;

    const statusLabels = {
        downloaded:    'Downloaded',
        not_modified:  'Unchanged',
        skipped_today: 'Skipped today',
        failed:        'Failed',
        pending:       'Pending',
        incomplete:    'Incomplete',
        skipped_large: 'Skipped (large)',
        no_space:      'No space',
        retrying:      'Retrying',
        parse_error:   'Parse error'
    };

    function badge(status) {
        const label = statusLabels[status];
        if (!label) return '<span class="muted">&mdash;</span>';
        return '<span class="status-badge status-' + status + '">' + label + '</span>';
    }

    function fmtSize(bytes) {
        bytes = parseInt(bytes || 0);
        if (bytes <= 0) return '<span class="muted">&mdash;</span>';
        const units = ['B', 'KB', 'MB', 'GB'];
        let i = 0, v = bytes;
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
        return (i >= 2 ? v.toFixed(1) : Math.round(v)) + ' ' + units[i];
    }

    function poll() {
        fetch('/ajax_tld_status.php')
            .then(r => r.json())
            .then(data => {
                if (!data.success || !data.tlds) return;
                data.tlds.forEach(t => {
                    const row = document.querySelector('.tld-row[data-name="' + t.name.replace(/"/g, '\\"') + '"]');
                    if (!row) return;
                    const lastSync = row.querySelector('.tld-last-sync');
                    const status = row.querySelector('.tld-status');
                    const domains = row.querySelector('.tld-domains');
                    const newc = row.querySelector('.tld-new');
                    const size = row.querySelector('.tld-size');
                    const retry = row.querySelector('.tld-retry');
                    const error = row.querySelector('.tld-error');
                    const syncText = t.last_sync ? t.last_sync : '<span class="muted">&mdash;</span>';
                    if (lastSync && lastSync.innerHTML !== syncText) lastSync.innerHTML = syncText;
                    if (status && status.innerHTML !== badge(t.status)) status.innerHTML = badge(t.status);
                    if (domains) domains.innerHTML = parseInt(t.records_total || 0) > 0 ? parseInt(t.records_total).toLocaleString() : '<span class="muted">&mdash;</span>';
                    if (newc) newc.innerHTML = parseInt(t.records_new || 0) > 0 ? '<strong>' + parseInt(t.records_new).toLocaleString() + '</strong>' : '<span class="muted">&mdash;</span>';
                    if (size) size.innerHTML = fmtSize(t.zone_size);
                    if (retry) {
                        const attempts = parseInt(t.retry_attempts || 0);
                        retry.innerHTML = attempts > 0
                            ? '#' + attempts + (t.next_retry ? ' @ ' + String(t.next_retry).substr(11, 8) : '')
                            : '<span class="muted">&mdash;</span>';
                    }
                    if (error) error.textContent = t.last_error || '';
                });
            })
            .catch(() => {});
    }

    setInterval(poll, 5000);
})();
</script>

<?php require __DIR__ . '/../templates/footer.php'; ?>
