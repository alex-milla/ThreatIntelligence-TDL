<?php
/**
 * Report builder.
 *
 * Users pick a set of keywords (marking them on the table or by selecting a
 * group) and generate a printable report with all the data collected for each
 * matched domain. Keywords can be organised into named groups; a keyword
 * belongs to at most one group.
 */
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
}

// Create group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'create_group') {
    $name = trim($_POST['group_name'] ?? '');
    if ($name === '') {
        $_SESSION['flash_error'] = 'Group name cannot be empty.';
    } elseif (mb_strlen($name) > 60) {
        $_SESSION['flash_error'] = 'Group name is too long (max 60 characters).';
    } else {
        $db->prepare("INSERT INTO keyword_groups (user_id, name) VALUES (?, ?)")->execute([$userId, $name]);
        $_SESSION['flash_message'] = 'Group created.';
    }
    header('Location: /reports.php');
    exit;
}

// Delete group (its keywords become ungrouped)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'delete_group') {
    $groupId = (int)($_POST['group_id'] ?? 0);
    $db->prepare("UPDATE keywords SET group_id = NULL WHERE group_id = ? AND user_id = ?")->execute([$groupId, $userId]);
    $db->prepare("DELETE FROM keyword_groups WHERE id = ? AND user_id = ?")->execute([$groupId, $userId]);
    $_SESSION['flash_message'] = 'Group deleted. Its keywords are now ungrouped.';
    header('Location: /reports.php');
    exit;
}

// Rename group
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'rename_group') {
    $groupId = (int)($_POST['group_id'] ?? 0);
    $name = trim($_POST['name'] ?? '');
    if ($name === '' || mb_strlen($name) > 60) {
        $_SESSION['flash_error'] = 'Invalid group name.';
    } else {
        $db->prepare("UPDATE keyword_groups SET name = ? WHERE id = ? AND user_id = ?")->execute([$name, $groupId, $userId]);
        $_SESSION['flash_message'] = 'Group renamed.';
    }
    header('Location: /reports.php?group=' . (int)$groupId);
    exit;
}

// Assign one keyword to a group (empty value = ungrouped)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'set_group') {
    $keywordId = (int)($_POST['keyword_id'] ?? 0);
    $groupId = (($_POST['group_id'] ?? '') === '') ? null : (int)$_POST['group_id'];
    if ($groupId !== null) {
        $chk = $db->prepare("SELECT COUNT(*) FROM keyword_groups WHERE id = ? AND user_id = ?");
        $chk->execute([$groupId, $userId]);
        if (!(int)$chk->fetchColumn()) {
            $groupId = null;
        }
    }
    $db->prepare("UPDATE keywords SET group_id = ? WHERE id = ? AND user_id = ?")->execute([$groupId, $keywordId, $userId]);
    $redirect = '/reports.php';
    $returnGroup = (string)($_POST['return_group'] ?? '');
    if ($returnGroup !== '' && $returnGroup !== 'all') {
        $redirect .= '?group=' . urlencode($returnGroup);
    }
    header('Location: ' . $redirect);
    exit;
}

// ---------- Filters (whitelisted) ----------
$groupFilter = (string)($_GET['group'] ?? 'all'); // 'all' | 'ungrouped' | numeric id

// Load groups + per-group keyword counts
$groupStmt = $db->prepare("SELECT id, name FROM keyword_groups WHERE user_id = ? ORDER BY name ASC");
$groupStmt->execute([$userId]);
$groups = $groupStmt->fetchAll();
$groupsById = [];
foreach ($groups as $g) {
    $groupsById[(int)$g['id']] = $g['name'];
}

$groupCounts = [];
$countStmt = $db->prepare("SELECT group_id, COUNT(*) AS cnt FROM keywords WHERE user_id = ? GROUP BY group_id");
$countStmt->execute([$userId]);
foreach ($countStmt->fetchAll() as $c) {
    $groupCounts[$c['group_id'] === null ? 'ungrouped' : (string)$c['group_id']] = (int)$c['cnt'];
}
$ungroupedCount = $groupCounts['ungrouped'] ?? 0;
$totalKeywords = array_sum($groupCounts);

// Validate numeric group filter
if ($groupFilter !== 'all' && $groupFilter !== 'ungrouped' && !ctype_digit($groupFilter)) {
    $groupFilter = 'all';
}

// ---------- Keyword list with visible match counts (same semantics as keywords.php) ----------
$newDomainDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));

$where = "WHERE k.user_id = ?";
$params = [$newDomainDays, $userId];
if ($groupFilter === 'ungrouped') {
    $where .= " AND k.group_id IS NULL";
} elseif (ctype_digit($groupFilter)) {
    $where .= " AND k.group_id = ?";
    $params[] = (int)$groupFilter;
}

$kwStmt = $db->prepare("SELECT k.id, k.keyword, k.match_count, k.group_id, k.created_at,
    COUNT(CASE WHEN
        n.id IS NOT NULL
        AND w.user_id IS NULL
        AND dt.domain IS NULL
        AND NOT EXISTS (SELECT 1 FROM domain_tags dx WHERE dx.domain = m.domain AND dx.tag = 'excluded')
        AND (
            dob.domain IS NOT NULL
            OR NOT (
                dw.domain IS NOT NULL AND t.name IS NOT NULL
                AND COALESCE(dw.creation_ts, datetime(dw.creation_date)) IS NOT NULL
                AND COALESCE(dw.creation_ts, datetime(dw.creation_date)) < datetime(t.last_ok_sync, '-' || ? || ' days')
            )
        )
    THEN 1 END) AS visible_count
FROM keywords k
LEFT JOIN matches m ON m.keyword_id = k.id AND m.is_historical = 0
LEFT JOIN notifications n ON n.match_id = m.id AND n.user_id = k.user_id
LEFT JOIN watchlist w ON w.user_id = k.user_id AND w.domain = m.domain
LEFT JOIN domain_tags dt ON dt.domain = m.domain AND dt.tag IN ('good','bad')
LEFT JOIN domain_tags dob ON dob.domain = m.domain AND dob.tag = 'observing'
LEFT JOIN domain_whois dw ON dw.domain = m.domain
LEFT JOIN tlds t ON t.name = m.tld
$where
GROUP BY k.id
ORDER BY k.keyword ASC");
$kwStmt->execute($params);
$keywords = $kwStmt->fetchAll();

$groupFilterLabel = 'All keywords';
if ($groupFilter === 'ungrouped') {
    $groupFilterLabel = 'Ungrouped';
} elseif (ctype_digit($groupFilter)) {
    $groupFilterLabel = $groupsById[(int)$groupFilter] ?? 'Group';
}

$pageTitle = 'Reports';
require __DIR__ . '/templates/header.php';
?>

<div class="card">
    <div class="card-head">
        <h2><i class="material-icons left">assessment</i>Reports</h2>
        <span class="muted"><?= $totalKeywords ?> keyword(s) in <?= count($groups) ?> group(s)</span>
    </div>
    <p class="muted">Select one or more keywords (or a whole group) and generate a printable report with all the data collected for each matched domain.</p>

    <?php if ($message): ?>
        <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <!-- Group tabs -->
    <div class="group-tabs">
        <a href="/reports.php?group=all" class="group-tab <?= $groupFilter === 'all' ? 'active' : '' ?>">All (<?= $totalKeywords ?>)</a>
        <?php foreach ($groups as $g):
            $gCount = $groupCounts[(string)$g['id']] ?? 0;
            $isActive = $groupFilter === (string)$g['id'];
        ?>
            <span class="group-chip">
                <a href="/reports.php?group=<?= (int)$g['id'] ?>" class="group-tab <?= $isActive ? 'active' : '' ?>"><?= htmlspecialchars($g['name']) ?> (<?= $gCount ?>)</a>
                <form method="POST" style="margin: 0; display: inline-flex;" onsubmit="return confirm('Delete group &quot;<?= htmlspecialchars(addslashes($g['name'])) ?>&quot;? Its keywords will become ungrouped.')">
                    <?php csrfField(); ?>
                    <input type="hidden" name="action" value="delete_group">
                    <input type="hidden" name="group_id" value="<?= (int)$g['id'] ?>">
                    <button type="submit" class="group-tab group-delete" title="Delete group"><i class="material-icons tiny">close</i></button>
                </form>
            </span>
        <?php endforeach; ?>
        <a href="/reports.php?group=ungrouped" class="group-tab <?= $groupFilter === 'ungrouped' ? 'active' : '' ?>">Ungrouped (<?= $ungroupedCount ?>)</a>
    </div>

    <!-- Create group form -->
    <form method="POST" class="group-create-form">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="create_group">
        <div class="input-field">
            <i class="material-icons prefix">create_new_folder</i>
            <input id="group_name" type="text" name="group_name" placeholder=" " maxlength="60" required>
            <label for="group_name">New group name</label>
        </div>
        <button type="submit" class="btn btn-small waves-effect"><i class="material-icons left">add</i>Add Group</button>
    </form>

    <?php if (empty($keywords)): ?>
        <p class="muted">No keywords in this view. <a href="/keywords.php">Add keywords</a> first or switch to another group.</p>
    <?php else: ?>
        <div class="report-options">
            <div class="report-filter">
                <label for="report-date">Period</label>
                <select id="report-date" class="browser-default compact">
                    <option value="all">All time</option>
                    <option value="24h" selected>Last 24h</option>
                    <option value="7d">Last 7 days</option>
                    <option value="30d">Last 30 days</option>
                </select>
            </div>
            <div class="report-filter">
                <label for="report-state">State</label>
                <select id="report-state" class="browser-default compact">
                    <option value="all">All states</option>
                    <option value="good">Good</option>
                    <option value="bad">Bad</option>
                    <option value="observing">Observing</option>
                    <option value="untagged">Untagged</option>
                    <option value="watchlist">In watchlist</option>
                    <option value="historical">Historical</option>
                </select>
            </div>
            <div class="report-filter">
                <label for="report-source">Source</label>
                <select id="report-source" class="browser-default compact">
                    <option value="all">All sources</option>
                    <option value="czds">CZDS (zone files)</option>
                    <option value="ct">OpenINTEL (CT)</option>
                </select>
            </div>
            <label class="check-inline" title="Reveal hidden domains: tagged good/bad, recheck matches, or validated as registered before the last scan">
                <input type="checkbox" id="report-archived">
                <span>Include tagged / historical / old</span>
            </label>
        </div>

        <div class="section-actions">
            <button type="button" class="btn waves-effect" onclick="generateReport()"><i class="material-icons left">print</i>Generate Report</button>
            <span class="muted">Report for the selected keywords (all visible keywords if none is checked).</span>
        </div>

        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th style="width: 30px;"><label><input type="checkbox" id="select-all" aria-label="Select all keywords"><span></span></label></th>
                    <th>Keyword</th>
                    <th>Matches</th>
                    <th>Group</th>
                    <th>Added</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($keywords as $k): ?>
                <tr>
                    <td><label><input type="checkbox" class="row-check kw-check" value="<?= (int)$k['id'] ?>" aria-label="Select <?= htmlspecialchars($k['keyword']) ?>"><span></span></label></td>
                    <td><strong><?= htmlspecialchars($k['keyword']) ?></strong></td>
                    <td>
                        <a href="/keyword_matches.php?id=<?= (int)$k['id'] ?>" title="Review all matched domains"><?= (int)$k['visible_count'] ?></a><?php if ((int)$k['visible_count'] !== (int)$k['match_count']): ?> <span class="muted" title="Total matches including hidden ones">(<?= (int)$k['match_count'] ?> total)</span><?php endif; ?>
                    </td>
                    <td>
                        <form method="POST" style="margin: 0;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="set_group">
                            <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                            <input type="hidden" name="return_group" value="<?= htmlspecialchars($groupFilter) ?>">
                            <select name="group_id" class="browser-default compact" onchange="this.form.submit()">
                                <option value="" <?= $k['group_id'] === null ? 'selected' : '' ?>>— Ungrouped</option>
                                <?php foreach ($groups as $g): ?>
                                <option value="<?= (int)$g['id'] ?>" <?= (string)$k['group_id'] === (string)$g['id'] ? 'selected' : '' ?>><?= htmlspecialchars($g['name']) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </form>
                    </td>
                    <td><?= htmlspecialchars(fmt_date($k['created_at'])) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
</div>

<script>
function generateReport() {
    var ids = Array.prototype.map.call(document.querySelectorAll('.kw-check:checked'), function (cb) { return cb.value; });
    var all = document.querySelectorAll('.kw-check');
    if (!ids.length) {
        // No explicit selection: report on every keyword visible in this view.
        if (!all.length) { alert('No keywords to report.'); return; }
        ids = Array.prototype.map.call(all, function (cb) { return cb.value; });
    }
    var p = new URLSearchParams();
    p.set('keywords', ids.join(','));
    p.set('date', document.getElementById('report-date').value);
    p.set('state', document.getElementById('report-state').value);
    p.set('source', document.getElementById('report-source').value);
    if (document.getElementById('report-archived').checked) p.set('archived', '1');
    window.location = '/report_view.php?' + p.toString();
}
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
