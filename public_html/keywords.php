<?php
require_once __DIR__ . '/includes/db.php';
require_once __DIR__ . '/includes/auth.php';
requireAuth();

$db = Database::get();
$userId = (int)$_SESSION['user_id'];
$isAdmin = !empty($_SESSION['is_admin']);

$message = $_SESSION['flash_message'] ?? '';
$error = $_SESSION['flash_error'] ?? '';
unset($_SESSION['flash_message'], $_SESSION['flash_error']);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    validateCsrf();
}

/** Validate a keyword/glob text; returns an error message or null. */
function keywordInputError(string $keyword): ?string {
    if (strlen($keyword) < 2) {
        return 'Keyword must be at least 2 characters.';
    }
    if (strlen($keyword) > 100) {
        return 'Keyword must be at most 100 characters.';
    }
    if (!preg_match('/^[a-z0-9\-.*?\[\]{}!,^]+$/', $keyword)) {
        return 'Keyword can only contain letters, numbers, "-", "." and the wildcards * ? [ ] { } ! ,';
    }
    return null;
}

// Add keyword
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add') {
    $keyword = strtolower(trim($_POST['keyword'] ?? ''));
    $err = keywordInputError($keyword);
    if ($err !== null) {
        $error = $err;
    } elseif (!canAddKeyword($db, $userId)) {
        $limit = getMaxKeywords($db, $userId);
        $error = $isAdmin
            ? 'You have reached your keyword limit. Increase it in Admin → Users.'
            : "You have reached your keyword limit ({$limit}). Contact the administrator.";
    } else {
        $stmt = $db->prepare("INSERT INTO keywords (user_id, keyword, tracking_interval_hours) VALUES (?, ?, 168)");
        try {
            $stmt->execute([$userId, $keyword]);
            $message = 'Keyword added successfully.';
        } catch (PDOException $e) {
            $error = 'This keyword already exists in your list.';
        }
    }
}

// Edit keyword text
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_keyword') {
    validateCsrf();
    $keywordId = (int)($_POST['keyword_id'] ?? 0);
    $keyword = strtolower(trim($_POST['keyword'] ?? ''));
    $err = keywordInputError($keyword);
    if ($err !== null) {
        $_SESSION['flash_error'] = $err;
    } elseif ($keywordId <= 0) {
        $_SESSION['flash_error'] = 'Invalid keyword.';
    } else {
        $dup = $db->prepare("SELECT id FROM keywords WHERE user_id = ? AND lower(keyword) = ? AND id <> ? LIMIT 1");
        $dup->execute([$userId, $keyword, $keywordId]);
        if ($dup->fetchColumn()) {
            $_SESSION['flash_error'] = 'Another keyword with that text already exists.';
        } else {
            $stmt = $db->prepare("UPDATE keywords SET keyword = ? WHERE id = ? AND user_id = ?");
            $stmt->execute([$keyword, $keywordId, $userId]);
            $_SESSION['flash_message'] = $stmt->rowCount() > 0 ? 'Keyword updated.' : 'Keyword not found.';
        }
    }
    header('Location: /keywords.php');
    exit;
}

// Delete keyword
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    validateCsrf();
    $keywordId = (int)($_POST['keyword_id'] ?? 0);
    $stmt = $db->prepare("DELETE FROM keywords WHERE id = ? AND user_id = ?");
    $stmt->execute([$keywordId, $userId]);
    $message = 'Keyword deleted.';
}

// Update per-keyword Intelligence tracking settings
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'update_tracking') {
    validateCsrf();
    $keywordId = (int)($_POST['keyword_id'] ?? 0);
    $enabled = isset($_POST['tracking_enabled']) ? 1 : 0;
    $days = max(1, min(3650, (int)($_POST['tracking_days'] ?? 90)));
    $maxAge = max(1, min(3650, (int)($_POST['tracking_enroll_max_age_days'] ?? 30)));
    $stmt = $db->prepare("UPDATE keywords SET tracking_enabled = ?, tracking_days = ?, tracking_enroll_max_age_days = ? WHERE id = ? AND user_id = ?");
    $stmt->execute([$enabled, $days, $maxAge, $keywordId, $userId]);
    $_SESSION['flash_message'] = 'Tracking settings updated.';
    header('Location: /keywords.php');
    exit;
}

// Admin recheck
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'recheck_keywords') {
    validateCsrf();
    if ($isAdmin) {
        // Recheck both caches (ccTLD/OpenINTEL + ICANN/CZDS). The source list is
        // decided server-side; the client may only add an optional subset of
        // keywords (empty = all keywords).
        $payloadData = ['sources' => ['openintel', 'czds']];
        $raw = (string)($_POST['payload'] ?? '');
        if ($raw !== '') {
            $decoded = json_decode($raw, true);
            $ids = (is_array($decoded) && !empty($decoded['keyword_ids']) && is_array($decoded['keyword_ids']))
                ? array_values(array_unique(array_filter(array_map('intval', $decoded['keyword_ids']), fn($v) => $v > 0)))
                : [];
            if ($ids) {
                // Never trust the client: keep only the admin's own keywords.
                $placeholders = implode(',', array_fill(0, count($ids), '?'));
                $own = $db->prepare("SELECT id FROM keywords WHERE user_id = ? AND id IN ($placeholders)");
                $own->execute(array_merge([$userId], $ids));
                $ownedIds = array_map('intval', $own->fetchAll(PDO::FETCH_COLUMN));
                if ($ownedIds) {
                    $payloadData['keyword_ids'] = $ownedIds;
                }
            }
        }
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)")
           ->execute(['recheck_keywords', json_encode($payloadData)]);
        $_SESSION['flash_message'] = !empty($payloadData['keyword_ids'])
            ? 'Keyword recheck queued for the selected keyword(s). The worker will scan the ccTLD + ICANN cached domains against them.'
            : 'Keyword recheck queued. The worker will scan the ccTLD + ICANN cached domains against all current keywords.';
    } else {
        $_SESSION['flash_error'] = 'Only administrators can trigger a recheck.';
    }
    // PRG so a refresh (button or browser) does not resubmit the form.
    header('Location: /keywords.php');
    exit;
}

// Admin stop recheck
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'stop_recheck') {
    validateCsrf();
    if ($isAdmin) {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['stop_recheck', '']);
        $_SESSION['flash_message'] = 'Stop recheck queued. The worker will stop at the next batch boundary.';
    } else {
        $_SESSION['flash_error'] = 'Only administrators can stop a recheck.';
    }
    header('Location: /keywords.php');
    exit;
}

// Column sorting (whitelisted, never interpolate user input into SQL).
$kwSortCols = ['keyword' => 'k.keyword', 'matches' => 'visible_count', 'added' => 'k.created_at'];
$kwSortDefaults = ['keyword' => 'asc', 'matches' => 'desc', 'added' => 'desc'];
$kwSort = $_GET['sort'] ?? 'added';
if (!isset($kwSortCols[$kwSort])) {
    $kwSort = 'added';
}
$kwDir = isset($_GET['dir']) ? (strtolower((string)$_GET['dir']) === 'asc' ? 'asc' : 'desc') : $kwSortDefaults[$kwSort];
$kwOrderBy = $kwSortCols[$kwSort] . ' ' . strtoupper($kwDir);

// List keywords with visible match count: only matches that still have an active
// notification for this user, are not in the watchlist, and match the default
// notifications visibility (good/bad/historical/old hidden; observing kept).
// Single-pass aggregation (LEFT JOINs + GROUP BY) instead of a correlated
// subquery per keyword: with the notifications(match_id) index this stays fast
// even with many matches. Semantics are identical to the previous query.
$newDomainDays = max(1, (int)getSetting($db, 'new_domain_days', '1'));
$stmt = $db->prepare("SELECT k.id, k.keyword, k.match_count, k.created_at,
    k.tracking_enabled, k.tracking_days, k.tracking_interval_hours, k.tracking_enroll_max_age_days,
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
WHERE k.user_id = ?
GROUP BY k.id
ORDER BY $kwOrderBy");
$stmt->execute([$newDomainDays, $userId]);
$keywords = $stmt->fetchAll();

/**
 * Render a sortable table header link for the keywords list.
 */
function kwSortLink(string $col, string $label, string $currentSort, string $currentDir, array $defaults): string {
    $dir = ($col === $currentSort) ? ($currentDir === 'asc' ? 'desc' : 'asc') : ($defaults[$col] ?? 'asc');
    $url = '/keywords.php?sort=' . urlencode($col) . '&dir=' . urlencode($dir);
    $active = ($col === $currentSort);
    $arrow = $active ? ($currentDir === 'asc' ? ' &#9650;' : ' &#9660;') : '';
    $aria = $active ? ' aria-sort="' . ($currentDir === 'asc' ? 'ascending' : 'descending') . '"' : '';
    return '<a href="' . htmlspecialchars($url) . '" class="th-sort' . ($active ? ' active' : '') . '"' . $aria . '>'
        . htmlspecialchars($label) . $arrow . '</a>';
}

// Live recheck status (admin only): powers the stop button, the progress line
// and the auto-refresh watcher on this page.
$recheckStatus = null;
$recheckRunning = false;
$recheckTotal = 0;
$recheckChecked = 0;
$recheckMatches = 0;
$recheckPct = 0;
$recheckPending = 0;
$activity = null;
if ($isAdmin) {
    $recheckStatus = $db->query("SELECT * FROM recheck_status WHERE id = 1")->fetch();
    $recheckRunning = !empty($recheckStatus['is_running']);
    $recheckTotal = (int)($recheckStatus['total_domains'] ?? 0);
    $recheckChecked = (int)($recheckStatus['checked_domains'] ?? 0);
    $recheckMatches = (int)($recheckStatus['matches_found'] ?? 0);
    $recheckPct = $recheckTotal > 0 ? round($recheckChecked / $recheckTotal * 100, 1) : 0;
    $recheckPending = (int)$db->query("SELECT COUNT(*) FROM commands WHERE command = 'recheck_keywords' AND status = 'pending'")->fetchColumn();
    $activity = getWorkerActivity($db);
}

// KPI aggregates for the v2 header strip.
$kwCount = count($keywords);
$kwMatchesTotal = 0;
$kwTrackingCount = 0;
foreach ($keywords as $k) {
    $kwMatchesTotal += (int)$k['match_count'];
    if (!empty($k['tracking_enabled'])) {
        $kwTrackingCount++;
    }
}

$pageTitle = 'My Keywords';
require __DIR__ . '/templates/header.php';
?>

<?php if ($isAdmin): ?>
<span id="activity-watcher" hidden
      data-url="/ajax_worker_activity.php"
      data-interval="5000"
      data-refresh-interval="5000"
      data-active="<?= !empty($activity['active']) ? '1' : '0' ?>"
      data-version="<?= htmlspecialchars($activity['worker_version'] ?? '') ?>"></span>
<?php endif; ?>

<div class="card">
    <div class="page-header">
        <h1>Keywords</h1>
        <span class="count-chip"><i class="material-icons" style="font-size:16px;">search</i><?= (int)$kwCount ?> keyword<?= $kwCount === 1 ? '' : 's' ?></span>
        <span class="spacer"></span>
        <button type="button" class="btn waves-effect" onclick="kwToggleAdd()" aria-controls="kw-add" aria-expanded="false"><i class="material-icons left">add</i>Add Keyword</button>
        <p class="subtitle">Track and monitor domains related to specific keywords.</p>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <div id="kw-add" class="kw-add-panel" hidden>
        <form method="POST" class="keyword-add-form">
            <?php csrfField(); ?>
            <input type="hidden" name="action" value="add">
            <div class="input-field">
                <i class="material-icons prefix">search</i>
                <input id="keyword" type="text" name="keyword" class="validate" placeholder=" " maxlength="100" required>
                <label for="keyword">Keyword</label>
                <span class="helper-text">Plain text or a pattern: e.g. <code>santander</code>, <code>micro*soft</code>, <code>microsoft[0-9]</code> — wildcards <code>* ? [ ] {n,m}</code> are applied automatically</span>
            </div>
            <button type="submit" class="btn waves-effect"><i class="material-icons left">add</i>Add Keyword</button>
        </form>
    </div>

    <div class="filter-form kw-filterbar">
        <div class="input-field">
            <i class="material-icons prefix">search</i>
            <input id="q" type="search" placeholder=" " autocomplete="off" aria-label="Search keyword">
            <label for="q">Search keyword</label>
        </div>
        <select id="kw-filter" class="browser-default compact" aria-label="Filter keywords">
            <option value="all">All keywords</option>
            <option value="on">Tracking on</option>
            <option value="off">Tracking off</option>
            <option value="matches">With matches</option>
        </select>
    </div>

    <?php if ($isAdmin): ?>
    <div id="live-recheck" data-live-section>
        <div class="recheck-bar">
            <?php if ($recheckRunning): ?>
            <span class="recheck-state"><i class="material-icons" style="color:var(--warning)">autorenew</i>Running · <?= number_format($recheckChecked) ?>/<?= number_format($recheckTotal) ?> (<?= $recheckPct ?>%) · <?= number_format($recheckMatches) ?> matches</span>
            <?php elseif ($recheckPending > 0): ?>
            <span class="recheck-state"><i class="material-icons">schedule</i>Queued — waiting for the worker</span>
            <?php elseif ($recheckStatus && $recheckStatus['completed_at']): ?>
            <span class="recheck-state"><i class="material-icons" style="color:var(--success)">check_circle</i>Completed · <?= number_format($recheckChecked) ?> checked · <?= number_format($recheckMatches) ?> matches <span class="muted">· Last recheck: <?= htmlspecialchars(fmt_date($recheckStatus['completed_at'])) ?></span></span>
            <?php else: ?>
            <span class="recheck-state"><i class="material-icons muted">info</i>Idle</span>
            <?php endif; ?>
            <span class="spacer"></span>
            <form method="POST" id="recheck-form" onsubmit="return prepareRecheck()">
                <?php csrfField(); ?>
                <input type="hidden" name="action" value="recheck_keywords">
                <input type="hidden" name="payload" id="recheck-payload" value="">
                <button type="submit" id="recheck-btn" class="btn btn-small waves-effect" <?= ($recheckRunning || $recheckPending > 0) ? 'disabled' : '' ?>>
                    <i class="material-icons left">search</i><span id="recheck-label">Recheck cached domains</span>
                </button>
            </form>
            <?php if ($recheckRunning): ?>
            <form method="POST">
                <?php csrfField(); ?>
                <input type="hidden" name="action" value="stop_recheck">
                <button type="submit" class="btn btn-small btn-danger waves-effect"><i class="material-icons left">stop</i>Stop</button>
            </form>
            <?php endif; ?>
            <button type="button" class="btn btn-small btn-outline waves-effect" data-refresh-live title="Check the recheck status now"><i class="material-icons left">refresh</i>Refresh</button>
        </div>
        <?php if ($recheckRunning): ?>
        <div class="progress" style="margin:0 0 12px;"><div class="determinate" style="width: <?= $recheckPct ?>%;"></div></div>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <div id="live-keywords" data-live-section>
        <div class="stat-strip">
            <div class="stat"><span class="stat-ico"><i class="material-icons">search</i></span><div><div class="stat-num"><?= (int)$kwCount ?></div><div class="stat-label">Keywords</div></div></div>
            <div class="stat"><span class="stat-ico info"><i class="material-icons">travel_explore</i></span><div><div class="stat-num"><?= number_format($kwMatchesTotal) ?></div><div class="stat-label">Matches (total)</div></div></div>
            <div class="stat"><span class="stat-ico ok"><i class="material-icons">track_changes</i></span><div><div class="stat-num"><?= (int)$kwTrackingCount ?></div><div class="stat-label">Tracking</div></div></div>
        </div>

    <?php if (empty($keywords)): ?>
        <p class="muted">No keywords yet. Add your first keyword above.</p>
    <?php else: ?>
        <?php if ($isAdmin): ?>
        <div id="kw-selection" class="kw-selection" hidden>
            <span class="sel-count">0 seleccionadas</span>
            <button type="submit" form="recheck-form" class="btn btn-small waves-effect" <?= ($recheckRunning || $recheckPending > 0) ? 'disabled' : '' ?>><i class="material-icons left">search</i>Recheck selected</button>
            <button type="button" class="btn btn-small btn-outline waves-effect" onclick="kwClearSelection()">Clear</button>
        </div>
        <?php endif; ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <?php if ($isAdmin): ?>
                    <th style="width: 30px;"><input type="checkbox" id="select-all" aria-label="Select all keywords"></th>
                    <?php endif; ?>
                    <th><?= kwSortLink('keyword', 'Keyword', $kwSort, $kwDir, $kwSortDefaults) ?></th>
                    <th><?= kwSortLink('matches', 'Matches', $kwSort, $kwDir, $kwSortDefaults) ?></th>
                    <th>Tracking</th>
                    <th><?= kwSortLink('added', 'Added', $kwSort, $kwDir, $kwSortDefaults) ?></th>
                    <th style="width: 170px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($keywords as $k): ?>
                <tr data-keyword="<?= htmlspecialchars(strtolower((string)$k['keyword'])) ?>" data-tracking="<?= !empty($k['tracking_enabled']) ? '1' : '0' ?>" data-matches="<?= (int)$k['match_count'] ?>">
                    <?php if ($isAdmin): ?>
                    <td><input type="checkbox" class="row-check kw-check" value="<?= (int)$k['id'] ?>" aria-label="Select <?= htmlspecialchars($k['keyword']) ?>"></td>
                    <?php endif; ?>
                    <td class="kw-name"><strong><?= htmlspecialchars($k['keyword']) ?></strong><?php if (strpbrk((string)$k['keyword'], '*?[]{}') !== false): ?> <span class="tag-chip report" title="Contains wildcards (matched as a glob too)">GLOB</span><?php endif; ?></td>
                    <td>
                        <a href="/keyword_matches.php?id=<?= (int)$k['id'] ?>" title="Review all matched domains"><?= (int)$k['visible_count'] ?></a><?php if ((int)$k['visible_count'] !== (int)$k['match_count']): ?> <a href="/keyword_matches.php?id=<?= (int)$k['id'] ?>" class="muted" title="Review all matched domains">(<?= (int)$k['match_count'] ?> total)</a><?php endif; ?>
                        <a href="/notifications.php?q=<?= urlencode($k['keyword']) ?>" class="muted" title="View notifications for this keyword" aria-label="View notifications for this keyword"><i class="material-icons tiny">notifications</i></a>
                    </td>
                    <td>
                        <form method="POST" class="kw-tracking-form">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="update_tracking">
                            <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                            <input type="hidden" name="tracking_days" value="<?= (int)$k['tracking_days'] ?>">
                            <input type="hidden" name="tracking_enroll_max_age_days" value="<?= (int)$k['tracking_enroll_max_age_days'] ?>">
                            <div class="switch kw-switch">
                                <label>Off<input type="checkbox" name="tracking_enabled" value="1" <?= !empty($k['tracking_enabled']) ? 'checked' : '' ?> onchange="this.form.submit()"><span class="lever"></span>On</label>
                            </div>
                        </form>
                    </td>
                    <td><?= htmlspecialchars(fmt_date($k['created_at'])) ?></td>
                    <td>
                        <div class="kw-actions">
                            <a class="icon-btn" href="/keyword_matches.php?id=<?= (int)$k['id'] ?>" title="Review matched domains" aria-label="Review matched domains"><i class="material-icons">list_alt</i></a>
                            <details class="kw-edit">
                                <summary class="icon-btn" title="Edit keyword" role="button" tabindex="0"><i class="material-icons">edit</i></summary>
                                <form method="POST" class="kw-edit-form">
                                    <?php csrfField(); ?>
                                    <input type="hidden" name="action" value="update_keyword">
                                    <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                                    <input type="text" name="keyword" value="<?= htmlspecialchars($k['keyword']) ?>" maxlength="100" required class="browser-default compact">
                                    <button type="submit" class="btn btn-small waves-effect">Save</button>
                                </form>
                            </details>
                            <details class="kw-tracking-settings">
                                <summary class="icon-btn" title="Tracking settings" role="button" tabindex="0"><i class="material-icons">tune</i></summary>
                                <form method="POST" class="kw-tracking-form">
                                    <?php csrfField(); ?>
                                    <input type="hidden" name="action" value="update_tracking">
                                    <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                                    <label class="check-inline"><input type="checkbox" name="tracking_enabled" value="1" <?= !empty($k['tracking_enabled']) ? 'checked' : '' ?>><span></span>Enabled</label>
                                    <label class="muted">Window (days) <input type="number" name="tracking_days" min="1" max="3650" value="<?= (int)$k['tracking_days'] ?>" class="browser-default compact"></label>
                                    <label class="muted">Enroll if &le; (days old) <input type="number" name="tracking_enroll_max_age_days" min="1" max="3650" value="<?= (int)$k['tracking_enroll_max_age_days'] ?>" class="browser-default compact"></label>
                                    <button type="submit" class="btn btn-small waves-effect">Save</button>
                                </form>
                            </details>
                            <form method="POST" style="display: inline-flex;" onsubmit="return confirm('Delete this keyword?')">
                                <?php csrfField(); ?>
                                <input type="hidden" name="action" value="delete">
                                <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                                <button type="submit" class="icon-btn danger" title="Delete keyword" aria-label="Delete keyword"><i class="material-icons">delete</i></button>
                            </form>
                        </div>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    </div>
</div>

<script>
// Reveal the add-keyword form on demand (keeps the list header clean in v2).
function kwToggleAdd() {
    var panel = document.getElementById('kw-add');
    if (!panel) return;
    panel.hidden = !panel.hidden;
    var btn = document.querySelector('[aria-controls="kw-add"]');
    if (btn) btn.setAttribute('aria-expanded', panel.hidden ? 'false' : 'true');
    if (!panel.hidden) {
        var input = document.getElementById('keyword');
        if (input) input.focus();
    }
}

// Recheck the selected keywords (or all when none is checked). The selected ids
// are sent as a JSON payload; the server keeps only the admin's own keywords.
function updateRecheckLabel() {
    var label = document.getElementById('recheck-label');
    var btn = document.getElementById('recheck-btn');
    if (!label || (btn && btn.disabled)) return;
    var checked = document.querySelectorAll('.kw-check:checked').length;
    label.textContent = checked ? ('Recheck ' + checked + ' selected') : 'Recheck cached domains';
}
function prepareRecheck() {
    var ids = Array.prototype.map.call(document.querySelectorAll('.kw-check:checked'), function (cb) { return cb.value; });
    var payload = document.getElementById('recheck-payload');
    if (payload) payload.value = ids.length ? JSON.stringify({ keyword_ids: ids }) : '';
    var msg = ids.length
        ? ('Recheck the ccTLD + ICANN cached domains against ' + ids.length + ' selected keyword(s)?\n\nThe ICANN scan can take a while.')
        : 'Recheck the ccTLD + ICANN cached domains against ALL keywords?\n\nThe ICANN scan can take a while.';
    return confirm(msg);
}

// Contextual selection bar for the admin bulk recheck.
function kwSelectionSync() {
    var checks = document.querySelectorAll('.kw-check');
    var n = document.querySelectorAll('.kw-check:checked').length;
    var bar = document.getElementById('kw-selection');
    if (bar) {
        bar.hidden = n === 0;
        var out = bar.querySelector('.sel-count');
        if (out) out.textContent = n + ' seleccionada' + (n === 1 ? '' : 's');
    }
    var all = document.getElementById('select-all');
    if (all) {
        all.checked = checks.length > 0 && n === checks.length;
        all.indeterminate = n > 0 && n < checks.length;
    }
    updateRecheckLabel();
}
function kwClearSelection() {
    document.querySelectorAll('.kw-check').forEach(function (cb) { cb.checked = false; });
    kwSelectionSync();
}

document.addEventListener('change', function (e) {
    if (!e.target) return;
    if (e.target.id === 'select-all') {
        document.querySelectorAll('.kw-check').forEach(function (cb) { cb.checked = e.target.checked; });
        kwSelectionSync();
    } else if (e.target.classList && e.target.classList.contains('kw-check')) {
        kwSelectionSync();
    }
});

// Client-side search + filter over the keyword rows (the list has no pagination).
(function () {
    var q = document.getElementById('q');
    var filter = document.getElementById('kw-filter');
    function apply() {
        var term = (q && q.value ? q.value : '').trim().toLowerCase();
        var mode = filter ? filter.value : 'all';
        document.querySelectorAll('tr[data-keyword]').forEach(function (tr) {
            var kw = tr.getAttribute('data-keyword') || '';
            var on = tr.getAttribute('data-tracking') === '1';
            var m = parseInt(tr.getAttribute('data-matches') || '0', 10) || 0;
            var ok = term === '' || kw.indexOf(term) !== -1;
            if (ok && mode === 'on') ok = on;
            else if (ok && mode === 'off') ok = !on;
            else if (ok && mode === 'matches') ok = m > 0;
            tr.hidden = !ok;
        });
    }
    if (q) q.addEventListener('input', apply);
    if (filter) filter.addEventListener('change', apply);
})();
</script>

<?php require __DIR__ . '/templates/footer.php'; ?>
