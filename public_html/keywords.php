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

// Add keyword
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add') {
    $keyword = strtolower(trim($_POST['keyword'] ?? ''));
    if (strlen($keyword) < 2) {
        $error = 'Keyword must be at least 2 characters.';
    } elseif (strlen($keyword) > 50) {
        $error = 'Keyword must be at most 50 characters.';
    } elseif (!preg_match('/^[a-z0-9\-]+$/', $keyword)) {
        $error = 'Keyword can only contain letters, numbers, and hyphens.';
    } elseif (!canAddKeyword($db, $userId)) {
        $limit = getMaxKeywords($db, $userId);
        $error = $isAdmin
            ? 'You have reached your keyword limit. Increase it in Admin → Users.'
            : "You have reached your keyword limit ({$limit}). Contact the administrator.";
    } else {
        $stmt = $db->prepare("INSERT INTO keywords (user_id, keyword) VALUES (?, ?)");
        try {
            $stmt->execute([$userId, $keyword]);
            $message = 'Keyword added successfully.';
        } catch (PDOException $e) {
            $error = 'This keyword already exists in your list.';
        }
    }
}

// Delete keyword
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    validateCsrf();
    $keywordId = (int)($_POST['keyword_id'] ?? 0);
    $stmt = $db->prepare("DELETE FROM keywords WHERE id = ? AND user_id = ?");
    $stmt->execute([$keywordId, $userId]);
    $message = 'Keyword deleted.';
}

// Admin recheck
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'recheck_keywords') {
    validateCsrf();
    if ($isAdmin) {
        $db->prepare("INSERT INTO commands (command, payload) VALUES (?, ?)") ->execute(['recheck_keywords', '']);
        $_SESSION['flash_message'] = 'Keyword recheck queued. The worker will scan all cached domains against current keywords.';
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
    COUNT(CASE WHEN
        n.id IS NOT NULL
        AND w.user_id IS NULL
        AND dt.domain IS NULL
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
    <div class="card-head">
        <h2>My Keywords</h2>
        <span class="muted"><?= count($keywords) ?> keyword(s)</span>
    </div>

    <?php if ($message): ?>
        <div class="alert alert-success"><i class="material-icons left">check_circle</i><?= htmlspecialchars($message) ?></div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="alert alert-error"><i class="material-icons left">error</i><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>

    <form method="POST" class="keyword-add-form">
        <?php csrfField(); ?>
        <input type="hidden" name="action" value="add">
        <div class="input-field">
            <i class="material-icons prefix">search</i>
            <input id="keyword" type="text" name="keyword" class="validate" placeholder=" " required>
            <label for="keyword">Keyword</label>
            <span class="helper-text">e.g. santander, nasa, caixabank</span>
        </div>
        <button type="submit" class="btn waves-effect"><i class="material-icons left">add</i>Add Keyword</button>
    </form>

    <?php if ($isAdmin): ?>
    <div id="live-recheck" data-live-section>
        <div class="section-actions">
            <form method="POST">
                <?php csrfField(); ?>
                <input type="hidden" name="action" value="recheck_keywords">
                <button type="submit" class="btn btn-outline waves-effect" <?= ($recheckRunning || $recheckPending > 0) ? 'disabled' : '' ?>>
                    <i class="material-icons left">search</i><?= $recheckRunning ? 'Recheck in progress...' : 'Recheck All Cached Domains' ?>
                </button>
            </form>
            <?php if ($recheckRunning): ?>
            <form method="POST">
                <?php csrfField(); ?>
                <input type="hidden" name="action" value="stop_recheck">
                <button type="submit" class="btn waves-effect btn-danger"><i class="material-icons left">stop</i>Stop Recheck</button>
            </form>
            <?php endif; ?>
            <button type="button" class="btn btn-outline waves-effect" data-refresh-live title="Check the recheck status now">
                <i class="material-icons left">refresh</i>Refresh
            </button>
            <span class="muted">Scans all previously downloaded domains against current keywords (admin only)</span>
        </div>
        <div class="recheck-status">
            <?php if ($recheckRunning): ?>
                <p><strong>Status:</strong> <span class="status-badge status-running">Running</span></p>
                <div class="progress"><div class="determinate" style="width: <?= $recheckPct ?>%;"></div></div>
                <p>Checked <strong><?= number_format($recheckChecked) ?></strong> of <strong><?= number_format($recheckTotal) ?></strong> domains (<?= $recheckPct ?>%) — <strong><?= number_format($recheckMatches) ?></strong> matches found</p>
            <?php elseif ($recheckPending > 0): ?>
                <p><strong>Status:</strong> <span class="status-badge status-running">Queued</span> — waiting for the worker to start.</p>
            <?php elseif ($recheckStatus && $recheckStatus['completed_at']): ?>
                <p><strong>Status:</strong> <span class="status-badge status-completed">Completed</span> at <?= htmlspecialchars(fmt_date($recheckStatus['completed_at'])) ?></p>
                <p>Checked <strong><?= number_format($recheckChecked) ?></strong> domains — <strong><?= number_format($recheckMatches) ?></strong> matches found</p>
            <?php else: ?>
                <p><strong>Status:</strong> <span class="status-badge status-cancelled">Idle</span></p>
            <?php endif; ?>
        </div>
    </div>
    <?php endif; ?>

    <div id="live-keywords" data-live-section>
    <?php if (empty($keywords)): ?>
        <p class="muted">No keywords yet. Add your first keyword above.</p>
    <?php else: ?>
        <table class="striped highlight responsive-table">
            <thead>
                <tr>
                    <th><?= kwSortLink('keyword', 'Keyword', $kwSort, $kwDir, $kwSortDefaults) ?></th>
                    <th><?= kwSortLink('matches', 'Matches', $kwSort, $kwDir, $kwSortDefaults) ?></th>
                    <th><?= kwSortLink('added', 'Added', $kwSort, $kwDir, $kwSortDefaults) ?></th>
                    <th style="width: 100px;">Actions</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($keywords as $k): ?>
                <tr>
                    <td><strong><?= htmlspecialchars($k['keyword']) ?></strong></td>
                    <td>
                        <a href="/keyword_matches.php?id=<?= (int)$k['id'] ?>" target="_blank" rel="noopener" title="Review all matched domains"><?= (int)$k['visible_count'] ?></a><?php if ((int)$k['visible_count'] !== (int)$k['match_count']): ?> <a href="/keyword_matches.php?id=<?= (int)$k['id'] ?>" target="_blank" rel="noopener" class="muted" title="Review all matched domains">(<?= (int)$k['match_count'] ?> total)</a><?php endif; ?>
                        <a href="/notifications.php?q=<?= urlencode($k['keyword']) ?>" class="muted" title="View notifications for this keyword" aria-label="View notifications for this keyword"><i class="material-icons tiny">notifications</i></a>
                    </td>
                    <td><?= htmlspecialchars(fmt_date($k['created_at'])) ?></td>
                    <td>
                        <form method="POST" style="display: inline;">
                            <?php csrfField(); ?>
                            <input type="hidden" name="action" value="delete">
                            <input type="hidden" name="keyword_id" value="<?= (int)$k['id'] ?>">
                            <button type="submit" class="btn btn-small btn-danger waves-effect" onclick="return confirm('Delete this keyword?')"><i class="material-icons left">delete</i>Delete</button>
                        </form>
                    </td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    <?php endif; ?>
    </div>
</div>

<?php require __DIR__ . '/templates/footer.php'; ?>
